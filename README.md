# CVE Backporting — Linux 内核漏洞补丁智能回溯引擎

> **一条命令，从 CVE 编号到可落地的 Backport 方案。**

面向自维护 Linux Kernel 仓库（深度定制、commit 偏移、路径重组），将 CVE 漏洞的**情报采集 → 引入判定 → 修复定位 → 依赖分析 → 冲突预检**五个阶段编排为全自动 Pipeline，为百万级 commit 规模的企业内核提供秒级响应的安全补丁决策支持。

---

## 为什么需要这个工具

| 传统人工流程 | 本工具 |
|-------------|--------|
| 手动查 MITRE、googlesource、邮件列表，逐个比对 commit | **Crawler Agent** 自动聚合多源情报，三级回退保证可用性 |
| `git log --grep` 然后肉眼比对 subject | **三级搜索引擎** (ID → Subject → Diff) 自动定位，置信度量化输出 |
| 本地仓库 squash 了社区补丁，传统 diff 比对完全失效 | **Diff 包含度算法** 识别"小补丁藏在大 commit 里"的场景 |
| 内核版本间路径重组 (`fs/cifs/` → `fs/smb/client/`)，搜索直接找不到 | **PathMapper** 双向路径翻译，自动适配 8+ 已知子系统迁移 |
| 百万级 commit 仓库 `git log` 一跑几分钟 | **SQLite + FTS5 缓存** + 增量更新，日常同步秒级完成 |
| cherry-pick 前不确定要不要先合前置补丁 | **Hunk 级依赖分析** 精确到行范围，强/中/弱三级分级 |

---

## 技术亮点

**多 Agent 流水线架构** — 四个独立 Agent（Crawler / Analysis / Dependency / DryRun）通过 Pipeline 编排器串联，每个阶段可独立使用、独立测试，关注点清晰分离。

**三级渐进式 Commit 搜索** — L1 精确 ID 匹配（毫秒级）→ L2 Subject 语义匹配（SequenceMatcher 标准化比对）→ L3 Diff 代码级匹配（双向相似度 + 单向包含度自适应切换），在 commit ID 完全偏移的深度定制仓库中仍能精准定位。

**Diff Containment 算法** — 针对企业内核"多 patch squash 为一个 commit"的常见实践，设计了基于 Multiset 的单向包含度检测：即使社区 3 行补丁被合入到一个 200 行的大 commit 中，仍能以 95%+ 包含度命中，而传统双向相似度仅有 ~30%。

**跨版本路径映射** — 内置 8 组 Linux 内核子系统目录迁移规则（cifs→smb、staging 毕业等），支持自定义扩展。在搜索和比对两个环节双向翻译，彻底解决"同一个文件在不同版本有不同路径"的匹配盲区。

**千万级 Commit 性能优化** — 流式 `git log` 读取（零内存拷贝）、50K 批量写入、WAL + mmap 调优、FTS5 全文索引。增量缓存自动校验分支一致性，rebase 后智能降级全量重建。

**多源补丁获取与容错** — `git.kernel.org`（主）→ `kernel.googlesource.com`（备，含重试）→ 本地 Git 对象库（兜底），三级回退 + 部分结果互补合并，单一数据源故障不影响分析流程。

**闭环验证框架** — 基于 `git worktree` 的非破坏性回退验证：自动创建修复前快照、运行 Pipeline、与真实合入记录对比，输出完整差异诊断（社区补丁 vs 本地修复对比、DryRun 冲突根因分析、前置依赖 TP/FP/FN 明细），并支持集成 LLM API 进行 AI 根因分析。批量基准测试汇总 Precision / Recall / F1 量化工具整体置信度。

---

## 核心能力

### 1. CVE 全流程分析 (`analyze`)

给定一个 CVE ID，自动完成 **情报获取 → 引入检测 → 修复定位 → 依赖分析 → Dry-Run 冲突预检** 全链路。

```
Crawler → Analysis → Dependency → DryRun
```

- 识别 Mainline fix commit 和引入 commit，三级搜索定位目标仓库中的对应 commit
- 判定漏洞是否已引入、修复补丁是否已合入
- 若未合入：自动分析前置依赖补丁 + `git apply --check` 检测冲突
- 适用于日常安全巡检、CVE 修复评估、批量漏洞状态盘点

### 2. 漏洞引入检测 (`check-intro`)

判断 mainline 引入 commit 在目标仓库中是否存在对应提交，确认漏洞是否影响本地内核。

- 支持 `--commit` 或 `--cve` 两种输入
- 三级策略全部执行（不短路），每级独立展示结果与置信度
- L1 区分"不存在 / 存在但不在目标分支 / 在目标分支"三种状态
- L3 启用包含度算法，适配 squash commit 场景

### 3. 修复补丁检测 (`check-fix`)

判断修复补丁是否已合入目标仓库，给出明确的"已修复 / 需 backport"结论。

- CVE 模式自动提取 mainline fix + stable backport，逐一检测
- L3 使用双向相似度（非包含度），适合精确的修复补丁匹配
- 适用于安全审计、合规检查、修复状态批量确认

### 4. Commit 缓存构建 (`build-cache`)

对百万级 commit 仓库建立 SQLite + FTS5 缓存，加速全部搜索能力。

- **增量更新（默认）：** 已有缓存时仅拉取新增 commit，秒级完成日常同步
- 自动检测缓存一致性：分支 rebase 后自动降级全量重建
- `--full` 强制全量重建

### 5. 工具准确度验证 (`validate`)

选取已修复的 CVE，通过 `git worktree` 回退到修复前状态，运行完整 Pipeline，与真实合入记录进行对比。

- 自动计算回滚点（`known_fix~1` 或最早 prereq 前）
- 验证修复检测、引入检测、DryRun 预测、前置依赖 Precision/Recall/F1
- worktree 共享 `.git` 对象库，秒级创建/清理，不影响主仓库

### 6. 批量基准测试 (`benchmark`)

从 YAML 文件批量加载已修复 CVE 集合，逐一执行回退验证，汇总工具整体准确度。

- 汇总引入/修复检测准确率、前置依赖 F1、DryRun 准确率、搜索策略分布
- CVE 数据不完整时自动标记，不影响其他 CVE 的统计
- 适用于持续集成中的回归测试和工具调优效果评估

### 7. Commit 搜索 (`search`)

快速查询某个 commit ID 是否存在于目标仓库的指定分支上，先查缓存再查 Git 对象库。

## 架构

```
cve_backporting/
├── core/                     # 基础设施层
│   ├── models.py             #   数据模型 (CveInfo, PatchInfo, StrategyResult 等)
│   ├── config.py             #   YAML 配置加载
│   ├── git_manager.py        #   Git 仓库操作 + SQLite 缓存 (百万级优化)
│   ├── matcher.py            #   相似度算法 + 依赖图
│   └── ui.py                 #   Rich 终端 UI 组件
├── agents/                   # 核心 Agent 层
│   ├── crawler.py            #   Crawler Agent — CVE 情报 + 补丁获取
│   ├── analysis.py           #   Analysis Agent — 三级 commit 搜索
│   ├── dependency.py         #   Dependency Agent — 前置依赖分析
│   └── dryrun.py             #   DryRun Agent — git apply 试应用
├── pipeline.py               # Pipeline 编排器 (串联四个 Agent)
├── cli.py                    # CLI 入口 (analyze/check-intro/check-fix/validate/benchmark)
├── config.yaml               # 配置文件
├── benchmarks.example.yaml   # 基准测试集示例
├── requirements.txt
├── tests/
│   └── test_agents.py        # 测试套件
└── docs/
    └── TECHNICAL.md          # 技术文档
```

| Agent | 职责 |
|-------|------|
| **Crawler** | 从 MITRE API + googlesource 获取 CVE 元数据和补丁内容 |
| **Analysis** | 三级搜索定位目标仓库中的对应 commit (ID → Subject → Diff) |
| **Dependency** | 分析前置依赖补丁、Fixes 标签引用、函数级冲突检测 |
| **DryRun** | `git apply --check` 试应用补丁，检测冲突文件 |

## 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 编辑配置（填入本地仓库路径和分支名）
vim config.yaml
```

### 构建缓存

```bash
# 首次构建（全量）
python cli.py build-cache --target 5.10-hulk

# 日常同步（增量，默认行为，仅拉取新增 commit）
python cli.py build-cache --target 5.10-hulk

# 强制全量重建
python cli.py build-cache --target 5.10-hulk --full
```

### CVE 全流程分析

```bash
# 分析单个 CVE
python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk

# 跳过 dry-run（加快速度）
python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk --no-dryrun

# 批量分析
python cli.py analyze --batch cve_list.txt --target 5.10-hulk
```

### 漏洞引入检测

```bash
# 直接指定 mainline 引入 commit ID
python cli.py check-intro --commit d375b98e0248 --target 5.10-hulk

# 通过 CVE ID 自动提取引入 commit
python cli.py check-intro --cve CVE-2024-26633 --target 5.10-hulk
```

### 修复补丁检测

```bash
# 直接指定修复 commit ID
python cli.py check-fix --commit abc123def456 --target 5.10-hulk

# 通过 CVE ID 自动提取修复 commit（含 stable backport）
python cli.py check-fix --cve CVE-2024-26633 --target 5.10-hulk
```

### 工具准确度验证 (`validate`)

选取已修复的 CVE，自动创建 `git worktree` 回退到修复前状态，运行完整分析流水线，将工具输出与真实合入记录进行对比。

```bash
# 单个 CVE 验证（无前置依赖）
python cli.py validate \
  --cve CVE-2024-26633 \
  --target 5.10-hulk \
  --known-fix da23bd709b46

# 单个 CVE 验证（含已知前置依赖）
python cli.py validate \
  --cve CVE-2024-26633 \
  --target 5.10-hulk \
  --known-fix da23bd709b46 \
  --known-prereqs "commit1,commit2"
```

验证报告展示完整的差异诊断：社区修复补丁 vs 本地真实修复 commit 对比、DryRun 冲突文件及不一致原因分析、工具推荐前置依赖 vs 真实合入记录并排对比（含 TP/FP/FN 匹配详情）。可选集成 LLM API 对 FAIL 项进行 AI 根因分析。

### 批量基准测试 (`benchmark`)

从 YAML 文件批量加载已修复 CVE，逐一执行回退验证，计算工具整体准确度指标。

```bash
python cli.py benchmark --file benchmarks.yaml --target 5.10-hulk
```

基准数据集格式见 `benchmarks.example.yaml`。

### Commit 搜索

```bash
python cli.py search --commit d375b98e0248 --target 5.10-hulk
```

### 通用选项

```bash
# 静默模式（仅写日志文件，不输出到终端）
python cli.py -q analyze --cve CVE-2024-26633 --target 5.10-hulk

# 指定配置文件
python cli.py -c /path/to/config.yaml analyze --cve CVE-2024-26633 --target 5.10-hulk
```

## 配置

`config.yaml` 关键配置：

```yaml
repositories:
  "5.10-hulk":
    path: "/path/to/linux"        # 本地仓库绝对路径
    branch: "linux-5.10.y"        # 目标分支名

cache:
  enabled: true
  database_path: "./commit_cache.db"
  max_cached_commits: 10000000

matching:
  subject_similarity_threshold: 0.85
  diff_similarity_threshold: 0.70
```

## 三级搜索策略

| Level | 策略 | 匹配方式 | 置信度 |
|-------|------|----------|--------|
| L1 | ID 精确匹配 | `git cat-file` + `merge-base --is-ancestor` | 100% |
| L2 | Subject 语义匹配 | `git log --grep` + SequenceMatcher ≥ 85% | 85-100% |
| L3 | Diff 代码匹配 | `git log -- <files>` + diff_similarity ≥ 70% | 70-100% |

L1 额外区分三种状态：commit 在目标分支上 / 存在于仓库但不在目标分支 / 不存在。

## 测试

```bash
python -m tests.test_agents                           # 完整测试
python -m tests.test_agents CVE-2024-26633            # 单个 CVE
python -m tests.test_agents mainline                  # Mainline 识别
python -m tests.test_agents full CVE-2024-26633       # 端到端（含 dry-run）
python -m tests.test_agents dryrun CVE-2024-26633     # DryRun Agent
python -m tests.test_agents repos                     # 查看仓库配置
```
