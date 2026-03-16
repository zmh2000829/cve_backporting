# CVE Backporting — Linux 内核漏洞补丁智能回溯引擎

<div align="center">

**一条命令，从 CVE 编号到可落地的 Backport 方案。**

面向自维护 Linux Kernel 仓库的**全自动 CVE 分析 Pipeline**，集情报采集、引入判定、修复定位、依赖分析、冲突预检于一体。

[![GitHub](https://img.shields.io/badge/GitHub-zmh2000829%2Fcve_backporting-blue?logo=github)](https://github.com/zmh2000829/cve_backporting)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)

</div>

---

## 🎯 核心价值

| 传统人工流程 | 本工具 |
|-------------|--------|
| 手动查 MITRE、googlesource、邮件列表，逐个比对 commit | **Crawler Agent** 自动聚合多源情报，三级回退保证可用性 |
| `git log --grep` 然后肉眼比对 subject | **三级搜索引擎** (ID → Subject → Diff) 自动定位，置信度量化输出 |
| 本地仓库 squash 了社区补丁，传统 diff 比对完全失效 | **Diff 包含度算法** 识别"小补丁藏在大 commit 里"的场景 |
| 内核版本间路径重组 (`fs/cifs/` → `fs/smb/client/`)，搜索直接找不到 | **PathMapper** 双向路径翻译，自动适配 8+ 已知子系统迁移 |
| 百万级 commit 仓库 `git log` 一跑几分钟 | **SQLite + FTS5 缓存** + 增量更新，日常同步秒级完成 |
| cherry-pick 前不确定要不要先合前置补丁 | **Hunk 级依赖分析** 精确到行范围，强/中/弱三级分级 |

---

## 🚀 技术亮点

### 1️⃣ 多 Agent 流水线架构

四个独立 Agent（Crawler / Analysis / Dependency / DryRun）通过 Pipeline 编排器串联，每个阶段可独立使用、独立测试，关注点清晰分离。

```
CVE ID → Crawler → Analysis → Dependency → DryRun → 决策报告
         情报采集   三级搜索    依赖分析    冲突预检
```

### 2️⃣ 三级渐进式 Commit 搜索

**L1 精确 ID 匹配**（毫秒级）→ **L2 Subject 语义匹配**（SequenceMatcher 标准化比对）→ **L3 Diff 代码级匹配**（双向相似度 + 单向包含度自适应切换）

在 commit ID 完全偏移的深度定制仓库中仍能精准定位。

### 3️⃣ Diff Containment 算法 — 企业仓库的"杀手锏"

针对企业内核"多 patch squash 为一个 commit"的常见实践，设计了基于 **Multiset 的单向包含度检测**：

```
社区补丁 (3 行改动)
  +line_a
  +line_b
  -line_c

企业大 commit (200 行改动)
  +unrelated_1
  +line_a      ✓ matched
  +line_b      ✓ matched
  -line_c      ✓ matched
  +unrelated_2
  -unrelated_3

结果: 包含度 100% (3/3 matched)
     双向相似度仅 ~30% (传统算法失效)
```

### 4️⃣ 跨版本路径映射

内置 **8 组 Linux 内核子系统目录迁移规则**（cifs→smb、staging 毕业等），支持自定义扩展。在搜索和比对两个环节双向翻译，彻底解决"同一个文件在不同版本有不同路径"的匹配盲区。

### 5️⃣ 千万级 Commit 性能优化

- 流式 `git log` 读取（零内存拷贝）
- 50K 批量写入、WAL + mmap 调优
- FTS5 全文索引加速 subject 搜索
- **增量缓存**自动校验分支一致性，rebase 后智能降级全量重建

### 6️⃣ 多源补丁获取与容错

`git.kernel.org`（主）→ `kernel.googlesource.com`（备，含重试）→ 本地 Git 对象库（兜底）

三级回退 + 部分结果互补合并，单一数据源故障不影响分析流程。

### 7️⃣ 五级自适应 DryRun 引擎 — 核心创新

`strict → -C1 → 3way → 上下文重生成 → 冲突适配` 渐进式策略。

**两层定位架构**：
- **第一层** `_locate_hunk` — 用**锚点行定位**（before-context 最后一行 / after-context 第一行单行搜索）精确找到变更点，**不受 context 序列被额外代码行打断的影响**
- **第二层** `_locate_in_file` — 用**七策略序列搜索**（精确 → 函数名锚点 → 行号窗口 → 模糊 → context → 投票 → 最长行）做兜底

**补丁重建改进**：直接从目标文件变更点读取 context，不走查 hunk_lines，彻底解决额外行导致的对齐错位。

**跨 hunk 偏移传播**：同文件多个 hunk 的搜索越来越精准。

**路径映射感知**：自动翻译跨版本文件路径，优先选用 stable backport 补丁。

**逐 hunk 冲突分析**：精确到行的"补丁期望 vs 文件实际"对比、L1/L2/L3 三级冲突严重度分级、自动生成冲突适配补丁。

### 8️⃣ 代码语义匹配（Level 8 策略）

当 context 序列被企业仓库的自定义代码打断时，提取 patch 的实际代码片段（removed/added），用**多维度代码相似度**（结构相似度 + 标识符匹配率 + 关键字序列相似度）在目标文件中搜索，**不依赖 context 序列连续性**，彻底解决"内容相同但 context 不连续"的核心难题。

### 9️⃣ 闭环验证框架

基于 `git worktree` 的非破坏性回退验证：自动创建修复前快照、运行 Pipeline、与真实合入记录对比，输出完整差异诊断（社区补丁 vs 本地修复对比、DryRun 冲突根因分析、前置依赖 TP/FP/FN 明细），并支持集成 LLM API 进行 AI 根因分析。批量基准测试汇总 Precision / Recall / F1 量化工具整体置信度。

---

## 📊 核心能力

### 1. CVE 全流程分析 (`analyze`)

给定一个 CVE ID，自动完成 **情报获取 → 引入检测 → 修复定位 → 依赖分析 → Dry-Run 冲突预检** 全链路。

```bash
python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk
```

### 2. 漏洞引入检测 (`check-intro`)

判断 mainline 引入 commit 在目标仓库中是否存在对应提交，确认漏洞是否影响本地内核。

```bash
python cli.py check-intro --cve CVE-2024-26633 --target 5.10-hulk
```

### 3. 修复补丁检测 (`check-fix`)

判断修复补丁是否已合入目标仓库，给出明确的"已修复 / 需 backport"结论。

```bash
python cli.py check-fix --cve CVE-2024-26633 --target 5.10-hulk
```

### 4. Commit 缓存构建 (`build-cache`)

对百万级 commit 仓库建立 SQLite + FTS5 缓存，加速全部搜索能力。

```bash
# 增量更新（默认）
python cli.py build-cache --target 5.10-hulk

# 强制全量重建
python cli.py build-cache --target 5.10-hulk --full
```

### 5. 工具准确度验证 (`validate`)

选取已修复的 CVE，通过 `git worktree` 回退到修复前状态，运行完整 Pipeline，与真实合入记录进行对比。

```bash
python cli.py validate \
  --cve CVE-2024-26633 \
  --target 5.10-hulk \
  --known-fix da23bd709b46
```

### 6. 批量基准测试 (`benchmark`)

从 YAML 文件批量加载已修复 CVE 集合，逐一执行回退验证，汇总工具整体准确度。

```bash
python cli.py benchmark --file benchmarks.yaml --target 5.10-hulk
```

---

## 🏗️ 架构

```
cve_backporting/
├── core/                     # 基础设施层
│   ├── models.py             #   数据模型
│   ├── config.py             #   YAML 配置加载
│   ├── git_manager.py        #   Git 仓库操作 + SQLite 缓存
│   ├── matcher.py            #   相似度算法 + 依赖图
│   ├── code_matcher.py       #   代码语义匹配 (Level 8)
│   ├── ai_patch_generator.py #   AI 辅助补丁生成
│   ├── function_analyzer.py  #   函数定义和调用链分析
│   └── ui.py                 #   Rich 终端 UI 组件
├── agents/                   # 核心 Agent 层
│   ├── crawler.py            #   Crawler Agent — CVE 情报 + 补丁获取
│   ├── analysis.py           #   Analysis Agent — 三级 commit 搜索
│   ├── dependency.py         #   Dependency Agent — 前置依赖分析
│   └── dryrun.py             #   DryRun Agent — git apply 试应用
├── pipeline.py               # Pipeline 编排器
├── cli.py                    # CLI 入口
├── config.yaml               # 配置文件
├── benchmarks.example.yaml   # 基准测试集示例
├── requirements.txt
├── tests/
│   └── test_agents.py        # 测试套件
└── docs/
    ├── TECHNICAL.md          # 技术文档
    └── ADAPTIVE_DRYRUN.md    # 五级自适应算法详解
```

---

## 🔧 快速开始

### 安装

```bash
pip install -r requirements.txt
```

### 配置

编辑 `config.yaml`，填入本地仓库路径和分支名：

```yaml
repositories:
  "5.10-hulk":
    path: "/path/to/linux"
    branch: "linux-5.10.y"
```

### 构建缓存

```bash
python cli.py build-cache --target 5.10-hulk
```

### 分析 CVE

```bash
python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk
```

---

## 📈 性能指标

| 指标 | 数据 |
|------|------|
| 支持仓库规模 | 千万级 commit |
| 单 CVE 分析耗时 | 15-30 秒（含网络请求） |
| Commit 搜索覆盖率 | L1 (ID) + L2 (Subject) + L3 (Diff + 包含度) 三级渐进 |
| 路径映射 | 内置 8 组规则，支持自定义扩展 |
| DryRun 冲突分析 | 精确到行的 expected vs actual 对比 |
| 补丁获取容错 | 三级回退 + 部分结果互补合并 |
| 验证框架 | git worktree 非破坏性回退，Precision/Recall/F1 量化 |

---

## 🎓 算法详解

详见 [`docs/TECHNICAL.md`](docs/TECHNICAL.md) 和 [`docs/ADAPTIVE_DRYRUN.md`](docs/ADAPTIVE_DRYRUN.md)

### 核心创新点

1. **单向包含度检测** — 首次在 CVE backport 场景中应用 Multiset 包含度算法，解决 squash commit 匹配失效问题

2. **两层定位架构 + 锚点行定位** — 锚点行搜索不受 context 序列被额外代码打断的影响，彻底解决"内容相同但 context 不连续"的核心难题；七策略序列搜索兜底处理复杂场景

3. **变更点直读补丁重建** — 不走查 hunk_lines（额外行导致错位），直接从目标文件变更点读取 context，保证补丁对齐正确

4. **五级自适应补丁应用 + 跨 hunk 偏移传播** — 从 strict 到冲突适配的渐进式降级，同文件多 hunk 的偏移量自动传播越来越精准

5. **闭环验证框架** — 基于 git worktree 的非破坏性回退验证，Precision/Recall/F1 量化工具置信度

6. **跨版本路径映射** — 双向路径翻译贯穿搜索、比对、DryRun 全链路，彻底解决目录重组盲区

7. **代码语义匹配** — 多维度相似度（结构 + 标识符 + 关键字），不依赖 context 序列连续性

---

## 📝 使用示例

### 场景 1: 日常 CVE 巡检

```bash
# 快速检查某个 CVE 是否影响本地内核
python cli.py check-intro --cve CVE-2024-26633 --target 5.10-hulk

# 检查修复补丁是否已合入
python cli.py check-fix --cve CVE-2024-26633 --target 5.10-hulk
```

### 场景 2: 完整分析与决策

```bash
# 获取完整的分析报告，包括前置依赖和冲突预检
python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk
```

### 场景 3: 工具准确度评估

```bash
# 验证工具在已修复 CVE 上的准确度
python cli.py validate \
  --cve CVE-2024-26633 \
  --target 5.10-hulk \
  --known-fix da23bd709b46 \
  --known-prereqs "commit1,commit2"

# 批量基准测试
python cli.py benchmark --file benchmarks.yaml --target 5.10-hulk
```

---

## 🧪 测试

```bash
python -m tests.test_agents                           # 完整测试
python -m tests.test_agents CVE-2024-26633            # 单个 CVE
python -m tests.test_agents mainline                  # Mainline 识别
python -m tests.test_agents full CVE-2024-26633       # 端到端（含 dry-run）
```

---

## 📚 文档

- **[TECHNICAL.md](docs/TECHNICAL.md)** — 完整技术文档，包含系统架构、算法详解、数据模型
- **[ADAPTIVE_DRYRUN.md](docs/ADAPTIVE_DRYRUN.md)** — 五级自适应 DryRun 算法深度解析

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

## 📄 许可证

MIT License — 详见 [LICENSE](LICENSE)

---

## 🙏 致谢

感谢 Linux 内核社区和所有贡献者。

---

<div align="center">

**Made with ❤️ for Linux Kernel Security**

</div>
