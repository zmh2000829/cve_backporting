# CVE 补丁回溯分析工具

针对自维护 Linux Kernel 仓库的 CVE 漏洞补丁回溯、引入检测与依赖分析工具。

## 核心能力

### 1. CVE 全流程分析 (`analyze`)

**场景：** 给定一个 CVE ID，自动完成从情报获取到补丁可行性验证的全链路分析。

```
Crawler → Analysis → Dependency → DryRun
```

- 从 MITRE API 获取漏洞元数据，从 googlesource 获取补丁 diff
- 识别 Mainline fix commit 和引入 commit
- 三级搜索（ID → Subject → Diff）定位目标仓库中的对应 commit
- 判定漏洞是否已引入、修复补丁是否已合入
- 若未合入：分析前置依赖补丁 + dry-run 检测冲突
- 适用于日常安全巡检、CVE 修复评估、批量漏洞状态盘点

### 2. 漏洞引入检测 (`check-intro`)

**场景：** 判断某个 mainline commit 是否在本地仓库中存在对应提交，确认漏洞是否被引入。

- 支持两种输入：直接指定 commit ID，或通过 CVE ID 自动提取引入 commit
- 三级策略全部执行（不短路），展示每个策略的独立结果
- L1 精确匹配区分"不存在"/"存在但不在目标分支"/"在目标分支"三种状态
- 适用于快速确认单个漏洞的影响面、mainline commit 溯源

### 3. Commit 缓存构建 (`build-cache`)

**场景：** 对百万级 commit 仓库建立 SQLite + FTS5 缓存，加速后续搜索。

- 流式读取 git log，不将全量输出加载到内存
- 50000 条批量写入 + WAL 模式 + PRAGMA 调优
- 导入期间禁用 FTS 触发器，完成后重建索引
- 大仓库 commit 计数支持三级回退（rev-list → 缓存数 → 采样），超时优雅降级
- 适用于首次初始化、定期缓存刷新

### 4. Commit 搜索 (`search`)

**场景：** 快速查询某个 commit ID 是否存在于目标仓库的指定分支上。

- 先查缓存，再查 git 对象库 + 分支祖先校验
- 适用于手动验证、脚本集成

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
├── cli.py                    # CLI 入口 (Rich 交互界面)
├── config.yaml               # 配置文件
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

### 构建缓存（百万级仓库首次使用前必须执行）

```bash
python cli.py build-cache --target 5.10-hulk
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
