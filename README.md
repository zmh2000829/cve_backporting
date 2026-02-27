# CVE 补丁回溯分析工具

针对自维护 Linux Kernel 仓库的 CVE 漏洞补丁回溯与依赖分析工具。

## 架构

四个核心 Agent 通过 Pipeline 编排：

```
Crawler Agent → Analysis Agent → Dependency Agent → DryRun Agent
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

# 编辑配置（填入本地仓库路径）
vim config.yaml

# 构建 commit 缓存（千万级仓库首次需要）
python cli.py build-cache --target 5.10-hulk

# 分析单个 CVE
python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk

# 跳过 dry-run（加快速度）
python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk --no-dryrun

# 批量分析
python cli.py analyze --batch cve_list.txt --target 5.10-hulk

# 搜索 commit
python cli.py search --commit d375b98e0248 --target 5.10-hulk
```

## 测试

```bash
# 完整测试套件
python -m tests.test_agents

# 单个 CVE
python -m tests.test_agents CVE-2024-26633

# Mainline 识别准确性
python -m tests.test_agents mainline

# 端到端分析（含 dry-run）
python -m tests.test_agents full CVE-2024-26633

# 单独测试 DryRun Agent
python -m tests.test_agents dryrun CVE-2024-26633

# 查看仓库配置
python -m tests.test_agents repos
```

## 项目结构

```
cve_backporting/
├── core/                     # 基础设施层
│   ├── models.py             #   所有数据模型
│   ├── config.py             #   YAML 配置加载
│   ├── git_manager.py        #   Git 仓库操作 + SQLite 缓存
│   └── matcher.py            #   相似度算法 + 依赖图
├── agents/                   # 核心 Agent 层
│   ├── crawler.py            #   Crawler Agent
│   ├── analysis.py           #   Analysis Agent
│   ├── dependency.py         #   Dependency Agent
│   └── dryrun.py             #   DryRun Agent
├── pipeline.py               # Pipeline 编排器
├── cli.py                    # CLI 入口
├── tests/
│   └── test_agents.py        # 测试套件
├── config.yaml               # 配置文件
├── requirements.txt
└── docs/
    └── TECHNICAL.md          # 技术文档
```

## 配置

`config.yaml` 关键配置：

```yaml
repositories:
  "5.10-hulk":
    path: "/path/to/linux"
    branch: "linux-5.10.y"

cache:
  enabled: true
  database_path: "./commit_cache.db"

matching:
  subject_similarity_threshold: 0.85
  diff_similarity_threshold: 0.70
```
