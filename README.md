# CVE 补丁回溯与依赖分析工具

针对自维护 Linux Kernel 仓库，自动化完成 CVE 漏洞补丁的定位、状态判定和前置依赖分析。

## 功能概览

| 功能 | 说明 |
|------|------|
| CVE 情报获取 | 从 MITRE API 获取漏洞元数据，自动识别 mainline fix commit |
| 版本映射 | 解析 `affected` 字段，建立 kernel 版本 → commit 的完整映射 |
| 引入 commit 识别 | 从 `affected.versions[].version` 提取漏洞引入 commit |
| 三级搜索定位 | 在目标仓库中按 ID → Subject → Diff 三级策略查找对应 commit |
| 合入状态判定 | 自动判断修复补丁是否已合入目标仓库 |
| 前置依赖分析 | 对未合入的补丁，分析修改同文件的中间 commits 和 Fixes 引用 |

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置仓库

复制示例配置并编辑：

```bash
cp config.example.yaml config.yaml
```

编辑 `config.yaml`，填写你的内核仓库信息：

```yaml
repositories:
  "5.10-hulk":
    path: "/path/to/your/linux"
    branch: "linux-5.10.y"
    description: "自维护5.10内核"
```

### 3. 构建 commit 缓存（首次使用）

对千万级 commit 的仓库，缓存可将搜索从分钟级降到毫秒级：

```bash
# 缓存所有 commits（推荐，约需 2-5 分钟）
python tests/test_crawl_cve.py build-cache 5.10-hulk

# 或只缓存最近 N 个
python tests/test_crawl_cve.py build-cache 5.10-hulk 100000
```

### 4. 分析 CVE

```bash
# 端到端分析（推荐）
python tests/test_crawl_cve.py full CVE-2024-26633

# 仅获取 CVE 信息（不查仓库）
python tests/test_crawl_cve.py CVE-2024-26633

# Mainline 识别准确性测试
python tests/test_crawl_cve.py mainline

# 搜索指定 commit
python tests/test_crawl_cve.py search da23bd709b46 5.10-hulk
```

### 5. CLI 工具

```bash
# 分析单个 CVE
python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk

# 批量分析（文件每行一个 CVE ID）
python cli.py analyze --batch cve_list.txt --target 5.10-hulk

# 构建缓存
python cli.py build-cache --target 5.10-hulk

# 搜索 commit
python cli.py search --commit da23bd709b46 --target 5.10-hulk
```

## 输出示例

以 CVE-2024-26633 为例，分析报告：

```
## 状态
- 是否受影响: 是
- 是否已修复: 是

## 漏洞引入commit定位
- 目标仓库commit: fbfa743a9d2a
- 策略: exact_id
- 置信度: 100%

## 修复补丁定位
- 目标仓库commit: da23bd709b46
- 策略: subject_match
- 置信度: 100%
```

对未修复的 CVE（如 CVE-2024-50257），会列出前置依赖补丁：

```
## 前置依赖补丁 (10 个)
- 1f3b9000cb44 netfilter: x_tables: fix compat match/target pad ...
- 3fdebc2d8e79 netfilter: x_tables: Use correct memory barriers.
...

## 建议
- 修复补丁 f48d258f0ac5 未合入, 发现 20 个修改相同文件的commits需要review
```

## 项目结构

```
cve_backporting/
├── crawl_cve_patch.py        # CVE 信息获取 + Patch 下载
├── git_repo_manager.py       # Git 仓库操作 + SQLite 缓存
├── enhanced_patch_matcher.py # 相似度匹配 + 依赖分析
├── enhanced_cve_analyzer.py  # 端到端分析主流程
├── config_loader.py          # YAML 配置加载
├── cli.py                    # 命令行工具
├── config.yaml               # 配置文件（git ignored）
├── config.example.yaml       # 配置模板
├── requirements.txt          # Python 依赖
├── tests/
│   └── test_crawl_cve.py     # 测试套件 + 快捷 CLI
├── docs/
│   └── TECHNICAL.md          # 技术文档
└── output/                   # 分析结果输出目录
```

## 配置说明

`config.yaml` 的完整字段参见 `config.example.yaml`。核心配置：

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `repositories.<name>.path` | 内核仓库绝对路径 | 必填 |
| `repositories.<name>.branch` | 目标分支名 | 必填 |
| `cache.enabled` | 是否启用 SQLite 缓存 | `true` |
| `cache.max_cached_commits` | 最大缓存 commit 数 | `10000000` |
| `matching.subject_similarity_threshold` | Subject 匹配阈值 | `0.85` |
| `matching.diff_similarity_threshold` | Diff 匹配阈值 | `0.70` |
