# 测试目录

本目录包含项目的所有测试代码和测试工具。

## 📋 测试文件

### test_crawl_cve.py
综合测试工具，支持多种测试模式。

## 🧪 测试命令

### 基础测试

```bash
# 从项目根目录运行
cd /path/to/cve_backporting

# 测试单个CVE
python3 tests/test_crawl_cve.py CVE-2025-40198

# 测试mainline识别
python3 tests/test_crawl_cve.py mainline

# 测试完整逻辑
python3 tests/test_crawl_cve.py full
```

### 功能测试

#### 1. 查找引入commit
```bash
# 显示搜索策略（无需配置）
python3 tests/test_crawl_cve.py search_introduced 8b67f04ab9de

# 实际搜索（需要配置config.yaml）
python3 tests/test_crawl_cve.py search_introduced 8b67f04ab9de 5.10-hulk
```

#### 2. 检查修复是否已合入
```bash
# 带CVE ID
python3 tests/test_crawl_cve.py check_fix abc123 5.10-hulk CVE-2025-40198

# 不带CVE ID
python3 tests/test_crawl_cve.py check_fix abc123
```

## 📁 输出文件

所有测试输出自动保存到 `../output/` 目录：

```
output/
├── cve_CVE_2025_40198_result.json      # CVE完整信息
├── test_mainline_CVE_2025_40198.json   # Mainline测试结果
├── test_full_logic_CVE_2025_40198.json # 完整逻辑测试结果
└── patch_8ecb790ea8c3.txt              # 补丁文件
```

## ⚙️ 配置要求

### 最小配置（仅查看策略）
无需配置，可以直接运行测试并查看搜索策略。

### 完整配置（实际搜索）
需要配置 `config.yaml`：

```yaml
repositories:
  5.10-hulk:
    path: /path/to/your/kernel-5.10
    branch: master
  6.6-hulk:
    path: /path/to/your/kernel-6.6
    branch: master

cache:
  enabled: true
  db_path: commit_cache.db
```

## 📊 测试覆盖

- ✅ CVE信息获取
- ✅ Mainline commit识别
- ✅ 版本映射关系
- ✅ Commit搜索（精确+模糊）
- ✅ Backport模式识别
- ✅ 修复状态检查
- ✅ 依赖分析

## 🐛 问题排查

### 网络问题
如果遇到网络错误：
```
OSError: [Errno 101] Network is unreachable
```

这是因为无法访问kernel.org，但不影响：
- 显示搜索策略
- 查看已保存的结果
- 测试本地仓库功能

### 配置问题
如果提示找不到仓库：
```
ValueError: 未配置版本 5.10-hulk 的仓库路径
```

请检查 `config.yaml` 是否正确配置。

## 📚 更多信息

详细测试指南请查看：`../docs/TESTING_GUIDE.md`
