# 配置文件使用说明

## 概述

项目已更新为从 `config.yaml` 配置文件中读取仓库和分支信息，无需在代码中硬编码。

## 配置步骤

### 1. 创建配置文件

复制示例配置文件并根据实际情况修改：

```bash
cp config.example.yaml config.yaml
```

### 2. 配置仓库信息

编辑 `config.yaml` 文件，在 `repositories` 部分添加你的仓库配置：

```yaml
repositories:
  # 格式: 版本名称: 仓库配置
  "5.10-hulk":
    path: "/data/zhangmh/Associated_Patch_Analysis/5.10/kernel"
    branch: "5.10.0-60.18.0.50.oe2203"
    description: "华为5.10内核维护版本"
  
  "6.1-custom":
    path: "/path/to/your/kernel/repo"
    branch: "your-branch-name"
    description: "自定义内核版本"
```

### 3. 验证配置

使用测试工具验证配置是否正确：

```bash
cd tests
python test_crawl_cve.py repos
```

这将显示所有配置的仓库信息，包括路径是否存在。

## 使用配置

### 在测试中使用

#### 查看配置的仓库

```bash
python test_crawl_cve.py repos
```

#### 使用配置的仓库进行测试

```bash
# 如果不指定仓库版本，将自动使用配置文件中的第一个仓库
python test_crawl_cve.py search_introduced 8b67f04ab9de

# 指定特定的仓库版本
python test_crawl_cve.py search_introduced 8b67f04ab9de 5.10-hulk

# 检查修复补丁是否已合入
python test_crawl_cve.py check_fix abc123def456 5.10-hulk CVE-2025-40198
```

### 在代码中使用

```python
from config_loader import ConfigLoader

# 加载配置
config = ConfigLoader.load("config.yaml")

# 获取所有仓库
repositories = config.repositories

# 获取特定仓库信息
repo_info = repositories.get("5.10-hulk")
if repo_info:
    repo_path = repo_info['path']
    repo_branch = repo_info['branch']
    repo_desc = repo_info.get('description', '')
```

## 配置文件结构

完整的配置文件包含以下部分：

- **repositories**: 仓库配置（必需）
- **cache**: 缓存配置
- **matching**: 匹配策略配置
- **dependency**: 依赖分析配置
- **cve_sources**: CVE信息源配置
- **ai_analysis**: AI分析配置
- **performance**: 性能优化配置
- **output**: 输出配置
- **alerts**: 告警配置
- **advanced**: 高级选项

详细配置选项请参考 `config.example.yaml`。

## 配置验证

使用 ConfigLoader 验证配置：

```python
from config_loader import ConfigLoader

config = ConfigLoader.load("config.yaml")
is_valid = ConfigLoader.validate_config(config)

if is_valid:
    print("配置验证通过")
else:
    print("配置验证失败，请检查配置文件")
```

## 常见问题

### 1. 配置文件不存在

如果 `config.yaml` 不存在，系统会显示警告并使用默认配置。请确保创建了配置文件。

### 2. 仓库路径不存在

配置验证会检查仓库路径是否存在。如果路径不存在，会显示错误信息。请确保：
- 路径正确
- 有访问权限
- 仓库已经克隆到指定位置

### 3. 查看可用的仓库版本

在运行测试时，如果参数不足，系统会自动显示配置的仓库列表：

```bash
python test_crawl_cve.py search_introduced
# 将显示用法和可用的仓库版本列表
```

## 示例工作流

```bash
# 1. 创建配置文件
cp config.example.yaml config.yaml

# 2. 编辑配置文件，添加你的仓库信息
vim config.yaml

# 3. 验证配置
python test_crawl_cve.py repos

# 4. 运行测试（使用配置的第一个仓库）
python test_crawl_cve.py search_introduced 8b67f04ab9de

# 5. 或指定特定仓库
python test_crawl_cve.py search_introduced 8b67f04ab9de 5.10-hulk
```

## 更新说明

### 主要变更

1. **tests/test_crawl_cve.py**
   - 添加了配置加载函数：`load_config()`, `get_repository_list()`, `get_repository_info()`
   - 更新了测试函数，支持从配置文件读取仓库信息
   - 添加了 `repos` 命令用于查看配置的仓库
   - 命令行参数提示中会显示可用的仓库列表

2. **crawl_cve_patch.py**
   - 所有 HTTP 请求添加了 `verify=False` 参数，避免SSL证书验证问题

### 向后兼容

所有修改都保持向后兼容：
- 如果未提供仓库参数，会自动使用配置文件中的第一个仓库
- 如果配置文件不存在，会使用默认配置或模拟模式
- 原有的命令行参数仍然有效
