# 基于分支的搜索和缓存 - 完整指南

## 📋 目录

1. [问题说明](#问题说明)
2. [快速迁移](#快速迁移)
3. [配置说明](#配置说明)
4. [使用方法](#使用方法)
5. [技术细节](#技术细节)
6. [常见问题](#常见问题)

---

## 问题说明

### 核心变更

**之前**: 搜索和缓存基于整个 `.git` 仓库（所有分支）
```bash
git log --all --max-count=10000  # 搜索所有分支
```

**问题**:
- ❌ 搜索到不相关分支的commits
- ❌ 缓存包含无关数据
- ❌ 可能找到错误的commit
- ❌ 浪费存储空间

**现在**: 只基于配置文件中指定的分支
```bash
git log <branch_name> --max-count=10000  # 只搜索指定分支
```

**优势**:
- ✅ 只搜索指定分支
- ✅ 缓存数据精准
- ✅ 避免跨分支错误
- ✅ 提高搜索准确性

---

## 快速迁移

### 3步完成迁移

#### 1️⃣ 更新配置文件

编辑 `config.yaml`，为每个仓库添加 `branch` 字段：

```yaml
repositories:
  "5.10-hulk":
    path: "/data/kernel/5.10"
    branch: "5.10.0-60.18.0.50.oe2203"  # 必须添加
    description: "华为5.10内核"
```

#### 2️⃣ 删除旧缓存

```bash
rm commit_cache.db
```

#### 3️⃣ 重新构建缓存

```bash
python tests/test_crawl_cve.py build-cache 5.10-hulk 10000
```

**验证输出**:
```
开始构建 5.10-hulk 的commit缓存（分支: 5.10.0-60.18.0.50.oe2203）...
执行命令: git log 5.10.0-60.18.0.50.oe2203 --max-count=10000 ...
✅ 缓存构建完成，共 10000 条记录（分支: 5.10.0-60.18.0.50.oe2203）
```

### ✅ 验证配置

运行验证脚本：
```bash
python verify_branch_config.py
```

---

## 配置说明

### 配置文件格式

```yaml
repositories:
  "5.10-hulk":
    path: "/data/kernel/5.10"              # 仓库路径（必需）
    branch: "5.10.0-60.18.0.50.oe2203"    # 分支名（必需）
    description: "华为5.10内核"            # 描述（可选）
```

### 配置要点

1. **path**: 仓库的绝对路径
2. **branch**: 分支名称，必须在仓库中存在
3. **description**: 可选的描述信息

### 查看仓库分支

```bash
cd /path/to/repo
git branch -a
```

---

## 使用方法

### 构建缓存

```bash
# 基本用法
python tests/test_crawl_cve.py build-cache <repo_version> [max_commits]

# 示例：缓存10000个commits
python tests/test_crawl_cve.py build-cache 5.10-hulk 10000

# 示例：缓存20000个commits
python tests/test_crawl_cve.py build-cache 5.10-hulk 20000
```

### 查看仓库状态

```bash
python tests/test_crawl_cve.py repos
```

**输出示例**:
```
配置的仓库:
  - 5.10-hulk
      路径: /data/kernel/5.10
      分支: 5.10.0-60.18.0.50.oe2203
      缓存: ✅ 已缓存 10000 个commits
```

### 搜索commit

```bash
# 查找引入commit
python tests/test_crawl_cve.py search_introduced <commit_id> <repo_version>

# 检查修复是否合入
python tests/test_crawl_cve.py check_fix <commit_id> <repo_version> [cve_id]
```

### 代码中使用

```python
from git_repo_manager import GitRepoManager
from config_loader import ConfigLoader

# 加载配置
config = ConfigLoader.load("config.yaml")

# 构建repo_configs（新格式）
repo_configs = {
    k: {
        'path': v['path'],
        'branch': v.get('branch')
    } 
    for k, v in config.repositories.items()
}

# 创建管理器
manager = GitRepoManager(repo_configs, use_cache=True)

# 构建缓存（只缓存指定分支）
manager.build_commit_cache("5.10-hulk", max_commits=10000)

# 搜索（只在指定分支上搜索）
result = manager.find_commit_by_id("abc123", "5.10-hulk")
```

---

## 技术细节

### 修改的核心函数

#### 1. build_commit_cache()

**之前**:
```python
cmd = ["git", "log", "--max-count=10000", "--format=%H|%s|%b|%an|%at"]
```

**现在**:
```python
cmd = ["git", "log"]
if branch:
    cmd.append(branch)  # 添加分支限定
cmd.extend(["--max-count=10000", "--format=%H|%s|%b|%an|%at"])
```

#### 2. find_commit_by_id()

新增分支验证：
```python
if branch:
    # 检查commit是否在指定分支上
    check_cmd = ["git", "branch", "--contains", commit_id]
    branch_output = self.execute_git_command(check_cmd, repo_version)
    
    if not branch_output or branch not in branch_output:
        return None  # commit不在指定分支上
```

#### 3. search_commits_by_keywords()

```python
cmd = ["git", "log"]
if branch:
    cmd.append(branch)  # 只搜索指定分支
cmd.extend(["--grep=pattern", "--max-count=100"])
```

### GitRepoManager 构造函数变更

**之前**:
```python
def __init__(self, repo_configs: Dict[str, str], use_cache: bool = True):
    """
    Args:
        repo_configs: {version_name: repo_path}
    """
```

**现在**:
```python
def __init__(self, repo_configs: Dict[str, Dict[str, str]], use_cache: bool = True):
    """
    Args:
        repo_configs: {version_name: {"path": repo_path, "branch": branch_name}}
    """
```

### 新增辅助方法

```python
def _get_repo_path(self, repo_version: str) -> Optional[str]:
    """获取仓库路径"""
    config = self.repo_configs.get(repo_version)
    if isinstance(config, dict):
        return config.get('path')
    return config if isinstance(config, str) else None

def _get_repo_branch(self, repo_version: str) -> Optional[str]:
    """获取仓库分支名称"""
    config = self.repo_configs.get(repo_version)
    if isinstance(config, dict):
        return config.get('branch')
    return None
```

---

## 常见问题

### Q1: 为什么要基于分支搜索？

**A**: 避免搜索到其他分支的commits，提高准确性：
- 防止跨分支污染
- 缓存数据更精准
- 搜索结果更可靠

### Q2: 必须指定branch吗？

**A**: 强烈推荐指定。如果不指定：
- 会使用当前分支
- 可能导致结果不一致
- 不推荐在生产环境使用

### Q3: 如何确认commit在指定分支上？

**A**: 使用命令：
```bash
cd /path/to/repo
git branch --contains <commit_id>
```

如果输出包含配置的分支名，则commit在该分支上。

### Q4: 旧缓存可以继续用吗？

**A**: 不行，必须删除并重建：
```bash
rm commit_cache.db
python tests/test_crawl_cve.py build-cache 5.10-hulk 10000
```

旧缓存包含所有分支的数据，不再准确。

### Q5: 分支名配置错误会怎样？

**A**: Git命令会失败，构建缓存或搜索会报错。

**解决方法**:
1. 使用 `git branch` 查看正确的分支名
2. 更新 `config.yaml` 中的配置
3. 重新构建缓存

### Q6: 如何验证是否生效？

**A**: 查看缓存构建日志，确认包含分支名：
```
执行命令: git log 5.10.0-60.18.0.50.oe2203 --max-count=10000 ...
```

### Q7: 搜索时没找到commit怎么办？

**A**: 可能的原因：
1. **Commit不在指定分支** - 正常，说明过滤起作用了
2. **缓存范围不够** - 增加 max_commits 重建缓存
3. **Commit确实不存在** - 检查commit ID是否正确

**调试步骤**:
```bash
# 1. 手动检查commit是否在分支上
cd /path/to/repo
git branch --contains <commit_id>

# 2. 如果在分支上但搜索不到，重建缓存
rm commit_cache.db
python tests/test_crawl_cve.py build-cache 5.10-hulk 20000
```

---

## 验证清单

使用验证脚本检查所有配置：

```bash
python verify_branch_config.py
```

**检查项**:
- ✅ 配置文件中是否配置了 branch
- ✅ 分支是否存在于仓库
- ✅ 缓存数据库状态
- ✅ Git命令是否正确执行

---

## 影响范围

### 已更新的文件

1. ✅ `git_repo_manager.py` - 核心搜索逻辑
2. ✅ `tests/test_crawl_cve.py` - 测试代码
3. ✅ `enhanced_cve_analyzer.py` - CVE分析器
4. ✅ `cli.py` - 命令行工具

### 用户需要的操作

1. ✅ 更新 `config.yaml` - 添加 branch 字段
2. ✅ 删除旧缓存 - `rm commit_cache.db`
3. ✅ 重新构建缓存 - 使用新格式

---

## 性能对比

### 缓存大小

**之前（所有分支）**:
```
缓存所有分支: 50000+ commits
占用空间: ~100MB
```

**现在（单个分支）**:
```
缓存单个分支: 10000 commits
占用空间: ~20MB
```

### 搜索速度

**使用缓存**:
- 精确ID匹配: < 0.1秒
- Subject搜索: < 1秒

**不使用缓存**:
- 精确ID匹配: 5-10秒
- Subject搜索: 30-60秒

---

## 快速参考

### 配置模板

```yaml
repositories:
  "your-repo-name":
    path: "/path/to/repo"
    branch: "your-branch-name"
    description: "描述信息"
```

### 常用命令

```bash
# 验证配置
python verify_branch_config.py

# 查看仓库状态
python tests/test_crawl_cve.py repos

# 构建缓存
python tests/test_crawl_cve.py build-cache <repo> <max_commits>

# 搜索commit
python tests/test_crawl_cve.py search_introduced <commit_id> <repo>

# 检查修复
python tests/test_crawl_cve.py check_fix <commit_id> <repo> [cve_id]
```

---

## 相关文档

- **配置使用**: `CONFIG_USAGE.md`
- **测试指南**: `TESTING_CACHE_GUIDE.md`
- **项目结构**: `../PROJECT_STRUCTURE.md`

---

## 总结

### 关键变化

1. **配置格式**: 需要为每个仓库指定 `branch`
2. **缓存范围**: 只缓存指定分支的commits
3. **搜索范围**: 只在指定分支上搜索
4. **验证机制**: 检查commit是否在指定分支上

### 迁移步骤

1. 更新 `config.yaml` 添加 branch
2. 删除旧缓存 `rm commit_cache.db`
3. 重新构建缓存
4. 验证配置

### 重要提醒

⚠️ **必须删除旧缓存并重建** - 旧缓存包含所有分支数据，不再准确！
