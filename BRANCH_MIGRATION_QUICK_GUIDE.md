# 基于分支搜索 - 快速迁移指南

## 🎯 核心变更

**之前**: 搜索整个 `.git` 仓库（所有分支）  
**现在**: 只搜索配置文件中指定的分支

## ⚡ 快速迁移（3步）

### 1️⃣ 更新配置文件

编辑 `config.yaml`，为每个仓库添加 `branch` 字段：

```yaml
repositories:
  "5.10-hulk":
    path: "/data/kernel/5.10"
    branch: "5.10.0-60.18.0.50.oe2203"  # 新增此行
    description: "华为5.10内核"
```

### 2️⃣ 删除旧缓存

```bash
rm commit_cache.db
```

### 3️⃣ 重新构建缓存

```bash
python tests/test_crawl_cve.py build-cache 5.10-hulk 10000
```

## ✅ 验证配置

运行验证脚本：

```bash
python verify_branch_config.py
```

## 📝 关键改变

### Git命令对比

**之前（搜索所有分支）**:
```bash
git log --all --max-count=10000
```

**现在（只搜索指定分支）**:
```bash
git log <branch_name> --max-count=10000
```

### 代码更新

**之前**:
```python
repo_configs = {k: v['path'] for k, v in config.repositories.items()}
```

**现在**:
```python
repo_configs = {k: {'path': v['path'], 'branch': v.get('branch')} 
               for k, v in config.repositories.items()}
```

## ⚠️ 注意事项

1. **必须删除旧缓存** - 旧缓存包含所有分支的数据
2. **必须指定分支** - 在 config.yaml 中为每个仓库添加 branch 字段
3. **分支必须存在** - 确保分支名在仓库中真实存在

## 🔍 验证是否生效

构建缓存时，查看输出：

```
开始构建 5.10-hulk 的commit缓存（分支: 5.10.0-60.18.0.50.oe2203）...
执行命令: git log 5.10.0-60.18.0.50.oe2203 --max-count=10000 ...
✅ 缓存构建完成，共 10000 条记录（分支: 5.10.0-60.18.0.50.oe2203）
```

**关键**: 命令中应该包含分支名称

## 📚 详细文档

- **完整说明**: `docs/BRANCH_BASED_SEARCH.md`
- **验证脚本**: `verify_branch_config.py`
- **配置说明**: `docs/CONFIG_USAGE.md`

## 🆘 常见问题

### Q: 为什么要这样改？
**A**: 避免搜索到其他分支的commits，提高搜索准确性和缓存效率。

### Q: 不指定分支会怎样？
**A**: 会使用当前分支，但不推荐。应该明确指定分支。

### Q: 如何查看仓库有哪些分支？
**A**: 
```bash
cd /path/to/repo
git branch -a
```

### Q: 旧缓存可以继续用吗？
**A**: 不行，必须删除并重建。旧缓存包含了所有分支的数据。

## 🎉 完成！

迁移完成后，所有搜索和缓存操作将只在配置的分支上进行。

测试一下：
```bash
python tests/test_crawl_cve.py search_introduced <commit_id> 5.10-hulk
```
