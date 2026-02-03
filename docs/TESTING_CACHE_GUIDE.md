# 测试和缓存使用指南

## 重要变更说明

为了确保测试的准确性和可靠性，我们已经移除了所有模拟/假数据测试。现在所有搜索功能都基于真实的Git仓库和缓存数据库。

## 前置要求

### 1. 配置仓库

首先需要配置你的Git仓库：

```bash
# 复制配置文件模板
cp config.example.yaml config.yaml

# 编辑配置文件
vim config.yaml
```

在 `config.yaml` 中配置你的仓库：

```yaml
repositories:
  "5.10-hulk":
    path: "/path/to/your/kernel/repo"
    branch: "your-branch-name"
    description: "你的内核版本描述"
```

### 2. 构建缓存数据库

**这是关键步骤！** 在首次使用前，必须为每个仓库构建缓存数据库：

```bash
cd tests
python test_crawl_cve.py build-cache 5.10-hulk 10000
```

参数说明：
- `5.10-hulk`: 仓库版本名称（在config.yaml中配置的）
- `10000`: 缓存的最大commit数量（可选，默认10000）

构建缓存的好处：
- **大幅提高搜索速度**: 从分钟级别降低到秒级
- **支持全文搜索**: 可以快速搜索commit message中的关键词
- **减少仓库压力**: 避免频繁执行git命令

## 使用流程

### 完整使用流程

```bash
# 1. 查看配置的仓库和缓存状态
python test_crawl_cve.py repos

# 输出示例:
# 配置的仓库:
#   - 5.10-hulk
#       路径: /data/zhangmh/kernel
#       分支: 5.10.0-60.18.0.50.oe2203
#       缓存: ⚠️  未构建 (建议执行: python test_crawl_cve.py build-cache 5.10-hulk)

# 2. 如果缓存未构建，先构建缓存
python test_crawl_cve.py build-cache 5.10-hulk 10000

# 3. 现在可以运行实际测试
python test_crawl_cve.py search_introduced 8b67f04ab9de 5.10-hulk
```

### 查找漏洞引入commit

```bash
# 在配置的仓库中查找社区commit
python test_crawl_cve.py search_introduced <community_commit_id> [repo_version]

# 示例
python test_crawl_cve.py search_introduced 8b67f04ab9de 5.10-hulk
```

如果未指定仓库版本，会自动使用配置文件中的第一个仓库。

搜索策略：
1. **精确ID匹配**: 查找完全相同的commit ID
2. **Subject模糊匹配**: 基于commit message的相似度
3. **文件匹配**: 基于修改的文件列表

### 检查修复补丁是否已合入

```bash
# 检查修复补丁是否已在自维护仓库中
python test_crawl_cve.py check_fix <introduced_commit_id> [repo_version] [cve_id]

# 示例1: 指定CVE ID（自动获取修复信息）
python test_crawl_cve.py check_fix abc123def456 5.10-hulk CVE-2025-40198

# 示例2: 不指定CVE ID（需要手动输入修复commit）
python test_crawl_cve.py check_fix abc123def456 5.10-hulk
```

## 可用命令列表

```bash
# 查看配置的仓库和缓存状态
python test_crawl_cve.py repos

# 构建commit缓存
python test_crawl_cve.py build-cache <repo_version> [max_commits]

# 测试mainline识别功能
python test_crawl_cve.py mainline

# 测试完整项目逻辑
python test_crawl_cve.py full

# 测试单个CVE
python test_crawl_cve.py CVE-2024-26633

# 查找引入commit
python test_crawl_cve.py search_introduced <commit_id> [repo_version]

# 检查修复是否合入
python test_crawl_cve.py check_fix <commit_id> [repo_version] [cve_id]
```

## 缓存数据库说明

### 数据库位置

缓存数据库默认位于项目根目录：`commit_cache.db`

### 数据库结构

```sql
CREATE TABLE commits (
    id INTEGER PRIMARY KEY,
    repo_version TEXT,
    commit_id TEXT,
    short_id TEXT,
    subject TEXT,
    commit_msg TEXT,
    author TEXT,
    timestamp INTEGER,
    modified_files TEXT,
    diff_code TEXT
);
```

### 缓存管理

#### 查看缓存状态

```bash
python test_crawl_cve.py repos
```

会显示每个仓库的缓存状态和commit数量。

#### 重建缓存

如果需要更新缓存（比如仓库有新的commits）：

```bash
# 删除旧缓存
rm commit_cache.db

# 重新构建
python test_crawl_cve.py build-cache 5.10-hulk 10000
```

#### 缓存大小控制

通过 `max_commits` 参数控制缓存大小：

```bash
# 缓存最近5000个commits（适合快速测试）
python test_crawl_cve.py build-cache 5.10-hulk 5000

# 缓存最近20000个commits（适合生产环境）
python test_crawl_cve.py build-cache 5.10-hulk 20000
```

## 常见问题

### Q1: 为什么必须构建缓存？

**A**: 为了确保测试结果的准确性：
- 避免假的"找到匹配"的结果
- 提供真实的搜索性能
- 支持复杂的搜索策略（全文搜索、相似度计算等）

### Q2: 如果不构建缓存会怎样？

**A**: 系统会提示你构建缓存，并提供选项：
```
⚠️  警告: 缓存数据库不存在或无数据
建议先构建缓存以提高搜索效率

是否现在为 5.10-hulk 构建缓存? (y/n):
```

你可以选择：
- 输入 `y`: 立即构建缓存
- 输入 `n`: 跳过，直接使用git命令（会很慢）

### Q3: 缓存构建需要多长时间？

**A**: 取决于commits数量和仓库大小：
- 1000个commits: 约10-30秒
- 10000个commits: 约1-3分钟
- 20000个commits: 约2-5分钟

### Q4: 搜索时没有找到commit怎么办？

**A**: 可能的原因：
1. **Commit不存在**: 该commit确实不在目标仓库中
2. **缓存范围不够**: 增加 `max_commits` 重新构建缓存
3. **Subject格式不同**: 查看输出的相似度分数，调整搜索策略
4. **Commit ID被修改**: Cherry-pick时commit ID会变化，需要基于subject搜索

建议的调试步骤：
```bash
# 1. 检查缓存状态
python test_crawl_cve.py repos

# 2. 如果缓存commits数量太少，重建缓存
python test_crawl_cve.py build-cache 5.10-hulk 20000

# 3. 查看详细搜索过程和相似度
python test_crawl_cve.py search_introduced <commit_id> 5.10-hulk
```

### Q5: 如何提高搜索准确性？

**A**: 
1. **增加缓存范围**: 构建更多commits到缓存
2. **使用完整commit ID**: 而不是短commit ID
3. **检查commit message格式**: 确保理解backport的命名规则
4. **调整相似度阈值**: 在代码中修改 `calculate_subject_similarity` 的阈值

## 搜索策略详解

### 精确ID匹配 (策略1)

最可靠的匹配方式，直接查找相同的commit ID。

```python
# 在缓存或Git仓库中查找
exact_match = manager.find_commit_by_id(commit_id, repo_version)
```

### Subject模糊匹配 (策略2)

基于commit message的词袋模型计算相似度：

```python
def calculate_subject_similarity(s1: str, s2: str) -> float:
    # 提取有意义的词（长度>3）
    words1 = set(w for w in s1.split() if len(w) > 3)
    words2 = set(w for w in s2.split() if len(w) > 3)
    
    # Jaccard相似度
    intersection = words1 & words2
    union = words1 | words2
    return len(intersection) / len(union)
```

相似度阈值：
- `> 0.8`: 高相似度，很可能是同一个patch
- `0.5 - 0.8`: 中等相似度，可能相关
- `< 0.5`: 低相似度，不太相关

### 文件匹配 (策略3)

查找修改相同文件的commits，适合作为辅助判断。

### Fixes标签匹配 (策略4)

针对修复补丁，查找包含 `Fixes: <commit_id>` 标签的commits。

## 示例工作流

### 完整的CVE分析工作流

```bash
# 1. 配置环境
cp config.example.yaml config.yaml
vim config.yaml  # 配置仓库路径

# 2. 查看配置
python test_crawl_cve.py repos

# 3. 构建缓存（首次使用）
python test_crawl_cve.py build-cache 5.10-hulk 10000

# 4. 获取CVE信息（测试mainline识别）
python test_crawl_cve.py CVE-2024-26633

# 5. 查找引入commit是否在自维护仓库
python test_crawl_cve.py search_introduced abc123def456 5.10-hulk

# 6. 检查修复是否已合入
python test_crawl_cve.py check_fix xyz789abc012 5.10-hulk CVE-2024-26633
```

## 性能优化建议

1. **首次使用构建足够的缓存**: 建议至少10000个commits
2. **定期更新缓存**: 当仓库有新commits时
3. **使用SSD存储**: 缓存数据库会频繁读写
4. **调整max_commits**: 根据实际需求平衡速度和覆盖率

## 与旧版本的区别

### 旧版本（已移除）
- ❌ 包含假数据和模拟结果
- ❌ "找到匹配"的结果是假的
- ❌ 没有真实的搜索逻辑
- ❌ 容易误导用户

### 新版本（当前）
- ✅ 基于真实的Git仓库
- ✅ 需要先构建缓存
- ✅ 真实的搜索和匹配
- ✅ 明确的错误提示和建议

## 总结

**关键点**:
1. 必须先配置 `config.yaml`
2. 必须先构建缓存数据库
3. 所有搜索结果都是真实的
4. 没有假数据和模拟结果

**推荐流程**:
```
配置仓库 → 构建缓存 → 运行测试 → 分析结果
```
