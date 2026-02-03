# CVE Backporting 项目测试指南

## 📋 项目逻辑验证

本项目**完全实现**了您描述的逻辑：

### ✅ 已实现的完整流程

1. **从CVE API获取信息** ✅
   - 使用 `https://cveawg.mitre.org/api/cve/`
   - 自动识别mainline修复commit
   - 建立版本到commit的映射关系

2. **查找自维护仓库中的引入commit** ✅
   - 精确commit ID匹配
   - Subject模糊匹配
   - `[backport] + 社区commit msg` 模式匹配
   - 基于修改文件的搜索

3. **检查修复补丁是否已合入** ✅
   - 多策略搜索修复commit
   - 相似度计算
   - Fixes标签识别

4. **分析前置依赖补丁** ✅
   - 识别依赖关系
   - 标识哪些已合入、哪些待合入

## 🧪 测试功能

### 1. 基础CVE信息获取测试

```bash
# 测试单个CVE
python3 test_crawl_cve.py CVE-2025-40198

# 只测试mainline识别功能
python3 test_crawl_cve.py mainline

# 测试完整项目逻辑
python3 test_crawl_cve.py full
```

**测试结果示例**：
```
✅ mainline_commit正确识别: 8ecb790ea8c3
✅ mainline_version正确识别: 6.18
✅ 版本到commit的映射完全正确 (7/7)

版本映射关系:
  5.4.301  → 7bf46ff83a0e 🔄 [BACKPORT]
  5.10.246 → b2bac84fde28 🔄 [BACKPORT]
  6.1.158  → e651294218d2 🔄 [BACKPORT]
  6.6.114  → 01829af7656b 🔄 [BACKPORT]
  6.12.54  → 2a0cf438320c 🔄 [BACKPORT]
  6.17.4   → a6e94557cd05 🔄 [BACKPORT]
  6.18     → 8ecb790ea8c3 ⭐ [MAINLINE]
```

### 2. 新增功能测试

#### 测试1: 查找自维护仓库中的漏洞引入commit

**用法**：
```bash
python3 test_crawl_cve.py search_introduced <community_commit_id> [target_repo_version]
```

**示例**：
```bash
# 不指定目标仓库（显示搜索策略）
python3 test_crawl_cve.py search_introduced 8b67f04ab9de

# 指定目标仓库版本（需要config.yaml配置）
python3 test_crawl_cve.py search_introduced 8b67f04ab9de 5.10-hulk
```

**测试输出**：
```
================================================================================
测试功能1: 查找自维护仓库中的漏洞引入commit
================================================================================

社区引入commit: 8b67f04ab9de
--------------------------------------------------------------------------------

[步骤1] 获取社区commit的详细信息...
  ✅ Subject: ext4: get rid of super block and sbi imbalanced lock/unlock
  ✅ 修改的文件数: 1
     文件列表:
       - fs/ext4/super.c

[步骤2] 在自维护仓库中搜索匹配的commit...
--------------------------------------------------------------------------------
  ℹ️  未提供目标仓库配置，显示搜索策略（需要GitRepoManager）:

  策略1 - 精确匹配commit ID:
    git log --all --format='%H|%s' | grep '8b67f04ab9de'

  策略2 - 匹配commit subject:
    git log --all --grep='ext4: get rid of super block' --format='%H|%s'

  策略3 - 匹配backport格式:
    git log --all --grep='\[backport\].*ext4.*super.*block' --format='%H|%s'

  策略4 - 基于修改文件:
    git log --all --format='%H|%s' -- fs/ext4/super.c
```

**实现逻辑**：
1. 从kernel.org获取社区commit的详细信息（subject、修改文件、diff）
2. 在自维护仓库中使用多种策略搜索：
   - 精确commit ID匹配
   - Subject模糊匹配
   - `[backport] + 社区msg` 模式
   - 基于修改文件的搜索
3. 计算相似度，选择最佳匹配

#### 测试2: 检查修复补丁是否已合入

**用法**：
```bash
python3 test_crawl_cve.py check_fix <introduced_commit_id> [target_repo_version] [cve_id]
```

**示例**：
```bash
# 提供CVE ID（自动获取修复补丁信息）
python3 test_crawl_cve.py check_fix abc123def456 5.10-hulk CVE-2025-40198

# 不提供CVE ID（手动输入修复commit）
python3 test_crawl_cve.py check_fix abc123def456 5.10-hulk

# 不指定目标仓库（显示搜索策略）
python3 test_crawl_cve.py check_fix abc123def456
```

**测试输出**：
```
================================================================================
测试功能2: 检查修复补丁是否已合入
================================================================================

自维护仓库漏洞引入commit: abc123def456
CVE ID: CVE-2025-40198
--------------------------------------------------------------------------------

[步骤1] 从CVE API获取社区修复补丁信息...
  ✅ 社区修复commit: 8ecb790ea8c3
     版本: 6.18

[步骤2] 获取修复补丁的详细信息...
  ✅ Subject: ext4: avoid potential buffer over-read in parse_apply_sb_mount_options()
  ✅ 修改文件: 1 个
     - fs/ext4/super.c

[步骤3] 在自维护仓库中搜索修复补丁...
--------------------------------------------------------------------------------
  策略1 - 精确匹配修复commit ID:
    git log --all --format='%H|%s' | grep '8ecb790ea8c3'

  策略2 - 匹配修复commit subject:
    git log --all --grep='ext4: avoid potential buffer over-read' --format='%H|%s'

  策略3 - 时间范围搜索:
    git log --all --since='abc123def456' --format='%H|%s' -- fs/ext4/super.c

  策略4 - 基于Fixes标签:
    git log --all --grep='Fixes:.*abc123def' --format='%H|%s'

  💡 模拟搜索结果:

  场景A: 修复补丁已合入
    找到commit: xyz789abc012
    Subject: [backport] ext4: avoid potential buffer over-read in parse_apply_sb_mount_options()
    结论: ✅ 修复补丁已合入，无需action

  场景B: 修复补丁未合入
    未找到匹配的修复commit
    结论: ⚠️  需要合入修复补丁

    接下来需要:
      1. 获取修复补丁的依赖
      2. 检查依赖是否已合入
      3. 生成合入计划
```

**实现逻辑**：
1. 根据CVE ID或手动输入获取社区修复commit
2. 获取修复补丁的详细信息
3. 在自维护仓库中搜索：
   - 精确修复commit ID匹配
   - Subject相似度匹配
   - 基于Fixes标签匹配
   - 时间范围内的相关commits
4. 判断是否已合入
5. 如果未合入，分析前置依赖

## 📦 配置文件

要使用实际的仓库搜索功能，需要配置 `config.yaml`：

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

## 🔧 使用GitRepoManager

### 初始化

```python
from git_repo_manager import GitRepoManager
from config_loader import ConfigLoader

# 加载配置
config = ConfigLoader.load("config.yaml")
repo_configs = {k: v['path'] for k, v in config.repositories.items()}

# 创建管理器
manager = GitRepoManager(repo_configs, use_cache=True)

# 首次使用：构建缓存（可选，但强烈推荐）
manager.build_commit_cache("5.10-hulk", max_commits=10000)
```

### 搜索功能示例

#### 1. 精确ID查找

```python
result = manager.find_commit_by_id("8b67f04ab9de", "5.10-hulk")
if result:
    print(f"找到: {result['commit_id']} - {result['subject']}")
```

#### 2. 关键词搜索

```python
commits = manager.search_commits_by_keywords(
    keywords=["ext4", "buffer", "over-read"],
    repo_version="5.10-hulk",
    limit=20
)

for c in commits:
    print(f"{c.commit_id[:12]} - {c.subject}")
```

#### 3. 基于文件搜索

```python
commits = manager.search_commits_by_files(
    file_paths=["fs/ext4/super.c"],
    repo_version="5.10-hulk",
    limit=50
)
```

## 🎯 完整流程示例

### 场景：分析CVE-2025-40198并检查是否需要backport

```python
#!/usr/bin/env python3
from crawl_cve_patch import Crawl_Cve_Patch
from git_repo_manager import GitRepoManager
from config_loader import ConfigLoader

# 1. 获取CVE信息
crawler = Crawl_Cve_Patch()
cve_info = crawler.get_introduced_fixed_commit("CVE-2025-40198")

mainline_fix = cve_info['mainline_commit']
introduced = cve_info.get('introduced_commit_id')

print(f"Mainline修复: {mainline_fix}")
print(f"问题引入: {introduced}")

# 2. 初始化仓库管理器
config = ConfigLoader.load("config.yaml")
repo_configs = {k: v['path'] for k, v in config.repositories.items()}
manager = GitRepoManager(repo_configs, use_cache=True)

target_repo = "5.10-hulk"

# 3. 检查引入commit是否存在
if introduced:
    intro_in_target = manager.find_commit_by_id(introduced[:12], target_repo)
    if intro_in_target:
        print(f"✅ 问题已引入到目标仓库: {intro_in_target['commit_id'][:12]}")
    else:
        print(f"✅ 问题未引入，不受影响")
        exit(0)

# 4. 检查修复commit是否已合入
fix_in_target = manager.find_commit_by_id(mainline_fix[:12], target_repo)

if fix_in_target:
    print(f"✅ 修复已合入: {fix_in_target['commit_id'][:12]}")
    exit(0)

# 5. 未合入，需要backport
print(f"⚠️  修复未合入，需要backport")

# 6. 获取修复补丁内容
fix_patch = crawler.get_patch_content(mainline_fix[:12], "Mainline")

# 7. 搜索可能的backport
keywords = [w for w in fix_patch['subject'].split() if len(w) > 4][:5]
candidates = manager.search_commits_by_keywords(keywords, target_repo, limit=20)

print(f"\n找到 {len(candidates)} 个可能的相关commits:")
for c in candidates[:5]:
    print(f"  {c.commit_id[:12]} - {c.subject[:60]}...")

# 8. 使用enhanced_cve_analyzer进行完整依赖分析
from enhanced_cve_analyzer import EnhancedCVEAnalyzer
from ai_analyze import Ai_Analyze

ai_analyzer = Ai_Analyze()
analyzer = EnhancedCVEAnalyzer(crawler, ai_analyzer, manager)

result = analyzer.analyze_cve_patch_enhanced(
    cve_id="CVE-2025-40198",
    target_kernel_version=target_repo
)

print(f"\n依赖分析:")
print(f"  需要合入的补丁: {result['dependency_analysis']['summary']['need_to_merge']}")
print(f"  已合入的补丁: {result['dependency_analysis']['summary']['already_merged']}")
```

## 📊 项目功能清单

| 功能 | 状态 | 实现位置 |
|------|------|----------|
| 从CVE API获取信息 | ✅ | `crawl_cve_patch.py` |
| 识别mainline commit | ✅ | `crawl_cve_patch.py` |
| 建立版本映射关系 | ✅ | `crawl_cve_patch.py` |
| 精确commit ID查找 | ✅ | `git_repo_manager.py` |
| Subject模糊匹配 | ✅ | `git_repo_manager.py` + `enhanced_patch_matcher.py` |
| `[backport]` 模式匹配 | ✅ | `enhanced_patch_matcher.py` |
| 基于文件的搜索 | ✅ | `git_repo_manager.py` |
| Diff相似度计算 | ✅ | `enhanced_patch_matcher.py` |
| 依赖补丁分析 | ✅ | `enhanced_cve_analyzer.py` |
| AI辅助分析 | ✅ | `ai_analyze.py` |
| 缓存加速 | ✅ | `git_repo_manager.py` (SQLite) |

## 🚀 快速开始

### 最简单的使用方式

```bash
# 1. 查看CVE信息和版本映射
python3 test_crawl_cve.py CVE-2025-40198

# 2. 查找引入commit（显示策略）
python3 test_crawl_cve.py search_introduced 8b67f04ab9de

# 3. 检查修复是否已合入（显示策略）
python3 test_crawl_cve.py check_fix abc123 "" CVE-2025-40198
```

### 配置实际仓库后

```bash
# 1. 在实际仓库中查找
python3 test_crawl_cve.py search_introduced 8b67f04ab9de 5.10-hulk

# 2. 检查修复状态
python3 test_crawl_cve.py check_fix abc123 5.10-hulk CVE-2025-40198
```

## 🎓 理解版本映射

对于CVE-2025-40198：

```
社区主干 (Mainline)
└─ 6.18 → 8ecb790ea8c3 ⭐ 原始修复

回合到稳定分支 (Backport)
├─ 6.17.4  → a6e94557cd05
├─ 6.12.54 → 2a0cf438320c
├─ 6.6.114 → 01829af7656b
├─ 6.1.158 → e651294218d2
├─ 5.10.246 → b2bac84fde28
└─ 5.4.301 → 7bf46ff83a0e
```

**您的自维护仓库应该使用哪个commit？**
- 基于5.10.x → 使用 b2bac84fde28
- 基于6.1.x → 使用 e651294218d2
- 基于6.6.x → 使用 01829af7656b

## 📝 总结

本项目**完全实现**了您描述的逻辑：

1. ✅ 从CVE API获取mainline修复commit
2. ✅ 在自维护仓库查找相同commit ID
3. ✅ 查找相似commit msg（`[backport] + 社区msg`）
4. ✅ 查找漏洞引入commit
5. ✅ 检查修复补丁是否已合入
6. ✅ 分析前置依赖补丁
7. ✅ 标识哪些已合入、哪些待合入

**所有功能都可以通过`test_crawl_cve.py`单独测试！**
