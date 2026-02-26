# 技术文档

## 1. 系统架构

```
                  ┌─────────────────────────────────┐
                  │       BackportAnalyzer           │
                  │    (enhanced_cve_analyzer.py)    │
                  │                                  │
                  │  analyze(cve_id, target_version) │
                  └──────┬──────────────┬────────────┘
                         │              │
              ┌──────────▼──┐    ┌──────▼──────────┐
              │  CveFetcher │    │  GitRepoManager  │
              │ (crawl_cve_ │    │ (git_repo_       │
              │  patch.py)  │    │  manager.py)     │
              └──────┬──────┘    └──────┬───────────┘
                     │                  │
        ┌────────────▼───┐    ┌────────▼─────────┐
        │  MITRE CVE API │    │  本地 Git 仓库    │
        │  Googlesource  │    │  SQLite 缓存      │
        └────────────────┘    └──────────────────┘

              ┌─────────────────────────┐
              │   CommitMatcher /       │
              │   DependencyAnalyzer    │
              │ (enhanced_patch_        │
              │  matcher.py)            │
              └─────────────────────────┘
```

数据流：`MITRE API` → `CveFetcher` → `BackportAnalyzer` → `GitRepoManager` → 分析结果

## 2. 模块详解

### 2.1 CveFetcher (`crawl_cve_patch.py`)

负责从外部数据源获取 CVE 漏洞信息和补丁内容。

#### 数据结构

```python
@dataclass
class CveInfo:
    cve_id: str
    description: str
    severity: str
    introduced_commits: List[Dict]       # 漏洞引入 commits
    fix_commits: List[Dict]              # 修复 commits
    mainline_fix_commit: str             # mainline 修复 commit ID
    mainline_version: str                # mainline 对应版本号
    version_commit_mapping: Dict[str, str]  # {版本号: commit_id}

@dataclass
class PatchInfo:
    commit_id: str
    subject: str
    commit_msg: str
    author: str
    diff_code: str
    modified_files: List[str]
```

#### CVE 数据解析逻辑

MITRE CVE API (`https://cveawg.mitre.org/api/cve/{CVE_ID}`) 返回的数据中，关键字段位于 `containers.cna`：

1. **references** — 包含补丁链接，通过 URL 正则提取 commit ID
2. **affected** — 包含两类 product 条目：
   - `versionType: "git"` → `version` 是**引入 commit**，`lessThan` 是**修复 commit**
   - `versionType: "semver"` / `"original_commit_for_fix"` → 版本号

映射建立算法：
```
git_commits = [每个 git 版本的 lessThan]    # 按顺序
semver_versions = [每个 semver 的 version]  # 按顺序
if len(git_commits) == len(semver_versions):
    mapping = dict(zip(semver_versions, git_commits))
```

`versionType == "original_commit_for_fix"` 标记的版本即为 **mainline 版本**，其对应的 git commit 即为 **mainline fix commit**。

#### Patch 获取

使用 Google Kernel 镜像的两个端点：

| 端点 | 格式 | 内容 |
|------|------|------|
| `/+/{commit}?format=JSON` | JSON（去掉 `)]}'` 前缀） | subject, author, date, tree_diff |
| `/+/{commit}^!?format=TEXT` | Base64 编码的 unified diff | 完整 diff 内容 |

两步获取：先 JSON 拿元数据，再 TEXT 拿 diff，合并为 `PatchInfo`。

### 2.2 GitRepoManager (`git_repo_manager.py`)

负责本地 Git 仓库的高效查询，针对千万级 commit 做了专门优化。

#### 性能关键决策

| 操作 | 旧方案 | 新方案 | 提速 |
|------|--------|--------|------|
| 判断 commit 是否在分支上 | `git branch --contains` O(n) | `git merge-base --is-ancestor` O(1) | ~1000x |
| commit 日志解析分隔符 | `\|`（与 body 冲突） | `\x1e` / `\x1f`（ASCII 控制字符） | 正确性修复 |
| 缓存写入 | 逐条 INSERT | 批量 INSERT + WAL 模式 | ~10x |

#### 分支感知查询

所有查询方法（`find_commit_by_id`, `search_by_subject`, `search_by_keywords`, `search_by_files`）都自动限定在配置的分支上，避免查到其他分支的 commit。

```python
# find_commit_by_id 的完整流程：
1. 查 SQLite 缓存（按 short_id 索引）
2. git cat-file -t {commit}          # 验证 commit 存在
3. git merge-base --is-ancestor {commit} {branch}  # 验证在目标分支上
4. git log -1 --format=... {commit}  # 获取详细信息
```

#### SQLite 缓存架构

```sql
CREATE TABLE commits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_version TEXT NOT NULL,
    commit_id TEXT NOT NULL,
    short_id TEXT NOT NULL,        -- commit_id[:12]，用于快速匹配
    subject TEXT NOT NULL,
    author TEXT,
    timestamp INTEGER,
    UNIQUE(repo_version, commit_id)
);

-- 索引
CREATE INDEX idx_short_id ON commits(repo_version, short_id);
CREATE INDEX idx_subject ON commits(repo_version, subject);
CREATE INDEX idx_timestamp ON commits(repo_version, timestamp);

-- FTS5 全文搜索（如果 SQLite 支持）
CREATE VIRTUAL TABLE commits_fts USING fts5(commit_id, subject, ...);
```

缓存构建使用 `PRAGMA journal_mode=WAL` 和 `PRAGMA synchronous=NORMAL` 加速批量写入。

### 2.3 CommitMatcher / DependencyAnalyzer (`enhanced_patch_matcher.py`)

#### 三级搜索算法

```
Level 1: ID 精确匹配
  ├── 查缓存 (short_id 索引)
  └── git cat-file + merge-base --is-ancestor
  置信度: 1.0

Level 2: Subject 语义匹配
  ├── 标准化 subject（移除 [backport] 前缀、小写化）
  ├── 精确 subject 搜索（git log --grep --fixed-strings）
  ├── 关键词搜索（git log --grep --extended-regexp）
  └── SequenceMatcher 计算相似度
  阈值: ≥ 0.85

Level 3: Diff 代码匹配
  ├── 搜索修改相同文件的 commits
  ├── 获取每个候选的 diff
  ├── 文件相似度 (Jaccard, 权重 0.4) + diff 相似度 (SequenceMatcher, 权重 0.6)
  └── 综合评分
  阈值: ≥ 0.70
```

#### 相似度算法

**Subject 相似度：**
```python
normalize(s) = lowercase → remove_backport_prefix → strip_special_chars
similarity = SequenceMatcher(None, normalize(s1), normalize(s2)).ratio()
```

**Diff 相似度：**
```python
# 只比较实际修改的代码行（以 + 或 - 开头，去掉 +++ / ---）
changes = [line[1:].strip() for line in diff if line starts with +/-]
similarity = SequenceMatcher(None, changes1, changes2).ratio()
```

**文件列表相似度（Jaccard）：**
```python
# 只比较文件名（不含路径），应对重构导致的路径变化
names = {path.split('/')[-1] for path in files}
similarity = |A ∩ B| / |A ∪ B|
```

#### 依赖分析

`DependencyAnalyzer` 基于文件/函数重叠度评估依赖强度：

```
dependency_score = file_overlap * 0.6 + function_overlap * 0.4
```

支持拓扑排序确定合入顺序，检测循环依赖。

### 2.4 BackportAnalyzer (`enhanced_cve_analyzer.py`)

端到端分析主流程：

```
Step 1: fetch_cve(cve_id)
    → CveInfo (mainline_fix, introduced, version_mapping)

Step 2: fetch_patch(fix_commit_id)
    → PatchInfo (subject, diff, files)

Step 3: _search_commit(introduced_commit, ...)
    → SearchResult (判断目标仓库是否包含漏洞引入代码)

Step 4: _search_commit(fix_commit, ...)
    → SearchResult (判断修复补丁是否已合入)

Step 5: 检查 stable backport (5.10.x 版本的 commit)
    → 如果 mainline 未命中，尝试匹配 stable 版本

Step 6: _analyze_prerequisites(...)
    → 分析修改同文件的中间 commits
    → 提取 Fixes: 标签引用
    → 生成前置依赖补丁列表
```

#### 输出数据结构

```python
@dataclass
class AnalysisResult:
    cve_id: str
    target_version: str
    cve_info: CveInfo              # CVE 元数据
    fix_patch: PatchInfo           # 修复补丁内容
    introduced_search: SearchResult # 引入 commit 搜索结果
    fix_search: SearchResult       # 修复 commit 搜索结果
    is_vulnerable: bool            # 目标仓库是否受影响
    is_fixed: bool                 # 修复补丁是否已合入
    prerequisite_patches: List[Dict]  # 前置依赖补丁
    conflict_files: List[str]      # 可能冲突的文件
    recommendations: List[str]     # 建议操作
```

## 3. 外部接口

### MITRE CVE API

- 端点：`GET https://cveawg.mitre.org/api/cve/{CVE_ID}`
- 返回：JSON，包含 `containers.cna.affected`、`containers.cna.references` 等
- 无需认证，有 rate limit

### Google Kernel 镜像

- 仓库地址：`https://kernel.googlesource.com/pub/scm/linux/kernel/git/stable/linux`
- Commit 元数据：`/+/{commit}?format=JSON`（注意去掉 `)]}'` 前缀）
- Commit Diff：`/+/{commit}^!?format=TEXT`（Base64 编码）
- 无需认证

## 4. 已验证的 CVE 测试用例

| CVE | 场景 | 验证结果 |
|-----|------|----------|
| CVE-2024-26633 | 已修复；introduced 在 5.10.y 上 | L1 找到 introduced (exact_id)，L2 找到 fix (subject 100%) |
| CVE-2024-50257 | 未修复；无 5.10 backport | 三级搜索均未命中，列出 10 个前置依赖 |
| CVE-2025-40198 | Mainline 识别 | 4/4 全通过，7/7 版本映射正确 |
| CVE-2024-53104 | Introduced commit 提取 | 正确从 affected 字段提取 `c0efd232929c` |

## 5. 已知限制

1. **网络依赖** — CVE 获取和 patch 下载需要访问外网（MITRE API + googlesource）
2. **Diff 匹配性能** — Level 3 需要逐个获取候选 commit 的 diff，对大量候选较慢
3. **引入 commit 判断** — 部分 CVE 的 affected 字段没有引入 commit 信息
4. **前置依赖精度** — 基于文件重叠的依赖分析是粗粒度的，复杂情况需人工review
5. **缓存一致性** — 如果仓库有新 commit 推入，需重建缓存
