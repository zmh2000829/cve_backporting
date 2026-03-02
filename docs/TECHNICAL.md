# 技术文档

## 系统架构

```
                    Pipeline (编排器)
                         │
    ┌────────────┬───────┴───────┬────────────┐
    ▼            ▼               ▼            ▼
 Crawler     Analysis       Dependency     DryRun
  Agent       Agent           Agent        Agent
    │            │               │            │
    ▼            ▼               ▼            ▼
 MITRE API   GitRepoManager  GitRepoManager  git apply
 Google Git  CommitMatcher   DependencyGraph  --check
```

### 数据流

1. **Pipeline.analyze(cve_id, target_version)** 启动分析
2. **Crawler** 从外部API获取 CveInfo + PatchInfo
3. **Analysis** 在目标仓库执行三级搜索，返回 SearchResult
4. **Dependency** 分析未合入补丁的前置依赖
5. **DryRun** 试应用补丁检测冲突

---

## core/ 基础设施

### models.py — 数据模型

| 类 | 用途 |
|---|------|
| `CveInfo` | CVE元数据：ID、描述、severity、fix/introduced commits、版本映射 |
| `PatchInfo` | 补丁内容：subject、commit_msg、diff_code、modified_files |
| `GitCommit` | Git commit记录（简化） |
| `CommitInfo` | 匹配用commit详情（含diff、函数列表） |
| `MatchResult` | 匹配结果：target_commit、confidence、match_type |
| `SearchResult` | 搜索结果：found、strategy、candidates |
| `DryRunResult` | 试应用结果：applies_cleanly、conflicting_files |
| `AnalysisResult` | 完整分析结果（聚合以上所有） |

### git_manager.py — Git仓库管理

**千万级commit优化：**
- `git merge-base --is-ancestor` 替代 `git branch --contains`（毫秒级 vs 分钟级）
- `\x1e`/`\x1f` 作为字段/记录分隔符，避免commit message中的`|`冲突
- SQLite + FTS5 全文索引加速subject搜索
- 批量缓存构建：WAL模式 + 5000条批写入

**关键API：**
```python
find_commit_by_id(commit_id, repo_version)   # Level 1
search_by_subject(subject, repo_version)      # Level 2
search_by_keywords(keywords, repo_version)    # Level 2
search_by_files(files, repo_version)          # Level 3 / Dependency
get_commit_diff(commit_id, repo_version)      # Level 3
build_commit_cache(repo_version, max_commits) # 缓存构建
```

### matcher.py — 相似度、包含度与路径映射算法

| 函数/类 | 算法 | 用途 |
|---------|------|------|
| `PathMapper` | 前缀替换 (双向) | 跨版本路径翻译 |
| `subject_similarity` | SequenceMatcher (标准化后) | Level 2 匹配 |
| `diff_similarity` | SequenceMatcher (仅+/-行) | Level 3 双向相似度 |
| `diff_containment` | Multiset 包含度 (单向) | Level 3 包含关系检测 |
| `file_similarity` | Jaccard + PathMapper 规范化 | 过滤 + 评分 |
| `normalize_subject` | 去除[backport]等前缀 | 预处理 |
| `extract_keywords` | 去停用词 + 截断 | 关键词搜索 |
| `extract_hunks_from_diff` | 解析 `@@` 行号范围 | 依赖分析 hunk 级重叠 |
| `compute_hunk_overlap` | 行范围相交/相邻检测 | 依赖分析分级 |

#### PathMapper — 跨版本路径映射

**设计背景：** Linux 内核在版本演进中会重组子系统目录结构。例如 6.2 将 `fs/cifs/` 迁移为 `fs/smb/client/`。当社区补丁修改 `fs/smb/client/file.c` 时，5.10 仓库中的对应文件是 `fs/cifs/file.c`，若不做路径翻译，L3 的 `search_by_files` 和 `file_similarity` 都会找不到匹配。

**工作原理：**

```
社区补丁 (mainline 7.x)              本地仓库 (5.10)
fs/smb/client/connect.c    ──映射──►  fs/cifs/connect.c
fs/smb/server/smb2pdu.c    ──映射──►  fs/ksmbd/smb2pdu.c
drivers/gpu/drm/i915/      ──映射──►  drivers/gpu/drm/i915/
  display/intel_dp.c                    intel_dp.c
```

**关键方法：**

| 方法 | 作用 | 调用位置 |
|------|------|---------|
| `translate(path)` | 返回路径的所有等价形式（含原始） | 内部使用 |
| `expand_files(files)` | 扩展文件列表，加入所有映射路径 | L3 搜索 / 依赖分析前 |
| `normalize_for_compare(path)` | 统一规范到 upstream 形式 | `file_similarity` 比较时 |

**内置默认映射规则：**

| 高版本路径 (upstream) | 低版本路径 (local) | 起始版本 |
|----------------------|-------------------|---------|
| `fs/smb/client/` | `fs/cifs/` | 6.2 |
| `fs/smb/server/` | `fs/ksmbd/` | 6.2 |
| `fs/smb/common/` | `fs/smbfs_common/` | 6.2 |
| `drivers/gpu/drm/amd/display/dc/link/` | `drivers/gpu/drm/amd/display/dc/core/` | 6.2 |
| `drivers/gpu/drm/i915/display/` | `drivers/gpu/drm/i915/` | 5.18 |
| `drivers/net/wireless/realtek/rtw89/` | `drivers/staging/rtw89/` | 5.16 |
| `drivers/net/wireless/ath/ath12k/` | `drivers/staging/ath12k/` | 6.5 |
| `fs/netfs/` | `fs/fscache/` | 6.1 |

映射规则可通过 `config.yaml` 的 `path_mappings` 字段自定义或覆盖（见 `config.yaml.example`）。

#### diff_containment — 包含度算法

**设计背景：** 自维护内核仓库常见操作是将社区多个 patch 合并（squash）为一个 commit 提交。此时社区补丁的改动被完整**包含**在一个更大的本地 commit 中，双向相似度（`diff_similarity`）会因为分母包含大量无关行而显著偏低，但实际上该补丁已经被合入。

**算法原理：**

```
Source (社区补丁)       Target (本地commit)
┌──────────────┐       ┌──────────────────────┐
│ +line_a      │       │ +unrelated_change_1  │
│ +line_b      │  ───▶ │ +line_a   ✓ matched  │
│ -line_c      │       │ +line_b   ✓ matched  │
│              │       │ -line_c   ✓ matched  │
│              │       │ +unrelated_change_2  │
│              │       │ -unrelated_change_3  │
└──────────────┘       └──────────────────────┘
  3 lines total          3/3 matched → 包含度 100%
                         diff_similarity 仅 ~40%
```

**实现步骤：**

1. **提取变更行**：分别从 source 和 target diff 中提取 `+` 行（added）和 `-` 行（removed），去掉前缀，过滤 `len < 4` 的噪声行（`}`、`{`、`return;` 等）
2. **分类匹配**：added 只与 added 匹配，removed 只与 removed 匹配，保证语义正确
3. **Multiset 计数**：使用 `Counter` 作为多重集合，每条 target 行只能匹配一次，避免重复计数
4. **计算包含度**：`containment = matched_count / total_source_lines`

**适用场景区分（`use_containment` 参数）：**

包含度检测**仅在引入 commit 搜索时启用**，修复 commit 搜索仅使用双向相似度：

| 搜索场景 | `use_containment` | L3 策略 | 原因 |
|----------|-------------------|---------|------|
| 引入 commit 搜索 | `True` | 包含度优先 | 本地仓库常将社区多 patch squash 为一个 commit |
| 修复 commit 搜索 | `False` | 仅双向相似度 | 修复补丁优先通过 L2 subject_match 定位 |
| stable backport 搜索 | `False` | 仅双向相似度 | backport 通常有明确 subject |
| check-intro 命令 | `True` | 包含度优先 | 判断引入代码是否存在 |

**`use_containment=True` 时的得分策略：**

`match_by_diff` 同时计算两个指标，取最优：

| 条件 | 选择的策略 | 综合得分公式 |
|------|-----------|-------------|
| `containment ≥ similarity` | `diff_containment` | `file_sim × 0.3 + containment × 0.7` |
| `containment < similarity` | `diff_similarity` | `file_sim × 0.4 + similarity × 0.6` |

包含度策略下 `file_sim` 权重降低（0.3 vs 0.4），因为 squash commit 修改的文件通常多于社区原始补丁。

**`use_containment=False` 时（修复搜索）：**

仅计算 `diff_similarity`，得分 = `file_sim × 0.4 + similarity × 0.6`，不计算包含度。

**典型场景对比：**

| 场景 | diff_similarity | diff_containment | 最终结果 |
|------|----------------|-----------------|---------|
| 社区补丁被 squash 到大 commit | 低 (~30%) | 高 (~95%) | 命中 (containment, 仅引入搜索) |
| 1:1 对应的 backport | 高 (~92%) | 高 (~95%) | 命中 (两种模式均可) |
| 改了同文件但不相关 | 低 (~10%) | 低 (~5%) | 不命中 |
| 部分 cherry-pick | 中 (~50%) | 中 (~60%) | 视阈值而定 |

**CommitMatcher.match_comprehensive 流程：**
1. ID精确比较 → confidence=1.0
2. Subject相似度 ≥ 0.95 → 直接返回
3. Diff匹配（受 `use_containment` 控制）≥ 0.70
4. 合并去重，按confidence降序

---

## agents/ 核心Agent

### Crawler Agent (`agents/crawler.py`)

**CVE 数据源：**
- MITRE CVE API: `https://cveawg.mitre.org/api/cve/{CVE_ID}`

**Mainline识别逻辑：**
1. `affected[].versions[]` 中 `versionType="git"` 的条目提取 fix commits
2. `versionType="original_commit_for_fix"` 标识 mainline 版本号
3. git commits 与 semver versions 一一映射
4. 匹配 mainline 版本号的 commit 即为 mainline fix

**Patch获取（三级回退，使用完整 40 位 commit ID）：**

| 优先级 | 数据源 | 方式 | 特点 |
|--------|--------|------|------|
| 1 | `git.kernel.org` | `/patch/?id={commit}` (format-patch) | 单请求获取全部信息，0.1-0.3s，最可靠 |
| 2 | `kernel.googlesource.com` | JSON 元数据 + TEXT diff (两次请求) | 含 3 次重试，间歇 502/500 |
| 3 | 本地 git 仓库 | `git show` / `git log` | commit 需存在于对象库中 |

- `git.kernel.org` 返回标准 `git format-patch` 输出，一次请求包含 From / Subject / Author / Date / commit message / diff
- 多个源的部分结果通过 `_merge_patch` 互补合并（如一个源拿到 subject，另一个拿到 diff）
- 同时尝试 stable tree 和 torvalds tree，覆盖 mainline 与 stable backport 两种场景

### Analysis Agent (`agents/analysis.py`)

**三级搜索：**

| Level | 策略 | 条件 | 置信度 |
|-------|------|------|--------|
| L1 | Commit ID精确匹配 | `git cat-file -t` + `git merge-base --is-ancestor` | 100% |
| L2 | Subject语义匹配 | `git log --grep` + SequenceMatcher ≥ 85% | 85-100% |
| L3 | Code Diff匹配 | `git log -- <files>` + diff score ≥ 70% | 70-100% |

L2 两阶段搜索：先精确subject，再关键词OR搜索。

L3 策略因搜索场景不同而异：
- **引入 commit 搜索**：启用包含度检测（`use_containment=True`），适配 squash 场景
- **修复 commit 搜索**：仅用双向相似度，优先依赖 L2 subject_match

### Dependency Agent (`agents/dependency.py`)

**分析流程：**
1. 提取 `Fixes:` 标签引用的 commit，加入排除列表
2. 根据引入 commit 时间戳确定时间窗口（`after_ts`），只分析引入后的 commit
3. `search_by_files` 搜索修改同文件的 commit（排除 merge commits）
4. 对每个候选 commit 执行 hunk 级重叠分析：
   - 提取 fix patch 和候选 commit 的 hunk 列表（文件 + 行范围）
   - 计算直接重叠（行范围相交）和相邻重叠（margin=50 行内）
   - 计算函数级重叠
5. 综合评分与分级：

| 等级 | 条件 | 含义 |
|------|------|------|
| 强 (strong) | 直接 hunk 重叠 ≥ 1 | 修改了相同代码行，几乎必须先合入 |
| 中 (medium) | 相邻 hunk 重叠 ≥ 1 或函数重叠 ≥ 1 | 修改了相邻区域，可能产生冲突 |
| 弱 (weak) | 仅文件级重叠 | 修改了同文件的不同区域 |

### DryRun Agent (`agents/dryrun.py`)

**流程：**
1. 从PatchInfo提取纯diff部分，写入临时文件
2. `git apply --stat` 获取修改统计
3. `git apply --check` 检测能否干净应用
4. 若失败，解析stderr提取冲突文件列表
5. 可选 `git apply --check --3way` 尝试3-way merge

**冲突解析模式：**
- `error: patch failed: <file>:<line>`
- `error: <file>: does not exist in index`

---

## Pipeline 编排

```
Step 1: Crawler.fetch_cve + fetch_patch
Step 2: Analysis.search (引入commit)
Step 3: Analysis.search (修复commit)
       └─ 若已合入 → 结束
       └─ 尝试 5.10 stable backport
Step 4: Dependency.analyze (前置依赖)
Step 5: DryRun.check (试应用)
       └─ 若失败 → DryRun.check_with_3way
```

---

## 已验证测试用例

| CVE | 状态 | 验证点 |
|-----|------|--------|
| CVE-2024-26633 | 已修复 | L1找到引入commit, L2找到修复backport |
| CVE-2025-40198 | N/A | Mainline识别准确性 (7个版本映射全部正确) |
| CVE-2024-50154 | 已修复 | L1引入 + L2修复 + DryRun冲突检测 |

## 已知限制

1. Diff匹配(L3)需要逐commit获取diff，大量候选时较慢
2. 依赖分析基于文件/函数重叠，无法捕获数据结构变更等间接依赖
3. DryRun只检测形式冲突，不检测语义冲突（编译/逻辑错误）
4. MITRE API对部分老旧CVE可能缺少structured affected数据
