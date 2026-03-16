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
| `SearchStep` | 搜索过程单级记录：level、status(hit/miss/skip)、detail、elapsed |
| `PrerequisitePatch` | 前置依赖补丁：commit_id、grade(strong/medium/weak)、score、overlap_hunks/funcs |
| `StrategyResult` | check-intro/fix 单级策略结果：level、found、confidence、candidates |
| `MultiStrategyResult` | 三级策略聚合结果：strategies、is_present、verdict |
| `DryRunResult` | 试应用结果：applies_cleanly、apply_method、conflict_hunks、adapted_patch |
| `AnalysisResult` | 完整分析结果（聚合以上所有） |

### git_manager.py — Git仓库管理

**千万级commit优化：**
- `git merge-base --is-ancestor` 替代 `git branch --contains`（毫秒级 vs 分钟级）
- `\x1e`/`\x1f` 作为字段/记录分隔符，避免commit message中的`|`冲突
- SQLite + FTS5 全文索引加速subject搜索
- 批量缓存构建：WAL模式 + 50000条批写入 + mmap 1GB

**关键API：**
```python
find_commit_by_id(commit_id, repo_version)   # Level 1
search_by_subject(subject, repo_version)      # Level 2
search_by_keywords(keywords, repo_version)    # Level 2
search_by_files(files, repo_version)          # Level 3 / Dependency
get_commit_diff(commit_id, repo_version)      # Level 3
build_commit_cache(repo_version, max_commits, incremental) # 缓存构建
get_latest_cached_commit(repo_version)        # 获取缓存中最新commit
```

**增量缓存构建：**

`build_commit_cache(incremental=True)` 时的工作流程：

```
┌─────────────────────────────────┐
│ get_latest_cached_commit(rv)    │  查询 SQLite 中 timestamp 最大的 commit
└──────────────┬──────────────────┘
               ▼
┌─────────────────────────────────┐
│ merge-base --is-ancestor        │  验证该 commit 仍在目标分支上
│ latest_commit  branch           │  (防止 rebase 后产生脏数据)
└──────────┬──────────┬───────────┘
       成功 ▼          ▼ 失败
┌──────────────┐  ┌───────────────┐
│ git log       │  │ 降级全量重建   │
│ latest..branch│  │ (清除脏缓存)   │
│ (仅新增commit)│  └───────────────┘
└──────────────┘
```

- 增量模式下保留 FTS 触发器，仅补录新增记录到 FTS 索引
- 全量模式下禁用 FTS 触发器，导入完成后通过 `_rebuild_fts()` 完整重建
- CLI 默认行为：已有缓存 → 增量；无缓存 → 全量；`--full` → 强制全量

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
| check-fix 命令 | `False` | 仅双向相似度 | 判断修复补丁是否已合入 |

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

**`search_detailed` 方法（用于 check-intro / check-fix）：**

运行全部三级策略（不短路），通过 `use_containment` 参数区分搜索语义：
- `search_detailed(..., use_containment=True)` — check-intro，L3 使用包含度优先
- `search_detailed(..., use_containment=False)` — check-fix，L3 仅用双向相似度

**check-intro 命令流程：**

```
输入: --cve CVE-xxx 或 --commit <intro_id>
  │
  ├─ CVE模式: fetch_cve → 提取 introduced_commit_id
  │
  └─ 对每个引入 commit:
       1. fetch_patch 获取补丁信息
       2. search_detailed(use_containment=True)
       3. L1 区分 on_branch / not_on_branch / not_found
       4. L3 启用包含度算法，适配 squash 场景
  │
  └─ 结论: is_present → 漏洞已引入 / 未引入
```

**check-fix 命令流程：**

```
输入: --cve CVE-xxx 或 --commit <fix_id>
  │
  ├─ CVE模式: fetch_cve → 提取 mainline_fix + version_commit_mapping
  │           对 mainline fix 和匹配版本的 stable backport 逐一检测
  │
  └─ 对每个 fix commit:
       1. fetch_patch 获取补丁信息
       2. search_detailed(use_containment=False)
       3. 三级策略独立展示结果
  │
  └─ 最终结论: 任一 commit 命中 → "已合入" / 全部未命中 → "需 backport"
```

### Dependency Agent (`agents/dependency.py`)

**核心问题：** 当社区修复补丁无法直接 cherry-pick 到目标仓库时，需要识别哪些中间 commit 必须先合入（前置依赖）。本质上是回答：*"从漏洞引入到现在，有哪些 commit 修改了相同的代码区域，导致修复补丁无法干净应用？"*

#### 完整分析流程

```
fix_patch (社区修复补丁)
  │
  ▼
Step 1: 提取 Fixes: 标签链
  │  正则提取 commit_msg 中 "Fixes: <commit_id>" 引用
  │  加入 skip_ids 排除列表，避免与 fix 本身混淆
  │
  ▼
Step 2: 确定时间窗口
  │  若有引入 commit 的搜索结果 (intro_search.target_commit)
  │  → 查询其 timestamp 作为 after_ts
  │  → 只分析「引入 commit → HEAD」这段区间
  │  若无引入信息 → after_ts=0，搜索全量
  │
  ▼
Step 3: 候选 commit 检索
  │  fix_patch.modified_files → PathMapper.expand_files()
  │  → git log --no-merges --after=@{after_ts} -- <files>
  │  → 返回最多 50 个候选 (search_by_files)
  │  → 排除 skip_ids (fix commit / intro commit / Fixes 引用)
  │
  ▼
Step 4: 逐候选 Hunk 级重叠分析
  │  对每个候选:
  │    ├─ git show <commit> 获取 diff
  │    ├─ 大重构过滤: 修改文件数 > 20 → 跳过
  │    ├─ extract_hunks_from_diff → 提取 hunk 列表 (file, start, end)
  │    ├─ extract_functions_from_diff → 提取函数名集合
  │    ├─ compute_hunk_overlap(fix_hunks, candidate_hunks, margin=50)
  │    │    ├─ direct: 行范围直接相交 (a_start ≤ b_end && b_start ≤ a_end)
  │    │    └─ adjacent: 行范围在 ±50 行内相邻
  │    └─ func_overlap = fix_funcs ∩ candidate_funcs
  │
  ▼
Step 5: 评分 + 分级 + 排序
  │  score 公式 + 三级分类 (见下方)
  │  排序: grade 优先 (strong > medium > weak), 同级按 score 降序
  │
  ▼
输出: List[PrerequisitePatch]
  含 commit_id, subject, author, grade, score,
  overlap_hunks, adjacent_hunks, overlap_funcs
```

#### Hunk 重叠检测算法

`extract_hunks_from_diff` 从 diff 文本中解析每个代码块的精确位置：

```
diff --git a/net/ipv6/ip6_tunnel.c b/net/ipv6/ip6_tunnel.c     ← 当前文件
@@ -1234,8 +1234,10 @@ static int ip6_tnl_xmit(...)            ← hunk 起始
│   old_start=1234  old_end=1242  (旧文件行范围)
│   new_start=1234  new_end=1244  (新文件行范围)
│
@@ -1500,6 +1502,9 @@ static void ip6_tnl_link_config(...)    ← 另一个 hunk
    old_start=1500  old_end=1506
    new_start=1502  new_end=1511
```

`compute_hunk_overlap(hunks_a, hunks_b, margin=50)` 对两组 hunk 做两两比较：

```
fix_patch hunk          candidate hunk          判定
─────────────────       ────────────────        ──────────────
file: ip6_tunnel.c      file: ip6_tunnel.c
lines: 1234-1244        lines: 1230-1240        → direct (相交)

file: ip6_tunnel.c      file: ip6_tunnel.c
lines: 1234-1244        lines: 1260-1280        → adjacent (间距<50)

file: ip6_tunnel.c      file: ip6_tunnel.c
lines: 1234-1244        lines: 1500-1510        → 无关 (间距>50)

file: ip6_tunnel.c      file: route.c
lines: 1234-1244        lines: 1234-1244        → 无关 (不同文件)
```

- **直接重叠 (direct)：** `a_start ≤ b_end && b_start ≤ a_end`（同文件、行范围相交）
- **相邻重叠 (adjacent)：** 行范围不相交，但间距在 `margin`(50) 行内

#### 函数级重叠

`extract_functions_from_diff` 从 `@@ ... @@ function_name` 行中提取函数名。Git diff 的 `@@` 行会自动标注所在函数，取交集即可得到修复补丁和候选 commit 共同修改的函数。

```python
fix_funcs    = {"ip6_tnl_xmit", "ip6_tnl_link_config"}
cand_funcs   = {"ip6_tnl_xmit", "ip6_tnl_create2"}
func_overlap = {"ip6_tnl_xmit"}  # 交集
```

#### 评分公式

```python
score  = min(direct_overlaps × 0.3, 0.6)     # 直接重叠: 单个 0.3, 上限 0.6
       + min(adjacent_overlaps × 0.1, 0.2)   # 相邻重叠: 单个 0.1, 上限 0.2
       + min(len(func_overlap) × 0.15, 0.3)  # 函数重叠: 单个 0.15, 上限 0.3
                                              # 理论最大值: 1.1 (实际被分级规则覆盖)
```

**噪声过滤：** `score < 0.05 && 无函数重叠 && direct_overlaps == 0` → 丢弃

#### 三级分级规则

| 等级 | 条件 | 含义 | 典型场景 |
|------|------|------|---------|
| **强 (strong)** | `(direct > 0 && func_overlap) \|\| score ≥ 0.5` | 修改了相同代码行和相同函数，几乎必须先合入 | 候选 commit 重构了 fix 补丁要修改的同一个函数 |
| **中 (medium)** | `direct > 0 \|\| adjacent > 0 \|\| score ≥ 0.2` | 修改了相邻区域或同函数，大概率产生 cherry-pick 冲突 | 候选 commit 在 fix 修改的上下 50 行内有改动 |
| **弱 (weak)** | 其余（仅文件级重叠） | 修改了同文件的不相关区域，通常不影响合入 | 同文件中的无关 bug fix |

#### 路径映射集成

`analyze` 方法在调用 `search_by_files` 前，先通过 `PathMapper.expand_files` 将修复补丁的文件列表扩展为包含所有等价路径的集合。例如修复补丁修改 `fs/smb/client/file.c`，扩展后搜索 `fs/smb/client/file.c` + `fs/cifs/file.c`，确保在 5.10 仓库中能找到历史修改记录。

#### 输出数据结构

```python
@dataclass
class PrerequisitePatch:
    commit_id: str
    subject: str
    author: str = ""
    timestamp: int = 0
    grade: str = "weak"         # "strong" / "medium" / "weak"
    score: float = 0.0
    overlap_funcs: List[str] = field(default_factory=list)   # 重叠函数名列表
    overlap_hunks: int = 0      # 直接重叠 hunk 数
    adjacent_hunks: int = 0     # 相邻重叠 hunk 数
```

最终输出按 `grade` 优先排序（strong > medium > weak），同级按 `score` 降序。

### DryRun Agent (`agents/dryrun.py`)

**设计背景：** 社区修复补丁无法直接 `git apply` 到目标分支的原因复杂多样：context lines 偏移（中间 commit 修改了相邻行）、补丁涉及的同一行被修改（真正的代码冲突）、跨版本路径不同。DryRun Agent 实现了**五级渐进式试应用策略**和**逐 hunk 冲突分析**，尽可能自动适配，无法自动解决时提供精确的冲突诊断。

#### 代码语义匹配 — 解决 Context 被打断问题

**核心问题**：mainline patch 的 context 行在企业仓库中被打断（中间插入了额外代码），导致 context 序列匹配全部失败。

**解决方案**：不再依赖 context 序列的连续性，而是提取 patch 的实际代码片段（removed/added），用**多维度代码相似度**在目标文件中搜索。

**新增类**：

| 类 | 用途 |
|---|------|
| `CodeMatcher` | 多维度代码相似度匹配：结构相似度 (编辑距离) + 标识符匹配率 + 关键字序列相似度 |
| `PatchContextExtractor` | 从 patch 提取代码片段、标识符、关键字、函数名等元数据 |

**多维度相似度计算**：

```
score = 0.5 × structure_sim (SequenceMatcher)
      + 0.3 × identifier_match_rate (变量名/函数名交集)
      + 0.2 × keyword_sequence_sim (关键字序列相似度)
```

**集成到 `_locate_hunk`**：

| 策略 | 调用位置 | 适用场景 |
|------|---------|---------|
| L1-L7 | 现有序列匹配 | context 连续、行号接近 |
| **L8** | **`_locate_removal_hunk` / `_locate_addition_hunk` 末尾** | **context 被打断、行号偏移严重** |

L8 策略在所有传统策略失败后触发，用代码内容而非 context 序列做匹配。

**示例**：

```
Mainline patch (纯添加 hunk):
  ctx_before = ["static struct kmem_cache *dquot_cachep;"]
  + 新增代码
  ctx_after = ["static int nr_dquots;"]

企业仓库文件:
  line 1: ...
  line 2: /* custom comment */  ← 额外行, 打断了 context 序列
  line 3: static struct kmem_cache *dquot_cachep;
  line 4: static int nr_dquots;

传统 context 序列匹配: 失败 (序列被打断)
L8 代码语义匹配:
  1. 提取 ctx_before[-1] 的标识符: {static, struct, kmem_cache, dquot_cachep}
  2. 在文件中搜索包含这些标识符的行
  3. 找到 line 3 (相似度 0.94)
  4. 插入点 = 3 + 1 = 4 ✔
```

#### 五级自适应策略

| Level | 策略 | 命令 / 算法 | 适用场景 |
|-------|------|------------|---------|
| L0 | `strict` | `git apply --check` | 补丁可直接应用 |
| L1 | `context-C1` | `git apply --check -C1` | context lines 有偏移，仅需 1 行 context 匹配 |
| L2 | `3way` | `git apply --check --3way` | base blob 可用时三方合并 |
| L3 | `regenerated` | 从目标文件重建 context | context 严重偏移，核心 +/- 不变 |
| L4 | `conflict-adapted` | 用目标文件实际行替换 - 行 | 中间 commit 修改了补丁涉及的同一行代码 |

```
check_adaptive(patch, target_version)
  │
  ├─ L0: git apply --check ──── 成功 → 返回 (strict)
  │                              失败 ↓
  ├─ L1: git apply --check -C1 ── 成功 → 返回 (context-C1)
  │                              失败 ↓
  ├─ L2: git apply --check --3way ── 成功 → 返回 (3way)
  │                              失败 ↓
  ├─ L3: _regenerate_patch ───── 成功 → 返回 (regenerated)
  │   └─ 定位 - 行位置, 从目标文件提取正确 context, 重建 patch
  │                              失败 ↓
  ├─ L4: _analyze_conflicts ──── 冲突分析 + 尝试冲突适配
  │   ├─ 逐 hunk 定位: expected vs actual
  │   ├─ 分级: L1/L2/L3
  │   ├─ 生成适配 patch: actual 替换 expected, 保留 +
  │   └─ git apply --check ──── 成功 → 返回 (conflict-adapted, 需人工审查)
  │                              失败 ↓
  └─ 全部失败: 返回冲突分析报告 (conflict_hunks)
```

#### 路径映射感知

DryRun Agent 接收 `PathMapper` 实例，在两个层面应用路径映射：

1. **Diff 路径重写** (`_rewrite_diff_paths`)：将补丁中的 upstream 路径（如 `fs/smb/client/`）替换为 local 路径（如 `fs/cifs/`），确保 `git apply` 能找到正确文件
2. **文件查找回退** (`_resolve_file_path`)：在 `_regenerate_patch` 和 `_analyze_conflicts` 中，先查原始路径，失败则尝试 `PathMapper.translate()` 的所有变体

#### Stable Backport 补丁优先

Pipeline 在执行 DryRun 前，自动从 CVE 的 `version_commit_mapping` 中查找与目标分支版本最匹配的 stable backport 补丁（如 5.10.237 的 backport），优先使用该补丁而非 mainline 补丁。Stable backport 的路径和 context 与目标分支更一致，大幅提高 DryRun 的成功率。

```python
# Pipeline._find_stable_patch 逻辑
1. 从 target_version (如 "5.10-hulk") 提取 major.minor 前缀 "5.10"
2. 在 version_commit_mapping 中查找 5.10.x 的 backport commit
3. 通过 Crawler 获取该 commit 的补丁
4. 若找到 → DryRun 使用此补丁; 否则 → 回退到最近低版本 backport 或 mainline
```

#### 核心定位算法 — 两层架构

**设计背景**：社区补丁的 context 行和 `-` 行来自 mainline 或 stable 版本，企业自维护仓库因自定义补丁插入了额外代码行，导致 context 序列被"打断"——6 行 context 中间多了 1-2 行自定义代码，无法作为连续序列精确匹配。同时行号偏移（如 mainline @@ -162 @@  vs 内部仓 @@ -163 @@），`git apply` 的标准 context 匹配全部失败。

**已修复的关键 bug**：
1. Diff 解析器 `_parse_hunks_for_regen` 的 `elif` 顺序错误 — `---`/`+++` 判断在 hunk 内容捕获之前，导致 `---xxx`（如删除 `--count`）被错误吞入 header
2. `_locate_in_file` 过滤空行后改变了序列对齐，导致滑动窗口模糊匹配找到错误位置
3. `_regenerate_patch` 逐行走查 `hunk_lines` 在目标文件有额外行时必然错位

**第一层：`_locate_hunk` — Hunk 级定位入口**

返回 `(change_pos, n_remove)`：change_pos = 变更点在目标文件中的行号，n_remove = 需删除行数（纯添加 hunk 为 0）。

```
_locate_hunk(hunk_lines, file_lines, hint, func_name)
  │
  ├─ 有 - 行: _locate_removal_hunk
  │   ├─ A) 直接搜索 removed 行序列 (_locate_in_file)
  │   ├─ B) before-ctx 最后一行做锚点 (_find_anchor_line)
  │   └─ C) after-ctx 第一行做锚点
  │
  └─ 纯添加: _locate_addition_hunk
      ├─ A) before-ctx 最后一行做锚点 → insert = anchor + 1  ★关键
      ├─ B) after-ctx 第一行做锚点 → insert = anchor
      ├─ C) 整段 before-ctx 序列搜索
      ├─ D) 整段 after-ctx 序列搜索
      └─ E) 全 hunk 非 + 行投票
```

**锚点行定位 (`_find_anchor_line`)** 是解决"内容相同但 context 被打断"问题的核心：

```
社区 patch (纯添加 hunk):
  ctx_before[-1] = "static struct kmem_cache *dquot_cachep;"  ← 锚点行
  + 新增代码 (workqueue, mutex)
  ctx_after[0]  = "static int nr_dquots;"

企业内部文件:
  line 1:  ...module_names[] = INIT_QUOTA_MODULE_NAMES;
  line 2:  (empty)
  line 3:  /* custom comment */  ← 额外行, 打断了 context 序列
  line 4:  static struct kmem_cache *dquot_cachep;  ← 锚点命中!
  line 5:  static int nr_dquots;

→ anchor = 4 → insert_point = 5 → 在 dquot_cachep 和 nr_dquots 之间插入 ✔
```

单行锚点搜索不受 context 序列中间额外行的影响，且利用行号 hint（含偏移传播）缩小搜索窗口（±300 行），先精确匹配再 SequenceMatcher ≥ 0.85 模糊匹配。

**跨 hunk 偏移传播**：同一文件的多个 hunk，前一个 hunk 的实际偏移量传播为下一个 hunk 的搜索起点修正。

**第二层：`_locate_in_file` — 序列级定位引擎**

当锚点行搜索不适用（如 removed 行序列搜索）时使用：

```
策略1: 精确序列匹配 (strip 后完全一致)
策略2: 函数名锚点搜索 (@@ 行提取函数名, 限定函数作用域)
策略3: 行号提示 ± 窗口 (±300 行, 含偏移修正)
策略4: 全局逐行模糊匹配 (加权评分, 短序列阈值 0.45)
策略5: Context 行重试
策略6: 逐行投票 (每行估算起始位置 estimate = file_pos - needle_idx, 取众数)
策略7: 最长行最佳匹配
```

**逐行投票算法 (`_find_by_line_voting`)** — 改进版使用位置估算众数：

```
needle:                          文件匹配    estimate = file_pos - idx
  [0] "dquot_cachep;"    →    line 4      →  4 - 0 = 4
  [1] "nr_dquots;"       →    line 5      →  5 - 1 = 4
  [2] "reserved_space;"  →    line 6      →  6 - 2 = 4
  [3] "quota_format;"    →    line 7      →  7 - 3 = 4

votes: {4: 4} → best = 4 ✔ (即使中间有额外行, 大多数行对起始位置的估算一致)
```

**补丁重建改进**：`_regenerate_patch` 不再逐行走查 `hunk_lines`（额外行导致错位），改为直接从目标文件 `change_pos` 读取 context + 实际 `-` 行、保留原始 `+` 行。

```python
# 旧方式 (走查 hunk_lines, 额外行导致错位):
for hl in hunk_lines:
    if hl.startswith("-"): ...  # 依赖 target[idx] 对齐
    elif hl.startswith("+"): ...
    else: target[idx]  # ← 错位!

# 新方式 (直接从变更点读取):
for i in range(change_pos - 3, change_pos): context
for i in range(change_pos, change_pos + n_remove): -target[i]
for a in added_lines: +a
for i in range(change_pos + n_remove, ...): context
```

#### 逐 Hunk 冲突分析

当所有自动策略失败时，`_analyze_conflicts` 对每个冲突 hunk 执行：

1. **定位**：用 `_locate_in_file` 找到 hunk 对应的文件位置
2. **对比**：提取 patch 期望的 `-` 行 (expected) 和文件实际行 (actual)
3. **逐行比较**：标记每一行的具体差异（补丁期望 vs 文件实际）
4. **分级**：

| 级别 | 行相似度 | 含义 | 处理方式 |
|------|---------|------|---------|
| **L1** | ≥ 85% | 轻微差异（变量重命名、空格变动等） | 自动适配 |
| **L2** | 50-85% | 中度差异（部分重构） | 自动适配 + 人工审查 |
| **L3** | < 50% | 重大差异（代码大幅改写） | 需人工手动合入 |

5. **冲突适配补丁生成**（L1/L2 级 hunk）：
   - 用目标文件 actual 行替换 patch 的 `-` 行
   - 保留 patch 的 `+` 行不变
   - 从目标文件提取正确的 context
   - 尝试 `git apply --check`，成功则标记为 `conflict-adapted`

**CLI 展示**：对分析人员展示完整的冲突诊断信息：
- 尝试路径：`✘ strict → ✘ -C1 → ✘ 3way → ✘ regenerated → ✔ conflict-adapted`
- 逐 hunk 冲突详情：文件路径、行号、冲突等级、行相似度
- 每行差异对比：`补丁期望: xxx` vs `文件实际: yyy`
- 补丁目标代码：patch 想改成什么 (`+` 行)

---

## Pipeline 编排

```
Step 1: Crawler.fetch_cve + fetch_patch
Step 2: Analysis.search (引入commit)
Step 3: Analysis.search (修复commit)
       └─ 若已合入 → 结束
       └─ 尝试 5.10 stable backport
Step 4: Dependency.analyze (前置依赖)
Step 5: DryRun.check_adaptive (多级自适应试应用)
       └─ 优先使用 stable backport 补丁
       └─ strict → -C1 → 3way → regenerated → conflict-adapted
```

---

## 验证框架 (validate / benchmark)

### 设计目标

工具对"未修复 CVE"给出的前置依赖推荐**无法直接验证准确性**。验证框架通过**利用已修复 CVE 反向验证**：将仓库回退到修复前状态，运行完整分析流水线，将工具输出与真实合入记录进行对比，量化工具的置信度。

### 核心技术：git worktree 回退

采用 `git worktree add --detach` 方案，在 `known_fix~1`（或最早 prereq 之前）创建轻量工作区：

```
主仓库 (.git 对象库)
  │
  ├─ linux-5.10.y 分支 (完整历史, 包含修复)
  │
  └─ /tmp/cve_validate_xxx  (worktree, HEAD = known_fix~1)
       └─ 共享 .git 对象库, 秒级创建/清理
       └─ branch = "HEAD" → 所有 git log 自动限定到修复前
```

**技术优势：**

| 方案 | 原理 | 优缺点 |
|------|------|--------|
| **git worktree (采用)** | 在 `known_fix~1` 创建 detached HEAD 工作区 | 非破坏性、可并行、现有 Pipeline 无需改动 |
| 虚拟 HEAD | 修改所有搜索方法加 `effective_head` 参数 | 侵入性强、缓存需过滤 |
| git checkout | 直接 checkout 到旧版本 | 破坏性、不可并行、中断需恢复 |

**关键实现细节：**

- worktree 内 GitRepoManager 配置 `branch="HEAD"`，确保 `git merge-base --is-ancestor commit_id HEAD` 正确排除修复后 commit
- worktree 使用 `use_cache=False`，避免缓存污染（搜索直接走 `git log`）
- 回滚点计算：无 `known_prereqs` 时用 `known_fix~1`；有时自动找最早 prereq 的父节点

### validate 命令流程

```
输入: --cve CVE-xxx --target 5.10-hulk --known-fix <commit> [--known-prereqs "a,b,c"]
  │
  ├─ Step 1: 验证 known_fix 在目标分支上 (merge-base --is-ancestor)
  │
  ├─ Step 2: 计算回滚点
  │   └─ 无 prereqs → known_fix~1
  │   └─ 有 prereqs → 最早 prereq 的父节点 (merge-base 两两比较)
  │
  ├─ Step 3: git worktree add --detach /tmp/validate-xxx <rollback>
  │
  ├─ Step 4: 创建 worktree GitRepoManager (branch=HEAD, use_cache=False)
  │          → Pipeline.analyze(cve_id, target) 运行完整分析
  │
  ├─ Step 5: 收集丰富诊断数据
  │   ├─ fix_patch_detail:   社区修复补丁的 commit/subject/author/修改文件/diff行数
  │   ├─ known_fix_detail:   本地仓库真实修复 commit 的 stat 输出 (文件变更摘要)
  │   ├─ dryrun_detail:      应用结果/冲突文件/error输出/stat/不一致原因分析
  │   ├─ tool_prereqs:       工具推荐的前置依赖 (含 grade/score/overlap_hunks/overlap_funcs)
  │   └─ known_prereqs_detail: 真实合入的前置补丁信息 (commit/subject/author)
  │
  ├─ Step 6: 对比检查
  │   ├─ fix_correctly_absent:  result.is_fixed == False
  │   ├─ intro_detected:        result.is_vulnerable == True
  │   ├─ dryrun_accurate:       冲突预测是否匹配 prereqs 需求
  │   └─ prereq_metrics:        Precision / Recall / F1 (ID + Subject 匹配)
  │
  ├─ Step 7: LLM 差异分析 (可选, 仅 FAIL 时触发)
  │   └─ 将 fix_patch/dryrun/prereqs/known_fix 全部上下文发送给 LLM
  │      请求分析: 1) 每个失败点根因 2) 前置依赖差异原因 3) DryRun 误判原因 4) 改进建议
  │
  └─ Step 8: git worktree remove, 渲染增强报告
```

### 前置依赖比较算法

```python
def _compare_prereqs(recommended, known_ids, git_mgr, rv):
    # 1. 获取 known_prereqs 的 subject 信息
    # 2. 尝试 ID 前缀匹配 (前 12 字符)
    # 3. 回退到 Subject 相似度匹配 (≥80%)，覆盖 cherry-pick ID 偏移
    # 4. 计算 Precision = |TP| / |推荐|, Recall = |TP| / |真实|
    #    F1 = 2PR / (P+R)
```

双重匹配策略解决了本地仓库 commit ID 与社区不同的问题：即使 cherry-pick 后 ID 完全变化，只要 subject 保持一致（>80% 相似度），仍可正确匹配。

### benchmark 命令

从 YAML 文件批量加载 CVE 基准集，逐一执行 validate，计算汇总指标：

```yaml
# benchmarks.yaml
benchmarks:
  - cve_id: CVE-2024-26633
    known_fix_commit: "da23bd709b46"
    known_prereqs: []
    notes: "ip6_tunnel 漏洞"
```

**汇总指标体系：**

| 指标 | 计算方式 |
|------|---------|
| 引入检测准确率 | 正确识别引入的 CVE 数 / 总数 |
| 修复检测准确率 | 正确返回"未合入"的 CVE 数 / 总数 |
| 前置依赖平均精确率 | Avg(Precision) |
| 前置依赖平均召回率 | Avg(Recall) |
| 前置依赖 F1-Score | Avg(F1) |
| DryRun 预测准确率 | 预测正确的 CVE 数 / 有 DryRun 的总数 |
| 搜索策略分布 | L1/L2/L3/未命中 各占比 |

**CVE 数据不完整处理：** 当 MITRE API 无 fix commit 数据时，标记为"CVE上游数据不完整"而非误报 FAIL。

### 增强验证报告

验证报告采用分层展示，在 FAIL 场景下提供完整的差异诊断信息：

| 报告区域 | 内容 | 何时显示 |
|----------|------|---------|
| 基本信息 | CVE / Known Fix / 目标分支 / Worktree Commit | 始终 |
| 检查结果矩阵 | 修复检测 / 引入检测 / DryRun / P/R/F1 | 始终 |
| 社区修复补丁 | commit / subject / author / 修改文件列表 / diff行数 | 有 fix_patch 时 |
| 本地真实修复 | commit / subject / author / git show --stat | 始终 |
| DryRun 详情 | 应用结果 / 冲突文件 / error 输出 / stat / **不一致原因** | 有 dryrun 时 |
| 前置依赖对比 | 工具推荐列表 (grade/score/hunks/funcs) vs 真实合入列表 | 有 prereqs 时 |
| 匹配详情 | TP / FP / FN 具体 commit ID | 有 prereq_metrics 时 |
| LLM 差异分析 | AI 生成的根因分析和改进建议 (Markdown) | LLM 启用且 FAIL 时 |
| 工具建议 | Pipeline 原生建议 | 有 recommendations 时 |

**DryRun 不一致原因分析：**

当 DryRun 预测与 known_prereqs 矛盾时，系统自动生成结构化原因分析：

- **补丁可应用但存在已知前置依赖**：语义依赖（非文本冲突）、3-way merge 掩盖冲突、编译/运行时依赖
- **补丁有冲突但无需前置依赖**：本地独立修改导致形式冲突、实际使用 3-way merge 或手动 resolve

### LLM 智能分析 (可选)

集成 OpenAI 兼容 API，在验证 FAIL 时自动分析差异原因：

```yaml
# config.yaml
llm:
  enabled: true
  provider: "openai"         # 兼容 DeepSeek / Azure / vLLM 等
  api_key: ""                # 或 LLM_API_KEY 环境变量
  base_url: "https://api.openai.com/v1"
  model: "gpt-4o"
```

LLM 接收完整上下文（社区补丁摘要、DryRun 输出、工具推荐、真实合入记录），输出：
1. 逐项分析每个验证失败点的根因
2. 工具推荐与真实情况的差异原因
3. DryRun 预测不准确的可能原因
4. 具体改进建议

实现位于 `core/llm_analyzer.py`，使用标准 `urllib` 发送 HTTP 请求，不引入额外依赖。

### GitRepoManager worktree API

```python
create_worktree(rv, commit, worktree_path) -> bool
    # git worktree add --detach <path> <commit>
    # 在指定 commit 创建 detached HEAD 工作区

remove_worktree(rv, worktree_path)
    # git worktree remove --force <path>
    # 清理工作区 (共享对象库不受影响)
```

---

## 已验证测试用例

| CVE | 状态 | 验证点 |
|-----|------|--------|
| CVE-2024-26633 | 已修复 | L1找到引入commit, L2找到修复backport |
| CVE-2025-40198 | N/A | Mainline识别准确性 (7个版本映射全部正确) |
| CVE-2024-50154 | 已修复 | L1引入 + L2修复 + DryRun冲突检测 |
| CVE-2024-26633 | validate | worktree回退验证: 修复检测✔ 引入检测L1✔ DryRun 3way✔ |
| CVE-2025-40196 | 未修复 | 引入L2✔, stable backport 补丁自动选择, DryRun 3way✔ |

## 已知限制

1. Diff匹配(L3)需要逐commit获取diff，大量候选时较慢
2. 依赖分析基于文件/函数重叠，无法捕获数据结构变更等间接依赖
3. DryRun 的 `conflict-adapted` 策略生成的适配补丁**需人工审查语义正确性** — 它保证补丁能 apply，但不保证逻辑正确
4. MITRE API对部分老旧CVE可能缺少structured affected数据
5. 验证框架的前置依赖比较依赖 ID/Subject 匹配，无法覆盖纯代码语义等价的情况

---

## 新增功能 (Phase 1-4)

### Phase 1: 代码语义匹配 (CodeMatcher)

**文件**：`core/code_matcher.py`

**核心类**：
- `PatchContextExtractor`：从 patch 提取代码片段、标识符、关键字、函数名
- `CodeMatcher`：多维度代码相似度匹配

**多维度相似度**：
```
score = 0.5 × structure_sim (SequenceMatcher 编辑距离)
      + 0.3 × identifier_match_rate (变量名/函数名交集)
      + 0.2 × keyword_sequence_sim (关键字序列相似度)
```

**集成点**：`agents/dryrun.py` 的 `_locate_hunk` 作为 Level 8 策略，在所有传统序列匹配失败后触发。

**解决的问题**：
- mainline patch 的 context 行在企业仓库中被打断（中间插入额外代码）
- 传统 context 序列匹配无法处理被打断的情况
- 代码语义匹配不依赖 context 序列连续性，只关注代码内容本身

### Phase 2: 详细搜索过程报告 (SearchReport)

**文件**：`core/search_report.py`

**核心类**：
- `StrategyResult`：单个搜索策略的结果（策略名、成功/失败、位置、置信度）
- `HunkSearchReport`：单个 hunk 的完整搜索报告（removed/added/context、策略结果、context 对比）
- `DetailedSearchReport`：完整补丁搜索报告（汇总统计）

**集成点**：`agents/dryrun.py` 的 `check_adaptive` 方法收集搜索报告，存储在 `DryRunResult.search_reports`。

**提供的信息**：
- 每个 hunk 的逐策略尝试结果
- mainline context vs 目标文件实际 context 的对比
- 代码片段对比（removed/added 的实际内容）
- 搜索成功/失败的原因

### Phase 3: AI 辅助补丁生成 (AIPatchGenerator)

**文件**：`core/ai_patch_generator.py`

**核心类**：
- `AIPatchGenerator`：调用 LLM 生成最小化修改的补丁

**工作流程**：
1. 输入：mainline patch + 目标文件实际代码 + 冲突分析结果
2. 构建 prompt，发送给 LLM
3. LLM 分析并生成新补丁（仅改变必要的 context 行，保留所有 + 行）
4. 验证补丁格式和可应用性

**配置**（在 `config.yaml` 中）：
```yaml
ai_patch_generation:
  enabled: false
  provider: "openai"
  # 复用现有 llm 配置
```

**集成点**：可在 `check_adaptive` 中作为 Level 5 策略（在所有自动策略失败后调用）。

### Phase 4: 函数分析 (FunctionAnalyzer)

**文件**：`core/function_analyzer.py`

**核心类**：
- `FunctionInfo`：函数信息（名称、位置、签名、参数、调用者/被调用者、修改行号）
- `FunctionAnalyzer`：C 代码函数分析

**功能**：
- 从 C 代码中提取函数定义
- 分析补丁修改的函数及其调用关系
- 生成影响分析报告

**方法**：
- `extract_functions(file_content, file_path)`：提取所有函数定义
- `analyze_patch_impact(patch_diff, file_content, file_path)`：分析补丁对函数的影响

**输出**：
```python
{
    "modified_functions": [FunctionInfo, ...],  # 被修改的函数
    "affected_functions": [FunctionInfo, ...],  # 调用被修改函数的函数
    "impact_summary": str                       # 影响摘要
}
```

**集成点**：可在 `DryRunResult` 中添加 `modified_functions` 字段，在 TUI 中展示函数调用链。

---

## 新增数据模型

**`core/models.py` 更新**：
- `DryRunResult` 新增字段 `search_reports: List[Dict]`，存储详细搜索过程

**`core/search_report.py` 新增**：
- `StrategyResult`、`HunkSearchReport`、`DetailedSearchReport` 数据类

---

## 集成总结

| 功能 | 文件 | 集成点 | 优先级 |
|------|------|--------|--------|
| 代码语义匹配 | `core/code_matcher.py` | `_locate_hunk` L8 策略 | P0 |
| 搜索过程报告 | `core/search_report.py` | `check_adaptive` 收集 | P1 |
| AI 补丁生成 | `core/ai_patch_generator.py` | `check_adaptive` L5 策略 | P2 |
| 函数分析 | `core/function_analyzer.py` | `DryRunResult` 扩展 | P3 |

所有新增功能均为**可选集成**，不影响现有 Pipeline 的正常运行。
