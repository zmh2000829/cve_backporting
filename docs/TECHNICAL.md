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

### matcher.py — 相似度算法

| 函数 | 算法 | 用途 |
|------|------|------|
| `subject_similarity` | SequenceMatcher (标准化后) | Level 2 匹配 |
| `diff_similarity` | SequenceMatcher (仅+/-行) | Level 3 匹配 |
| `file_similarity` | Jaccard (文件名集合) | 过滤 + 评分 |
| `normalize_subject` | 去除[backport]等前缀 | 预处理 |
| `extract_keywords` | 去停用词 + 截断 | 关键词搜索 |

**CommitMatcher.match_comprehensive 流程：**
1. ID精确比较 → confidence=1.0
2. Subject相似度 ≥ 0.95 → 直接返回
3. Diff相似度 (file×0.4 + diff×0.6) ≥ 0.70
4. 合并去重，按confidence降序

---

## agents/ 核心Agent

### Crawler Agent (`agents/crawler.py`)

**数据源：**
- MITRE CVE API: `https://cveawg.mitre.org/api/cve/{CVE_ID}`
- Google Kernel Mirror: `kernel.googlesource.com/pub/scm/linux/kernel/git/stable/linux`

**Mainline识别逻辑：**
1. `affected[].versions[]` 中 `versionType="git"` 的条目提取 fix commits
2. `versionType="original_commit_for_fix"` 标识 mainline 版本号
3. git commits 与 semver versions 一一映射
4. 匹配 mainline 版本号的 commit 即为 mainline fix

**Patch获取（双请求）：**
1. `?format=JSON` → commit元数据（subject、author、tree_diff文件列表）
2. `%5E%21?format=TEXT` → base64编码的diff

### Analysis Agent (`agents/analysis.py`)

**三级搜索：**

| Level | 策略 | 条件 | 置信度 |
|-------|------|------|--------|
| L1 | Commit ID精确匹配 | `git cat-file -t` + `git merge-base --is-ancestor` | 100% |
| L2 | Subject语义匹配 | `git log --grep` + SequenceMatcher ≥ 85% | 85-100% |
| L3 | Code Diff匹配 | `git log -- <files>` + diff_similarity ≥ 70% | 70-100% |

L2 两阶段搜索：先精确subject，再关键词OR搜索。

### Dependency Agent (`agents/dependency.py`)

**分析流程：**
1. 提取 Fixes: 标签引用的commit
2. 在目标仓库搜索修改同文件的近期commits
3. 排除已找到的fix/introduced commits
4. 对候选补丁做函数级重叠分析，标记强依赖

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
