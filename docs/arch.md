# CVE Backporting Engine — 系统架构全景

> **版本**: v1.0  
> **文档定位**: 以 ASCII 图形方式呈现系统全链路架构，帮助理解模块关系与数据流转

---

## 1. 系统总览

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          CVE Backporting Engine                                 │
│                                                                                 │
│   输入: CVE-ID + Target Version ──→ 输出: 回溯分析报告 + 可部署补丁策略          │
│                                                                                 │
│  ┌────────────────────────────────────────────────────────────────────────────┐  │
│  │                        CLI 交互层  (cli.py)                               │  │
│  │   analyze │ check-intro │ check-fix │ validate │ benchmark │ build-cache  │  │
│  │                            │                                              │  │
│  │   ┌─ Rich TUI ────────────┤                                              │  │
│  │   │  StageTracker         │  render_report / render_validate_report       │  │
│  │   │  Live Progress        │  render_benchmark_report                     │  │
│  │   └───────────────────────┘                                              │  │
│  └────────────────────────────┬───────────────────────────────────────────────┘  │
│                               │                                                 │
│  ┌────────────────────────────▼───────────────────────────────────────────────┐  │
│  │                     Pipeline 编排层  (pipeline.py)                         │  │
│  │                                                                           │  │
│  │   Pipeline.analyze(cve_id, target_version)                                │  │
│  │       │                                                                   │  │
│  │       ├─ Step 1: Crawler    ── 情报采集                                    │  │
│  │       ├─ Step 2: Analysis   ── Commit 搜索定位                             │  │
│  │       ├─ Step 3: Dependency ── 前置依赖分析                                │  │
│  │       └─ Step 4: DryRun     ── 补丁试应用                                  │  │
│  │                                                                           │  │
│  │   回调机制: on_stage(key, status, detail) → 驱动 TUI 实时更新              │  │
│  └────────────────────────────┬───────────────────────────────────────────────┘  │
│                               │                                                 │
│  ┌────────────────────────────▼───────────────────────────────────────────────┐  │
│  │                        Agent 业务层  (agents/)                             │  │
│  │                                                                           │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │  │
│  │  │   Crawler    │  │  Analysis    │  │  Dependency  │  │   DryRun     │  │  │
│  │  │   Agent      │  │  Agent       │  │  Agent       │  │   Agent      │  │  │
│  │  │              │  │              │  │              │  │              │  │  │
│  │  │ fetch_cve()  │  │ search()     │  │ analyze()    │  │ check_       │  │  │
│  │  │ fetch_patch()│  │ search_all() │  │              │  │ adaptive()   │  │  │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │  │
│  │         │                 │                  │                 │          │  │
│  └─────────┼─────────────────┼──────────────────┼─────────────────┼──────────┘  │
│            │                 │                  │                 │              │
│  ┌─────────▼─────────────────▼──────────────────▼─────────────────▼──────────┐  │
│  │                       Core 基础设施层  (core/)                            │  │
│  │                                                                           │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────────┐ │  │
│  │  │  models    │ │ git_manager│ │  matcher   │ │    code_matcher        │ │  │
│  │  │  数据模型   │ │ Git操作    │ │ 相似度匹配  │ │    代码语义匹配         │ │  │
│  │  │  + 结构体   │ │ + SQLite   │ │ + PathMap  │ │    + 多维评分           │ │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────────────────┘ │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────────┐ │  │
│  │  │  config    │ │ ui (Rich)  │ │ search_    │ │  function_analyzer    │ │  │
│  │  │  配置管理   │ │ TUI 渲染   │ │ report     │ │  C函数分析             │ │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────────────────┘ │  │
│  │  ┌────────────────────────┐ ┌──────────────────────────────────────────┐ │  │
│  │  │  llm_analyzer  🤖     │ │  ai_patch_generator  🤖                 │ │  │
│  │  │  LLM差异分析           │ │  AI辅助补丁生成                          │ │  │
│  │  └────────────────────────┘ └──────────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. 端到端数据流

```
                              ┌──────────────┐
                              │  用户输入     │
                              │  CVE-2024-xxx│
                              │  + 5.10-hulk │
                              └──────┬───────┘
                                     │
                ╔════════════════════╪════════════════════╗
                ║   Pipeline 编排    │                    ║
                ║                    ▼                    ║
                ║  ┌─────────────────────────────────┐   ║
                ║  │  ① Crawler Agent                │   ║
                ║  │                                 │   ║
                ║  │  MITRE API ──→ CveInfo          │   ║
                ║  │  git.kernel.org ──→ PatchInfo   │   ║
                ║  │  googlesource (fallback)        │   ║
                ║  │                                 │   ║
                ║  │  输出: cve_info + fix_patch     │   ║
                ║  └──────────────┬──────────────────┘   ║
                ║                 │                       ║
                ║                 ▼                       ║
                ║  ┌─────────────────────────────────┐   ║
                ║  │  ② Analysis Agent               │   ║
                ║  │                                 │   ║
                ║  │  三级搜索 (短路模式):             │   ║
                ║  │   L1 Commit ID 精确匹配         │   ║
                ║  │   L2 Subject 语义匹配           │   ║
                ║  │   L3 Diff 代码匹配              │   ║
                ║  │      └─ 含 Diff 包含度检测       │   ║
                ║  │                                 │   ║
                ║  │  输出: SearchResult             │   ║
                ║  │   .found / .strategy            │   ║
                ║  │   .confidence / .target_commit  │   ║
                ║  └──────────────┬──────────────────┘   ║
                ║                 │                       ║
                ║         ┌───────┴───────┐               ║
                ║         │  已合入？      │               ║
                ║         ├─ Yes → 返回   │               ║
                ║         └─ No ──┐       │               ║
                ║                 │       │               ║
                ║                 ▼                       ║
                ║  ┌─────────────────────────────────┐   ║
                ║  │  ③ Dependency Agent             │   ║
                ║  │                                 │   ║
                ║  │  时间窗口: intro_commit → HEAD   │   ║
                ║  │  Hunk 行范围重叠分析             │   ║
                ║  │  函数名交集检测                  │   ║
                ║  │  三级评分: 强 / 中 / 弱          │   ║
                ║  │                                 │   ║
                ║  │  输出: PrerequisitePatch[]      │   ║
                ║  └──────────────┬──────────────────┘   ║
                ║                 │                       ║
                ║                 ▼                       ║
                ║  ┌─────────────────────────────────┐   ║
                ║  │  ④ DryRun Agent                 │   ║
                ║  │     五级自适应补丁试应用          │   ║
                ║  │                                 │   ║
                ║  │  输出: DryRunResult             │   ║
                ║  │   .applies_cleanly              │   ║
                ║  │   .apply_method                 │   ║
                ║  │   .adapted_patch                │   ║
                ║  │   .conflict_hunks               │   ║
                ║  └──────────────┬──────────────────┘   ║
                ║                 │                       ║
                ╚═════════════════╪═══════════════════════╝
                                  │
                                  ▼
                           ┌──────────────┐
                           │AnalysisResult│
                           │  完整报告     │
                           └──────┬───────┘
                                  │
                          ┌───────┴───────┐
                          ▼               ▼
                   ┌────────────┐  ┌────────────┐
                   │ Rich TUI   │  │ JSON 输出  │
                   │ 交互式报告  │  │ 结构化数据  │
                   └────────────┘  └────────────┘
```

---

## 3. Agent 内部架构

### 3.1 Crawler Agent — 情报采集

```
┌─────────────────────────────────────────────────────────────┐
│                       Crawler Agent                         │
│                                                             │
│  fetch_cve(cve_id)                                         │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                                                       │  │
│  │   MITRE CVE API ──────→ 解析 JSON 提取:              │  │
│  │   (cveawg.mitre.org)     ├─ fix_commits[]            │  │
│  │                          ├─ introduced_commits[]      │  │
│  │                          ├─ mainline_fix_commit       │  │
│  │                          ├─ mainline_version          │  │
│  │                          └─ version_commit_mapping{}  │  │
│  │                                                       │  │
│  │   三级补丁源 (fallback):                               │  │
│  │     ① git.kernel.org/stable (format-patch)           │  │
│  │     ② git.kernel.org/torvalds                        │  │
│  │     ③ googlesource.com (base64)                      │  │
│  │                                                       │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  fetch_patch(commit_id, target_version)                    │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                                                       │  │
│  │   远程获取 ──→ 解析 diff ──→ PatchInfo               │  │
│  │       │                        ├─ subject            │  │
│  │       │ (失败时)                ├─ diff_code          │  │
│  │       ▼                        ├─ modified_files[]   │  │
│  │   本地 git show (via git_mgr)  └─ commit_msg         │  │
│  │                                                       │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Analysis Agent — 三级搜索引擎

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                            Analysis Agent                                    │
│                                                                              │
│  search(commit_id, subject, diff_code, target_version)                      │
│                                                                              │
│  ┌───── L1: Commit ID 精确匹配 ────────────────────────────────────────┐    │
│  │                                                                     │    │
│  │   git_mgr.commit_exists(commit_id, target_version)                 │    │
│  │     ├─ 命中 → confidence=1.0, 短路返回                              │    │
│  │     └─ 未命中 → 继续 L2                                             │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                              │ miss                                          │
│                              ▼                                               │
│  ┌───── L2: Subject 语义匹配 ──────────────────────────────────────────┐    │
│  │                                                                     │    │
│  │   git_mgr.search_by_subject(keywords)                              │    │
│  │     │                                                               │    │
│  │     ▼                                                               │    │
│  │   CommitMatcher.match_subject()                                    │    │
│  │     ├─ normalize_subject() 标准化                                   │    │
│  │     ├─ subject_similarity() SequenceMatcher                        │    │
│  │     ├─ 阈值 ≥ 0.7 → confidence 评分, 短路返回                      │    │
│  │     └─ 未达标 → 继续 L3                                             │    │
│  │                                                                     │    │
│  │   SQLite FTS5 全文索引加速                                          │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                              │ miss                                          │
│                              ▼                                               │
│  ┌───── L3: Diff 代码匹配 ────────────────────────────────────────────┐    │
│  │                                                                     │    │
│  │   路径翻译: PathMapper.translate(filepath)                          │    │
│  │     │                                                               │    │
│  │     ▼                                                               │    │
│  │   git_mgr.search_by_files(modified_files)                          │    │
│  │     │                                                               │    │
│  │     ▼                                                               │    │
│  │   CommitMatcher.match_diff()                                       │    │
│  │     ├─ extract_files_from_diff()                                   │    │
│  │     ├─ file_overlap() 文件重合度                                    │    │
│  │     ├─ diff_containment() Multiset 包含度 ← (引入commit场景)       │    │
│  │     ├─ diff_similarity() 双向相似度 ← (修复commit场景)              │    │
│  │     └─ 综合评分                                                     │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 3.3 Dependency Agent — 前置依赖分析

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           Dependency Agent                                   │
│                                                                              │
│  analyze(fix_patch, cve_info, target_version)                               │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Step 1: 确定时间窗口                                                │   │
│  │                                                                      │   │
│  │   intro_commit ──────────────────────────── HEAD                    │   │
│  │       │              搜索范围                  │                      │   │
│  │       └──────────────────────────────────────┘                       │   │
│  │                                                                      │   │
│  │  Step 2: 获取候选 commits                                            │   │
│  │                                                                      │   │
│  │   git log --follow -- <modified_files>                              │   │
│  │     │                                                                │   │
│  │     ▼                                                                │   │
│  │  Step 3: Hunk 级重叠分析                                             │   │
│  │                                                                      │   │
│  │   对每个候选 commit:                                                  │   │
│  │     ├─ extract_hunks_from_diff()  提取 hunk 行范围                   │   │
│  │     ├─ compute_hunk_overlap()     计算行范围重叠                      │   │
│  │     ├─ extract_functions_from_diff()  提取函数名                     │   │
│  │     └─ 函数名交集 ∩ 检测                                             │   │
│  │                                                                      │   │
│  │  Step 4: 三级评分                                                    │   │
│  │                                                                      │   │
│  │   ┌──────────┬────────────────────────────────────────┐             │   │
│  │   │  Grade   │  条件                                   │             │   │
│  │   ├──────────┼────────────────────────────────────────┤             │   │
│  │   │  强依赖  │  行范围直接重叠 且 函数名交集非空        │             │   │
│  │   │  中依赖  │  行范围相邻(±50行) 或 函数名交集非空     │             │   │
│  │   │  弱依赖  │  仅文件级重合                            │             │   │
│  │   └──────────┴────────────────────────────────────────┘             │   │
│  │                                                                      │   │
│  │  Step 5: Fixes: 标签链追踪                                           │   │
│  │                                                                      │   │
│  │   git log --grep="Fixes:" → 追踪引用链                              │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  输出: PrerequisitePatch[] (按 score 降序)                                   │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 3.4 DryRun Agent — 五级自适应试应用

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                             DryRun Agent                                     │
│                                                                              │
│  check_adaptive(patch, target_version) → DryRunResult                       │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                                                                        │  │
│  │   PatchInfo ──→ 写入临时 .patch 文件                                   │  │
│  │                    │                                                    │  │
│  │   ┌────────────────▼────────────────────────────────────────────────┐  │  │
│  │   │                                                                 │  │  │
│  │   │  L0: Strict ── git apply --check                               │  │  │
│  │   │    │                                                            │  │  │
│  │   │    ├── ✔ 成功 → return {method: "strict"}                      │  │  │
│  │   │    └── ✘ 失败                                                   │  │  │
│  │   │          │                                                      │  │  │
│  │   │          ▼                                                      │  │  │
│  │   │  L1: Context-C1 ── git apply --check -C1                      │  │  │
│  │   │    │                                                            │  │  │
│  │   │    ├── ✔ 成功 → return {method: "context-C1"}                  │  │  │
│  │   │    └── ✘ 失败                                                   │  │  │
│  │   │          │                                                      │  │  │
│  │   │          ▼                                                      │  │  │
│  │   │  L2: 3-Way Merge ── git apply --check --3way                  │  │  │
│  │   │    │                                                            │  │  │
│  │   │    ├── ✔ 成功 → return {method: "3way"}                        │  │  │
│  │   │    └── ✘ 失败                                                   │  │  │
│  │   │          │                                                      │  │  │
│  │   │          ▼                                                      │  │  │
│  │   │  L3: Regenerated  ⭐ 核心创新                                   │  │  │
│  │   │    │                                                            │  │  │
│  │   │    │  ┌─────────────────────────────────────────────────────┐  │  │  │
│  │   │    │  │  逐 Hunk 处理:                                      │  │  │  │
│  │   │    │  │                                                     │  │  │  │
│  │   │    │  │  _locate_hunk(hunk, target_file_lines)             │  │  │  │
│  │   │    │  │    │                                                │  │  │  │
│  │   │    │  │    │  七策略序列搜索 (按优先级):                     │  │  │  │
│  │   │    │  │    │   ┌─ S1: 精确序列匹配                          │  │  │  │
│  │   │    │  │    │   ├─ S2: 锚点行定位                            │  │  │  │
│  │   │    │  │    │   ├─ S3: 函数作用域搜索                        │  │  │  │
│  │   │    │  │    │   ├─ S4: 行号提示 ± 窗口 (跨hunk偏移传播)     │  │  │  │
│  │   │    │  │    │   ├─ S5: 全局逐行模糊匹配                     │  │  │  │
│  │   │    │  │    │   ├─ S6: 分段 context (before/after独立搜索)  │  │  │  │
│  │   │    │  │    │   └─ S7: 逐行投票 (起始位置众数)               │  │  │  │
│  │   │    │  │    │                                                │  │  │  │
│  │   │    │  │    │  定位失败时 → 代码语义匹配 (CodeMatcher)       │  │  │  │
│  │   │    │  │    │    score = 0.5×结构 + 0.3×标识符 + 0.2×关键字  │  │  │  │
│  │   │    │  │    │                                                │  │  │  │
│  │   │    │  │    ▼                                                │  │  │  │
│  │   │    │  │  (change_pos, n_remove)                            │  │  │  │
│  │   │    │  │    │                                                │  │  │  │
│  │   │    │  │    ▼                                                │  │  │  │
│  │   │    │  │  直接读取目标文件 → 重建 context → 组装新 hunk      │  │  │  │
│  │   │    │  │                                                     │  │  │  │
│  │   │    │  └─────────────────────────────────────────────────────┘  │  │  │
│  │   │    │                                                            │  │  │
│  │   │    │  组装完整补丁 → git apply --check 验证                     │  │  │
│  │   │    │                                                            │  │  │
│  │   │    ├── ✔ 成功 → return {method: "regenerated", adapted_patch}  │  │  │
│  │   │    └── ✘ 失败                                                   │  │  │
│  │   │          │                                                      │  │  │
│  │   │          ▼                                                      │  │  │
│  │   │  L4: Conflict-Adapted                                          │  │  │
│  │   │    │                                                            │  │  │
│  │   │    │  目标文件实际行替换 removed 行                              │  │  │
│  │   │    │  保留 added 行不变                                          │  │  │
│  │   │    │  逐 hunk 冲突严重性分析 (L1/L2/L3)                         │  │  │
│  │   │    │                                                            │  │  │
│  │   │    ├── ✔ 成功 → return {method: "conflict-adapted"}            │  │  │
│  │   │    └── ✘ 失败                                                   │  │  │
│  │   │          │                                                      │  │  │
│  │   │          ▼                                                      │  │  │
│  │   │  L5: AI-Generated 🤖 (可选)                                    │  │  │
│  │   │    │                                                            │  │  │
│  │   │    │  AIPatchGenerator.generate_patch()                        │  │  │
│  │   │    │    ├─ 输入: mainline_patch + target_file + conflict_info  │  │  │
│  │   │    │    └─ LLM 生成最小化修改补丁                               │  │  │
│  │   │    │                                                            │  │  │
│  │   │    └── return {method: "ai-generated", adapted_patch}          │  │  │
│  │   │                                                                 │  │  │
│  │   └─────────────────────────────────────────────────────────────────┘  │  │
│  │                                                                        │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Core 基础设施层详解

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           core/ 基础设施层                                   │
│                                                                             │
│  ┌─── models.py ────────────────────────────────────────────────────────┐  │
│  │                                                                      │  │
│  │   CveInfo ──→ PatchInfo ──→ SearchResult ──→ DryRunResult           │  │
│  │      │                          │                  │                  │  │
│  │      │         GitCommit    SearchStep        conflict_hunks[]       │  │
│  │      │         CommitInfo   StrategyResult    search_reports[]       │  │
│  │      │         MatchResult  MultiStrategyResult   adapted_patch     │  │
│  │      │                                                               │  │
│  │      └────→ AnalysisResult (聚合全部结果)                             │  │
│  │               ├─ cve_info: CveInfo                                   │  │
│  │               ├─ fix_patch: PatchInfo                                │  │
│  │               ├─ introduced_search: SearchResult                    │  │
│  │               ├─ fix_search: SearchResult                           │  │
│  │               ├─ prerequisite_patches: PrerequisitePatch[]          │  │
│  │               ├─ dry_run: DryRunResult                              │  │
│  │               └─ recommendations: str[]                             │  │
│  │                                                                      │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌─── git_manager.py ──────────────────────────────────────────────────┐   │
│  │                                                                     │   │
│  │   GitRepoManager                                                    │   │
│  │     │                                                               │   │
│  │     ├─ commit_exists()        ── L1 精确查询                        │   │
│  │     ├─ search_by_subject()    ── L2 FTS5 全文检索                   │   │
│  │     ├─ search_by_files()      ── L3 文件路径过滤                    │   │
│  │     ├─ get_commit_diff()      ── 获取完整 diff                      │   │
│  │     ├─ get_file_content()     ── 读取指定版本文件内容                │   │
│  │     ├─ build_cache()          ── 构建 SQLite + FTS5 缓存            │   │
│  │     └─ worktree 操作           ── 非破坏性回退验证                   │   │
│  │                                                                     │   │
│  │   存储后端:                                                         │   │
│  │   ┌────────────────────────────────────────────┐                   │   │
│  │   │  SQLite (commit_cache.db)                  │                   │   │
│  │   │  ┌──────────────┐  ┌────────────────────┐ │                   │   │
│  │   │  │  commits 表   │  │  commits_fts (FTS5)│ │                   │   │
│  │   │  │  commit_id   │  │  全文索引           │ │                   │   │
│  │   │  │  subject     │  │  subject + msg 检索 │ │                   │   │
│  │   │  │  author      │  │                    │ │                   │   │
│  │   │  │  timestamp   │  │  千万级 commit     │ │                   │   │
│  │   │  │  files       │  │  毫秒级响应        │ │                   │   │
│  │   │  └──────────────┘  └────────────────────┘ │                   │   │
│  │   └────────────────────────────────────────────┘                   │   │
│  │                                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─── matcher.py ──────────────────────────────────────────────────────┐   │
│  │                                                                     │   │
│  │   PathMapper                  CommitMatcher                        │   │
│  │     │                           │                                   │   │
│  │     ├─ translate()              ├─ match_subject()                 │   │
│  │     │  upstream ↔ local         │    └─ subject_similarity()       │   │
│  │     │  双向路径映射             ├─ match_diff()                    │   │
│  │     │                           │    ├─ file_overlap()             │   │
│  │     │  已知迁移:                │    ├─ diff_similarity()          │   │
│  │     │  fs/cifs/ ↔ fs/smb/      │    └─ diff_containment()         │   │
│  │     │  drivers/gpu/ ↔ ...      │        Multiset 包含度检测        │   │
│  │     │                           │                                   │   │
│  │     │                           extract_functions_from_diff()       │   │
│  │     │                           extract_hunks_from_diff()          │   │
│  │     │                           compute_hunk_overlap()             │   │
│  │     │                                                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─── code_matcher.py ─────────────────────────────────────────────────┐   │
│  │                                                                     │   │
│  │   CodeMatcher                  PatchContextExtractor                │   │
│  │     │                            │                                  │   │
│  │     ├─ find_best_location()      ├─ extract_hunk_metadata()        │   │
│  │     │   多维度相似度评分:         ├─ extract_removed_block()        │   │
│  │     │                            └─ extract_context_block()         │   │
│  │     │   score = 0.5 × S_structure                                  │   │
│  │     │         + 0.3 × S_identifier                                 │   │
│  │     │         + 0.2 × S_keyword                                    │   │
│  │     │                                                               │   │
│  │     │   S_structure:  SequenceMatcher 编辑距离                      │   │
│  │     │   S_identifier: 变量名/函数名 Jaccard 系数                    │   │
│  │     │   S_keyword:    去空格后关键字序列匹配                        │   │
│  │     │                                                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─── AI 模块 (可选, 标注 🤖) ─────────────────────────────────────────┐   │
│  │                                                                     │   │
│  │   llm_analyzer.py               ai_patch_generator.py              │   │
│  │     │                             │                                 │   │
│  │     │  LLMAnalyzer                │  AIPatchGenerator              │   │
│  │     │  验证差异根因分析           │  最小化修改补丁生成             │   │
│  │     │                             │                                 │   │
│  │     │  用于 validate 命令         │  用于 DryRun L5               │   │
│  │     │  解释预期 vs 实际偏差       │  mainline + target → patch     │   │
│  │     │                             │                                 │   │
│  │     └─────────────┬───────────────┘                                 │   │
│  │                   │                                                 │   │
│  │                   ▼                                                 │   │
│  │        OpenAI 兼容 API (DeepSeek / Azure / 本地部署)               │   │
│  │                                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─── 辅助模块 ────────────────────────────────────────────────────────┐   │
│  │                                                                     │   │
│  │   function_analyzer.py       search_report.py      config.py       │   │
│  │     │                          │                     │              │   │
│  │     │  FunctionAnalyzer        │  HunkSearchReport   │  ConfigLoader│   │
│  │     │  C 函数提取与分析        │  StrategyResult     │  YAML 配置   │   │
│  │     │  调用链追踪              │  搜索过程报告       │  管理        │   │
│  │     │                          │                     │              │   │
│  │   ui.py                                                            │   │
│  │     │                                                               │   │
│  │     │  Rich TUI 渲染引擎                                           │   │
│  │     │  ├─ StageTracker (实时进度)                                   │   │
│  │     │  ├─ render_report() (分析报告)                                │   │
│  │     │  ├─ render_validate_report() (验证报告 + DryRun 详情)        │   │
│  │     │  └─ render_benchmark_report() (基准测试)                     │   │
│  │     │                                                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. 外部依赖关系

```
                  ┌────────────────────────────────────────┐
                  │          CVE Backporting Engine         │
                  └──────────┬───────────────┬─────────────┘
                             │               │
              ┌──────────────┘               └──────────────┐
              │                                              │
    ┌─────────▼─────────┐                        ┌──────────▼──────────┐
    │  外部数据源 (只读)  │                        │  本地资源 (读写)     │
    │                    │                        │                     │
    │  MITRE CVE API     │                        │  Linux Kernel Repo  │
    │  (漏洞情报)        │                        │  (目标分支)          │
    │                    │                        │                     │
    │  git.kernel.org    │                        │  SQLite Cache DB    │
    │  (补丁获取)        │                        │  (commit_cache.db)  │
    │                    │                        │                     │
    │  googlesource.com  │                        │  Git Worktree       │
    │  (备选补丁源)      │                        │  (非破坏性验证)      │
    │                    │                        │                     │
    │  LLM API 🤖       │                        │  临时文件           │
    │  (可选, AI辅助)    │                        │  (.patch 文件)      │
    │                    │                        │                     │
    └────────────────────┘                        └─────────────────────┘
```

---

## 6. 模块依赖图

```
cli.py ──────────────────────────────────────→ core/ui.py
  │                                                │
  └──→ pipeline.py                                 │ (Rich TUI)
         │                                         │
         ├──→ agents/crawler.py ──→ core/models.py ←────┘
         │         │
         │         └──→ core/git_manager.py ──→ SQLite + FTS5
         │
         ├──→ agents/analysis.py
         │         │
         │         ├──→ core/matcher.py ──────→ core/models.py
         │         │       │
         │         │       └──→ PathMapper
         │         │       └──→ CommitMatcher
         │         │       └──→ diff_containment()
         │         │
         │         └──→ core/git_manager.py
         │
         ├──→ agents/dependency.py
         │         │
         │         ├──→ core/matcher.py
         │         │       └──→ extract_hunks_from_diff()
         │         │       └──→ compute_hunk_overlap()
         │         │
         │         └──→ core/git_manager.py
         │
         └──→ agents/dryrun.py
                   │
                   ├──→ core/code_matcher.py
                   │       └──→ CodeMatcher (语义匹配)
                   │       └──→ PatchContextExtractor
                   │
                   ├──→ core/matcher.py
                   │       └──→ PathMapper
                   │
                   ├──→ core/search_report.py
                   │       └──→ HunkSearchReport
                   │
                   ├──→ core/function_analyzer.py
                   │       └──→ FunctionAnalyzer
                   │
                   ├──→ core/ai_patch_generator.py  🤖
                   │
                   └──→ core/git_manager.py
```

---

## 7. 算法层级总览

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            算法分层架构                                      │
│                                                                             │
│  ╔═════════════════════════════════════════════════════════════════════════╗ │
│  ║  情报层 (Intelligence)                                                 ║ │
│  ║                                                                        ║ │
│  ║    三级补丁源回退: kernel.org/stable → kernel.org/torvalds             ║ │
│  ║                    → googlesource → 本地 git show                     ║ │
│  ║    部分结果互补合并                                                    ║ │
│  ╚════════════════════════════════╤════════════════════════════════════════╝ │
│                                   │                                         │
│  ╔════════════════════════════════▼════════════════════════════════════════╗ │
│  ║  搜索层 (Search)                                                       ║ │
│  ║                                                                        ║ │
│  ║    L1  Commit ID 精确匹配    O(1)   100% 置信                         ║ │
│  ║    L2  Subject 语义匹配      O(N)   FTS5 加速, SequenceMatcher        ║ │
│  ║    L3  Diff 代码匹配         O(NK)  文件重合 + 双向相似度/包含度       ║ │
│  ║                                                                        ║ │
│  ║    辅助: PathMapper 跨版本路径翻译                                     ║ │
│  ║    辅助: Diff 包含度 (Multiset, 检测 squash 场景)                      ║ │
│  ╚════════════════════════════════╤════════════════════════════════════════╝ │
│                                   │                                         │
│  ╔════════════════════════════════▼════════════════════════════════════════╗ │
│  ║  依赖层 (Dependency)                                                   ║ │
│  ║                                                                        ║ │
│  ║    Hunk 行范围重叠分析                                                 ║ │
│  ║    函数名交集检测                                                      ║ │
│  ║    三级评分: 强 (重叠+函数) / 中 (相邻|函数) / 弱 (文件级)             ║ │
│  ║    Fixes: 标签链追踪                                                   ║ │
│  ╚════════════════════════════════╤════════════════════════════════════════╝ │
│                                   │                                         │
│  ╔════════════════════════════════▼════════════════════════════════════════╗ │
│  ║  应用层 (Application)          五级自适应 DryRun                        ║ │
│  ║                                                                        ║ │
│  ║    L0  Strict            git apply --check                            ║ │
│  ║    L1  Context-C1        git apply --check -C1                        ║ │
│  ║    L2  3-Way Merge       git apply --check --3way                     ║ │
│  ║    L3  Regenerated  ⭐   锚点行定位 + 七策略搜索 + context 重建       ║ │
│  ║    L4  Conflict-Adapted  逐 hunk 冲突分析 + 目标行替换                 ║ │
│  ║    L5  AI-Generated 🤖  LLM 辅助最小化补丁生成 (可选)                ║ │
│  ║                                                                        ║ │
│  ║    L3 子算法:                                                          ║ │
│  ║      七策略序列搜索: 精确序列 → 锚点行 → 函数作用域 → 行号窗口        ║ │
│  ║                     → 全局模糊 → 分段 context → 逐行投票              ║ │
│  ║      跨 Hunk 偏移传播: offset_n = offset_{n-1} + Δ                   ║ │
│  ║      代码语义匹配: 结构×0.5 + 标识符×0.3 + 关键字×0.2                 ║ │
│  ╚════════════════════════════════╤════════════════════════════════════════╝ │
│                                   │                                         │
│  ╔════════════════════════════════▼════════════════════════════════════════╗ │
│  ║  验证层 (Validation)                                                   ║ │
│  ║                                                                        ║ │
│  ║    Git Worktree 非破坏性回退                                           ║ │
│  ║    P/R/F1 量化评估                                                     ║ │
│  ║    LLM 根因分析 🤖 (可选)                                             ║ │
│  ╚════════════════════════════════════════════════════════════════════════╝ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. CLI 命令与数据流映射

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  命令                         触发的 Agent 链路                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  analyze --cve X --target T   Crawler → Analysis → Dependency → DryRun     │
│                                (完整 Pipeline)                              │
│                                                                             │
│  check-intro --cve X -t T     Crawler → Analysis (仅引入commit搜索)        │
│                                                                             │
│  check-fix --cve X -t T       Crawler → Analysis (仅修复commit搜索)        │
│                                                                             │
│  validate --cve X -t T        Crawler → Analysis → Dependency → DryRun     │
│    --known-fix <commit>        + 结果与 known-fix 对比 + LLM 分析 🤖       │
│                                                                             │
│  benchmark --file F -t T      批量 validate + P/R/F1 统计                  │
│                                                                             │
│  build-cache --target T       GitRepoManager.build_cache()                 │
│                                (构建 SQLite + FTS5 索引)                    │
│                                                                             │
│  search --commit C -t T       Analysis (多策略搜索, 非短路)                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 9. 文件组织结构

```
cve_backporting/
│
├── cli.py                      # CLI 入口 + TUI 交互
├── pipeline.py                 # Pipeline 编排器 (4 Agent 串联)
│
├── agents/                     # 业务 Agent 层
│   ├── __init__.py
│   ├── crawler.py              # 情报采集 (MITRE + kernel.org)
│   ├── analysis.py             # 三级 Commit 搜索
│   ├── dependency.py           # 前置依赖分析
│   └── dryrun.py               # 五级自适应补丁试应用
│
├── core/                       # 基础设施层
│   ├── __init__.py
│   ├── models.py               # 所有数据模型 (dataclass)
│   ├── config.py               # YAML 配置管理
│   ├── git_manager.py          # Git 操作 + SQLite/FTS5 缓存
│   ├── matcher.py              # 相似度匹配 + PathMapper + 依赖图
│   ├── code_matcher.py         # 代码语义匹配 (多维评分)
│   ├── function_analyzer.py    # C 函数分析 + 调用链
│   ├── search_report.py        # 搜索过程详细报告
│   ├── llm_analyzer.py         # LLM 差异分析 🤖
│   ├── ai_patch_generator.py   # AI 补丁生成 🤖
│   └── ui.py                   # Rich TUI 渲染引擎
│
├── tests/                      # 测试
│   └── test_agents.py
│
├── docs/                       # 文档
│   ├── TECHNICAL.md            # 技术文档
│   ├── ADAPTIVE_DRYRUN.md      # 五级自适应算法详解
│   ├── MULTI_LEVEL_ALGORITHM.md# 多级算法参考手册
│   ├── arch.md                 # 架构全景图 (本文)
│   └── presentation.md         # 领导汇报 PPT 大纲
│
├── config.yaml                 # 运行配置
├── requirements.txt            # Python 依赖
└── README.md                   # 项目说明
```

---

## 10. 关键设计决策

```
┌───────────────────────┬──────────────────────────────────────────────────────┐
│  设计决策              │  原因                                                │
├───────────────────────┼──────────────────────────────────────────────────────┤
│  4-Agent Pipeline     │  关注点分离, 每个 Agent 可独立测试和替换              │
│  短路搜索模式         │  L1 命中即返回, 避免不必要的 L2/L3 计算开销          │
│  SQLite + FTS5 缓存   │  千万级 commit 仓库, 避免每次 git log 的秒级延迟     │
│  PathMapper 双向映射   │  内核版本间子系统路径迁移 (如 cifs→smb) 是常态       │
│  Multiset 包含度       │  企业仓库 squash commit 导致传统 diff 比较失效       │
│  七策略序列搜索        │  企业仓库在 mainline 代码间大量插入自定义代码         │
│  跨 Hunk 偏移传播     │  前序 hunk 的偏移量是后续 hunk 定位的重要先验         │
│  AI 标注为可选 🤖     │  确定性算法优先, AI 仅作为最终兜底, 降低不确定性      │
│  Git Worktree 验证     │  非破坏性, 不影响主工作区状态                        │
│  回调驱动 TUI         │  Pipeline 通过 on_stage 回调解耦 UI, 支持 CLI/API    │
└───────────────────────┴──────────────────────────────────────────────────────┘
```
