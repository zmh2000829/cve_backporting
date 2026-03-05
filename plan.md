# 优化计划

基于项目当前全部代码的审阅，总结已完成的迭代成果，并提出下一阶段优化方向。

---

## 已完成迭代总览

### Phase 0 — 基础模块化与核心流程 ✅

| 完成项 | 说明 |
|--------|------|
| 四 Agent 模块化 | Crawler / Analysis / Dependency / DryRun 独立分层 |
| Pipeline 编排 | 五阶段全链路串联（情报→引入→修复→依赖→DryRun）|
| 三级搜索引擎 | L1 ID → L2 Subject → L3 Diff，短路优化 |
| SQLite + FTS5 缓存 | 千万级 commit 流式构建，50K 批写入 + WAL + mmap |
| Rich CLI 交互 | 阶段追踪、进度条、彩色报告面板 |

### Phase 1 — 依赖分析精细化与 UI 增强 ✅

| 完成项 | 说明 |
|--------|------|
| 时间窗口约束 | `search_by_files(after_ts, no_merges)` 限定搜索范围 |
| Hunk 级重叠分析 | `extract_hunks_from_diff` + `compute_hunk_overlap`，行级精确比对 |
| 三级依赖分级 | 强（hunk 直接重叠）/ 中（相邻 ±50 行）/ 弱（同文件），评分公式量化 |
| 前置依赖详情表 | Rich Table 展示 commit/score/hunk 重叠/函数列表 |
| DryRun 冲突详情 | `--stat` 统计 + 冲突文件列表 + 错误行号 |
| 搜索过程可视化 | `SearchStep` 记录 L1→L2→L3 每级状态/耗时 |
| 版本映射展示 | CVE 影响版本-commit 映射表 |

### Phase 2 — 核心算法增强 ✅

| 完成项 | 说明 |
|--------|------|
| Diff Containment 算法 | Multiset 单向包含度，解决 squash commit 场景（传统相似度 ~30% → 包含度 95%+）|
| `use_containment` 场景区分 | 引入搜索启用包含度，修复搜索仅用双向相似度 |
| PathMapper 跨版本路径映射 | 8 组内置规则 + 自定义扩展，`expand_files` / `normalize_for_compare` 双向翻译 |
| 多源补丁获取 | `git.kernel.org` → `googlesource.com`（重试）→ 本地 Git，三级回退 + `_merge_patch` 互补 |
| check-intro 命令 | 独立漏洞引入检测，三级策略不短路全展示 |
| check-fix 命令 | 独立修复补丁检测，CVE 模式自动提取 mainline + stable backport |
| `search_detailed` 参数化 | `use_containment` 参数控制 L3 策略语义 |
| 增量缓存构建 | `get_latest_cached_commit` + `latest..branch` 增量拉取，rebase 自动降级 |
| 配置清理 | 移除 `MatchingConfig` / `DependencyConfig` / `PerformanceConfig` 等无用配置类 |

---

## P0 — 验证框架与准确度度量 ✅ 已完成

### 核心问题

工具对"未修复 CVE"给出的前置依赖推荐**无法验证准确性**，因为只有已修复的 CVE 才有分析人员真实合入的 patch 作为真值。需要一套机制：**利用已修复 CVE 反向验证工具输出，量化工具的置信度。**

### 实现状态

**已完成（方案 A: git worktree）**，验证通过：

- `validate` 命令：基于 `git worktree add --detach` 创建修复前工作区，运行完整 Pipeline，对比修复检测/引入检测/DryRun/前置依赖
- `benchmark` 命令：从 YAML 文件批量验证，汇总 Precision/Recall/F1/搜索策略分布
- `render_validate_report` / `render_benchmark_report` Rich 面板渲染
- 前置依赖比较支持 ID 精确匹配 + Subject 相似度匹配（80% 阈值）
- CVE 数据不完整时正确识别并报告 "CVE上游数据不完整"
- **实测验证**：CVE-2024-26633 (ip6_tunnel) 全部检查项 PASS（修复检测 ✔、引入检测 L1 ✔、DryRun ✔）

---

### P0.1 — `validate` 命令：基于已修复 CVE 的回退验证

**场景：** 选取一个已修复的 CVE，将仓库回退到修复前状态，运行工具分析，将工具推荐的结果与**真实合入记录**进行对比。

#### 核心设计

```
输入:
  --cve CVE-2024-26633
  --target 5.10-hulk
  --known-fix <本地仓库中实际合入修复的 commit ID>
  --known-prereqs <实际先合入的前置 commit 列表> (可选, 逗号分隔)

执行流程:
  ┌────────────────────────────────────────────────┐
  │ Step 1: 验证 known-fix 存在于目标分支           │
  │         git merge-base --is-ancestor            │
  └──────────────┬─────────────────────────────────┘
                 ▼
  ┌────────────────────────────────────────────────┐
  │ Step 2: 创建回退工作区                          │
  │   方案A: git worktree add /tmp/validate-xxx     │
  │          known_fix~1                            │
  │   方案B: 虚拟HEAD (修改搜索范围为 known_fix~1)   │
  └──────────────┬─────────────────────────────────┘
                 ▼
  ┌────────────────────────────────────────────────┐
  │ Step 3: 在"修复前"状态运行完整分析              │
  │   Crawler → Analysis → Dependency → DryRun      │
  │   预期:                                         │
  │     - 修复搜索应返回"未合入"                    │
  │     - 引入搜索应返回"已引入"(如有引入commit)    │
  │     - Dependency 给出前置依赖列表               │
  │     - DryRun 检测补丁是否可干净应用             │
  └──────────────┬─────────────────────────────────┘
                 ▼
  ┌────────────────────────────────────────────────┐
  │ Step 4: 对比工具输出 vs 真实合入记录            │
  │   对比项见下方"度量指标"                       │
  └──────────────┬─────────────────────────────────┘
                 ▼
  ┌────────────────────────────────────────────────┐
  │ Step 5: 清理 worktree / 恢复状态               │
  └────────────────────────────────────────────────┘
```

#### 实现方案对比

| 方案 | 原理 | 优点 | 缺点 |
|------|------|------|------|
| **A: git worktree (推荐)** | `git worktree add` 在 `known_fix~1` 创建轻量工作区，指向修复前状态 | 非破坏性、可并行、现有代码无需改动（仅改 config 路径） | 需要额外磁盘空间（但 worktree 共享 .git 对象库，开销小）；缓存需为 worktree 单独构建 |
| **B: 虚拟HEAD** | `GitRepoManager` 增加 `effective_head` 参数，所有 `git log branch` 替换为 `git log known_fix~1` | 无额外磁盘、无需新缓存 | 侵入性强，需修改 `search_by_subject`/`search_by_files`/`find_commit_by_id` 等所有搜索方法；缓存含修复后 commit 需过滤 |
| **C: checkout 回退** | `git checkout known_fix~1` 后运行，结束后 `checkout` 回来 | 最简单 | 破坏性操作、不能并行、中断后需手动恢复 |

**推荐方案 A（git worktree）**，理由：
- 现有 Pipeline / Agent 代码完全不需要改动
- 只需要在 `validate` 命令中：创建 worktree → 构造新 config 指向 worktree 路径 → 调用现有 Pipeline → 比对结果 → 清理
- worktree 共享 `.git` 对象库，创建和删除都是秒级

#### CLI 设计

```bash
# 单个 CVE 验证
python cli.py validate \
  --cve CVE-2024-26633 \
  --target 5.10-hulk \
  --known-fix abc123def456 \
  --known-prereqs "commit1,commit2,commit3"

# 批量验证（从 YAML 文件）
python cli.py benchmark \
  --file benchmarks.yaml \
  --target 5.10-hulk
```

---

### P0.2 — `benchmark` 命令：批量准确度度量

**场景：** 收集 N 个已修复 CVE 的真实合入记录，批量运行回退验证，计算工具整体准确度。

#### 基准数据集格式 (`benchmarks.yaml`)

```yaml
benchmarks:
  - cve_id: CVE-2024-26633
    known_fix_commit: abc123def456       # 本地仓库中真实修复的 commit
    known_prereqs:                       # 可选: 真实先合入的前置 commit
      - 111222333444
      - 555666777888
    notes: "ip6_tunnel 漏洞, 分析人员实际合入了2个前置补丁"

  - cve_id: CVE-2024-50154
    known_fix_commit: def456789012
    known_prereqs: []                    # 空列表 = 直接合入无前置
    notes: "可直接 cherry-pick, 无冲突"

  - cve_id: CVE-2025-71235
    known_fix_commit: 789012abc345
    # 不提供 known_prereqs = 只验证搜索准确性, 不验证依赖
```

#### 度量指标体系

```
单个 CVE 验证指标:
┌─────────────────────────────────────────────────────────────┐
│ 1. 引入检测                                                 │
│    intro_correct: 工具是否正确识别"漏洞已引入"               │
│    intro_commit_match: 引入commit定位是否匹配(L1/L2/L3命中)  │
│                                                             │
│ 2. 修复检测 (回退后)                                        │
│    fix_correctly_absent: 在修复前状态是否正确返回"未合入"    │
│    (这一项应该100%正确, 否则说明回退机制有bug)               │
│                                                             │
│ 3. 前置依赖 (需提供 known_prereqs)                          │
│    precision = |推荐 ∩ 真实| / |推荐|  (推荐中有多少是对的) │
│    recall    = |推荐 ∩ 真实| / |真实|  (真实的有多少被找到)  │
│    grade_accuracy: 强依赖是否确实是真实需要的                 │
│    false_positives: 工具推荐但实际不需要的 commit 列表       │
│    false_negatives: 实际需要但工具未推荐的 commit 列表       │
│                                                             │
│ 4. DryRun 准确性                                            │
│    conflict_prediction: 在修复前状态,                        │
│      若DryRun报告冲突 → 验证是否确实需要前置补丁             │
│      若DryRun报告干净 → 验证是否确实可以直接合入             │
└─────────────────────────────────────────────────────────────┘

批量汇总指标:
┌─────────────────────────────────────────────────────────────┐
│ 引入检测准确率 = 正确识别引入的CVE数 / 总CVE数              │
│ 修复检测准确率 = 正确返回"未合入"的CVE数 / 总CVE数          │
│ 前置依赖平均精确率 (Avg Precision)                          │
│ 前置依赖平均召回率 (Avg Recall)                             │
│ 前置依赖 F1-Score = 2 × P × R / (P + R)                    │
│ DryRun 预测准确率                                           │
│ 各级搜索命中率分布 (L1/L2/L3/未命中)                       │
└─────────────────────────────────────────────────────────────┘
```

#### CLI 输出设计

```
╭──────────────────── Benchmark Report ────────────────────╮
│                                                          │
│  基准集: 12 个 CVE, 目标: 5.10-hulk                      │
│                                                          │
│  引入检测准确率:      11/12  (91.7%)                     │
│  修复检测准确率:      12/12 (100.0%)                     │
│  前置依赖精确率:       8/10  (80.0%)                     │
│  前置依赖召回率:       7/10  (70.0%)                     │
│  前置依赖 F1:                (74.4%)                     │
│  DryRun 预测准确率:    9/12  (75.0%)                     │
│                                                          │
│  搜索策略分布:                                           │
│    L1 命中: 3 (25%)  L2 命中: 7 (58%)                    │
│    L3 命中: 1 (8%)   未命中: 1 (8%)                      │
│                                                          │
╰──────────────────────────────────────────────────────────╯

╭─ Per-CVE Detail ─────────────────────────────────────────╮
│ # │ CVE              │ Intro │ Fix │ Prec │ Recall│ DryRun│
│ 1 │ CVE-2024-26633   │  ✔    │  ✔  │ 100% │  67%  │  ✔   │
│ 2 │ CVE-2024-50154   │  ✔    │  ✔  │ 100% │ 100%  │  ✔   │
│ 3 │ CVE-2025-71235   │  ✘    │  ✔  │  -   │   -   │  ✘   │
│ ...                                                      │
╰──────────────────────────────────────────────────────────╯
```

#### 对比逻辑核心算法

```python
def compare_prereqs(recommended: List[str], actual: List[str]) -> dict:
    """
    recommended: 工具推荐的前置 commit ID 列表
    actual:      真实合入的前置 commit ID 列表
    比较时使用 short_id (前12位) 匹配
    """
    rec_set = {c[:12] for c in recommended}
    act_set = {c[:12] for c in actual}

    tp = rec_set & act_set          # 正确推荐
    fp = rec_set - act_set          # 误报 (推荐了但实际不需要)
    fn = act_set - rec_set          # 漏报 (需要但未推荐)

    precision = len(tp) / len(rec_set) if rec_set else 1.0
    recall = len(tp) / len(act_set) if act_set else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "true_positives": sorted(tp),
        "false_positives": sorted(fp),
        "false_negatives": sorted(fn),
    }
```

#### 实现步骤拆解

| 步骤 | 内容 | 状态 |
|------|------|------|
| 0.1 | `GitRepoManager` 增加 `create_worktree` / `remove_worktree` 方法 | ✅ 完成 |
| 0.2 | `cli.py` 新增 `validate` 命令，单 CVE 回退验证 + 对比报告 | ✅ 完成 |
| 0.3 | `cli.py` 新增 `benchmark` 命令，批量验证 + 汇总统计 | ✅ 完成 |
| 0.4 | `core/ui.py` 新增 `render_validate_report` / `render_benchmark_report` | ✅ 完成 |
| 0.5 | 提供 `benchmarks.example.yaml` 示例 + 文档更新 | ✅ 完成 |
| 0.6 | 收集首批 5-10 个已修复 CVE 构建初始基准集 | 需业务配合 |

#### 已验证的技术决策

1. **worktree 缓存策略**：worktree 使用 `use_cache=False`，避免缓存污染。单次验证约 30-40s，性能可接受
2. **分支指定**：worktree 内 `branch="HEAD"` 确保 `git merge-base --is-ancestor` 正确排除修复后 commit
3. **回滚点计算**：无 prereqs 时用 `known_fix~1`；有 prereqs 时自动找最早 prereq 的父节点
4. **前置依赖比较**：同时使用 ID 前缀匹配 (12 chars) 和 Subject 相似度匹配 (≥80%)，覆盖 cherry-pick ID 偏移场景
5. **CVE 数据缺失处理**：MITRE API 无 fix commit 时标记 "CVE上游数据不完整" 而非误报 FAIL

---

## 当前遗留问题

### 1. `normalize_subject` 前缀处理不够灵活

**现状：** 使用固定列表 `[backport]`、`[stable]`、`backport:` 等匹配前缀，且只去除第一个命中。

**问题：** 企业内核 commit 常有自定义前缀如 `[hulk]`、`[PATCH v2]`、`UPSTREAM:` 等，当前无法处理；多个前缀叠加时只去除第一个。

### 2. FTS5 关键词搜索过于严格

**现状：** `_cache_fts` 使用 `" AND ".join(kws)` 连接关键词。

**问题：** 当 backport 对 subject 做了较大修改（删字/加字）时，AND 连接要求全部命中，容易漏掉。

### 3. L3 性能瓶颈

**现状：** 每个候选 commit 都执行 `git show` 获取完整 diff（100 个候选 = 100 次 git show）。

**问题：** 频繁的 git show 在大仓库中单次 ~50ms，批量候选时显著拖慢 L3 搜索。

### 4. Stable backport 版本匹配硬编码

**现状：** `_try_stable_backport` 中硬编码 `ver.startswith("5.10")`。

**问题：** 当目标仓库基于 6.x 或其他版本时无法正确匹配。

### 5. `verify=False` 散布于代码

**现状：** `agents/crawler.py` 中 3 处 `requests.get(..., verify=False)`。

**问题：** 安全风险，且未从配置项控制。

### 6. 阈值硬编码

**现状：** L2 阈值 `0.85`、L3 阈值 `0.70` 硬编码在 `agents/analysis.py` 中。

**问题：** 不同仓库的 commit message 风格不同，阈值应可配置微调。

### 7. Fixes 标签链未递归追踪

**现状：** 依赖分析只提取第一层 `Fixes:` 标签引用。

**问题：** 内核社区常见 A fixes B, B fixes C 的链式引用，当前只排除了直接引用。

---

## 下一阶段优化方向

### P2 — 搜索质量增强

| 编号 | 项目 | 描述 | 复杂度 |
|------|------|------|--------|
| 2.1 | `normalize_subject` 正则化 | 用正则 `re.sub(r'\[.*?\]', '', s)` 去除所有方括号前缀；增加 `UPSTREAM:`、`FROMLIST:` 等常见前缀；支持 config 自定义前缀列表 | 低 |
| 2.2 | FTS5 搜索改 OR + 权重 | 关键词用 OR 连接，命中越多得分越高；对前 3 个关键词给更高权重（通常是函数名/模块名）| 中 |
| 2.3 | L3 延迟 diff 获取 | 先用 `git show --stat` 预过滤（修改文件数差异过大的直接跳过），再按 subject 预排序取 top N 执行完整 diff | 中 |
| 2.4 | diff LRU 内存缓存 | `get_commit_diff` 加 `functools.lru_cache`，避免 analysis + dependency 重复获取同一 commit diff | 低 |

### P2 — Pipeline 通用化

| 编号 | 项目 | 描述 | 复杂度 |
|------|------|------|--------|
| 3.1 | Stable backport 版本自动匹配 | 从 config 的 `branch` 字段提取版本前缀（如 `linux-5.10.y` → `5.10`），替代硬编码 | 低 |
| 3.2 | 引入 commit 缺失的降级策略 | 无引入 commit 时，使用版本范围（`affected.versions.lessThan`）做范围判定，而非默认标记为受影响 | 中 |
| 3.3 | on_stage 细粒度回调 | Crawler 区分"获取 MITRE" / "获取 patch"；Analysis L2 显示"N 个候选，比对中..."；Dependency 显示"分析第 M/N 个" | 低 |

### P3 — 代码质量与健壮性

| 编号 | 项目 | 描述 | 复杂度 |
|------|------|------|--------|
| 4.1 | `verify=False` 可配置 | 新增 `config.network.ssl_verify` 配置项，默认 `true`，内网环境可关闭 | 低 |
| 4.2 | 阈值配置化 | L2 subject 阈值、L3 diff 阈值、依赖评分阈值从 `config.yaml` 读取 | 低 |
| 4.3 | SQLite 连接池 | 使用持久连接或 `threading.local` 线程级连接复用，减少连接开销 | 中 |
| 4.4 | Fixes 标签链递归 | 递归追踪 `Fixes:` 引用（限深 3 层），将整条链上的 commit 加入排除列表 | 中 |
| 4.5 | 异常处理规范化 | 消除裸 `except Exception: pass`，统一使用 `logger.debug` 记录 | 低 |
| 4.6 | `check_commit_existence` 返回值类型化 | 返回 NamedTuple 替代裸 tuple，提升可读性 | 低 |

### P4 — 扩展能力

| 编号 | 项目 | 描述 | 复杂度 |
|------|------|------|--------|
| 5.1 | 批量 CVE 报告 | `analyze --batch` 生成汇总 HTML/Markdown 报告，含统计图表 | 高 |
| 5.2 | CI/CD 集成模式 | `--json` 输出格式 + 非零退出码（有未修复 CVE 时 exit 1），便于流水线集成 | 中 |
| 5.3 | 多仓库并行 | 支持同时分析多个目标版本（如 5.10-hulk 和 6.6-hulk），结果对比展示 | 高 |
| 5.4 | CVE 订阅与增量扫描 | 接入 linux-cve-announce 邮件列表或 RSS，自动触发新 CVE 分析 | 高 |
| 5.5 | Web Dashboard | 轻量 FastAPI + 前端面板，展示 CVE 修复状态看板 | 高 |

---

## 建议执行路径

```
最高优先 (P0, 1-2 周):
  ├─ 0.1 GitRepoManager 增加 worktree 管理方法 (半天)
  ├─ 0.2 validate 命令: 单 CVE 回退验证 + 对比报告 (2天)
  ├─ 0.3 benchmark 命令: 批量验证 + 汇总统计 (1天)
  ├─ 0.4 render_benchmark_report UI 渲染 (半天)
  ├─ 0.5 benchmarks.example.yaml + 文档 (半天)
  └─ 0.6 收集首批 5-10 个已修复 CVE 构建基准集 (需业务配合)

近期 (P2, 2-3 周):
  ├─ 2.1 normalize_subject 正则化 (半天)
  ├─ 2.4 diff LRU 缓存 (半天)
  ├─ 3.1 Stable backport 版本自动匹配 (半天)
  └─ 4.1 + 4.2 verify 可配置 + 阈值配置化 (半天)

中期 (P2-P3, 3-5 周):
  ├─ 2.2 FTS5 搜索改 OR + 权重
  ├─ 2.3 L3 延迟 diff 获取
  ├─ 3.2 引入 commit 缺失降级策略
  ├─ 4.4 Fixes 标签链递归
  └─ 4.5 异常处理规范化

远期 (P4):
  ├─ 5.2 CI/CD 集成模式
  ├─ 5.1 批量报告
  └─ 5.4 + 5.5 CVE 订阅 / Web Dashboard
```
