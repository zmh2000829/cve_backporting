# 项目计划与技术原理

---

## 一、项目完成状态总览

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

### Phase 2 — 核心算法增强 ✅

| 完成项 | 说明 |
|--------|------|
| Diff Containment 算法 | Multiset 单向包含度，解决 squash commit 场景（传统相似度 ~30% → 包含度 95%+）|
| PathMapper 跨版本路径映射 | 8 组内置规则 + 自定义扩展 |
| 多源补丁获取 | `git.kernel.org` → `googlesource.com` → 本地 Git，三级回退 |
| check-intro / check-fix 独立命令 | 独立漏洞引入/修复检测 |
| 增量缓存构建 | `get_latest_cached_commit` + 增量拉取 |

### Phase 3 — 多级自适应 DryRun 引擎 ✅

| 完成项 | 说明 |
|--------|------|
| L0-L4 六级自适应 | strict → C1 → 3way → regenerated → conflict-adapted |
| L5 Verified-Direct | 绕过 git apply，内存级直接验证 |
| L3.5 Zero-Context | 零上下文 diff，仅保留 ±行 |
| 符号/宏映射 | 自动检测重命名并替换 |
| 缩进适配 | tab↔space 自动调整 |

### Phase 4 — 批量验证与 CVE 级聚合 ✅

| 完成项 | 说明 |
|--------|------|
| batch-validate 命令 | 从 JSON 批量运行 validate，实时 JSON 报告 |
| CVE 级聚合 | 自动识别主修复 vs 前置补丁 |
| 前置补丁交叉验证 | 工具推荐 vs 已知真值的 Precision/Recall |

### Phase 5 — 分析过程可视化 ✅

| 完成项 | 说明 |
|--------|------|
| Analysis Narrative | 结构化 JSON 叙述工具的分析逻辑和结论 |
| 集成 validate / batch-validate | 验证模式额外包含补丁质量评估 |

### Phase 6 — Validate 模式修复 ✅

| 完成项 | 说明 |
|--------|------|
| force_dryrun | 确保 validate 模式下 DryRun 始终执行 |
| worktree 假阳性修正 | `git merge-base --is-ancestor` 替代 subject_match |

### Phase 7 — v2.0 深度分析能力 ✅

| 完成项 | 说明 |
|--------|------|
| 统一 LLM 客户端 | `LLMClient` 封装 chat/chat_json，确定性兜底 |
| VulnAnalysisAgent | 漏洞类型分类、根因分析、触发路径、检测方法 |
| CommunityAgent | lore.kernel.org + bugzilla + CVE 引用链接收集 |
| PatchReviewAgent | 函数映射、调用拓扑、数据结构检测、安全模式检视 |
| RiskBenefitAnalyzer | 四维量化 + 文字等级描述（无裸数值） |
| MergeAdvisorAgent | 规则引擎 + 关联补丁完整分析 + 检视 checklist |
| 关联补丁完整分析 | 前置/后置补丁无论有无都给出分析理由和结论 |
| --deep 标志集成 | analyze / validate / batch-validate 均支持 --deep |
| C 函数名提取修复 | 跳过 static/int/void 等噪声词，正确提取函数名 |
| TUI 面板增强 | 关联补丁分析面板、风险收益文字描述面板 |

### Phase 8 — L0-L5 分级编排与可插拔规则引擎 ✅（本轮新增）

| 完成项 | 说明 |
|--------|------|
| L0-L5 统一分级判定 | 基于 DryRun 方法映射 `strict→L0`、`context-C1→L1`、`3way→L2`、`regenerated→L3`、`conflict-adapted→L4`、`verified-direct→L5` |
| 分级策略文案 | `level_decision.strategy` / `reason` 区分 L0~L5 含义；**仅 L0 且无 high/warn 规则** 才 `harmless=true` |
| 无害判定收敛 | L1 不自动无害；与 `l1_api_surface`、大改动、扇出、关键结构规则联动 |
| 调用链影响分析 | 修改文件范围内 **跨文件** 符号边合并；callers/callees、扇出告警 |
| 大改动告警 | 按改动行数 / hunk 数阈值触发 warning |
| 关键结构变更告警 | 锁/RCU/refcount/struct 等关键词命中后提升风险 |
| L1 细粒度启发式 | 签名行增删不一致、`return` 行差阈值（可配置、可关闭） |
| 可插拔规则框架 | `RuleRegistry` + `policy.extra_rule_modules` 动态扩展 |
| Profile 预设 | `conservative` / `balanced` / `aggressive` / `default`，YAML 覆盖预设 |
| 输出可审计化 | `validation_details.rule_version=v2`；`level_decision`、`function_impacts`、`validation_details`、DryRun `apply_attempts` |
| 回归测试 | `tests/test_policy_engine.py` |
| TUI 报告增强 | 新增“策略分级判定”“函数影响分析”“DryRun 尝试轨迹”面板 |

---

## 三、下一步推进计划（更新版）

### P0（本周）— 稳定化与可回归验证 ✅（代码侧已落地）

1. **补齐规则引擎回归用例** ✅
   - `tests/test_policy_engine.py`：`unittest` 覆盖 L0 无害、L0+关键结构、大改动阈值、L1 签名启发式、跨文件扇出、`l1_api_surface` 可关闭、空 DryRun→L5、`POLICY_PROFILE_PRESETS` 存在性
   - 运行：`python -m unittest tests.test_policy_engine -v`
2. **完成 20+ CVE 小样本验证**
   - 指标：level 判定稳定性、warning 误报率（需在具名仓库与 CVE 清单上人工/批跑，本仓库不绑数据）
3. **统一报告字段 schema** ✅
   - `validation_details.rule_version` 递增至 **v2**（与 L1 规则、跨文件图、profile 合并行为对齐）；字段仍为 `level_decision` / `function_impacts` / `validation_details` / DryRun `apply_attempts`

### P1（2~4 周）— 策略质量提升 ✅（首版已合入，后续观测调参）

1. **L1 无害判定质量提升** ✅（首版）
   - 新增可插拔默认规则 `l1_api_surface`：签名行增删不一致、`return` 行数差阈值（`l1_return_line_delta_threshold`）
   - 编排上 **L1 仍不自动 `harmless`**，与专家「L0 才机械无害」一致
2. **调用链影响精度增强** ✅（首版）
   - 修改文件集合内 **跨文件符号边**：`FunctionAnalyzer.build_call_topology_extended` + `build_cross_file_call_graph`
   - 后续：全仓库符号索引 / 子系统白名单（见 P2）
3. **规则配置模板化** ✅
   - `core/config.py`：`POLICY_PROFILE_PRESETS`（`conservative` / `balanced` / `aggressive` / `default`），YAML 显式项覆盖预设；默认 `profile: balanced`（无 policy 节时与 dataclass 一致）

### P2（1~2 月）— 工程化落地

1. **CI 门禁集成**
   - L4/L5 + high severity rule 命中时自动要求人工审批
2. **规则插件生态**
   - 沉淀 `rules/` 目录规范，支持业务团队独立扩展
3. **专家答辩模板自动生成**
   - 基于 narrative 自动生成“证据链 + 结论边界 + 建议动作”文案

### 风险与对策

- **风险1：调用链分析受限于静态解析精度**
  - 对策：先用于 warning，不直接阻断；逐步引入跨文件符号索引
- **风险2：规则过多导致误报上升**
  - 对策：按 profile 分层启用，先观测再收紧
- **风险3：不同分支编码风格导致阈值不稳**
  - 对策：按仓库/子系统配置独立阈值

### 验收标准（下一里程碑）

- L0/L1/L2 判定与人工结论一致率 ≥ 90%
- 关键结构改动漏报率 ≤ 5%
- validate 报告可直接用于专家评审（无需二次补充核心证据）

---

## 四、核心技术原理：关联补丁发现逻辑

> 这是分析人员最关心的问题：工具怎么判断一个补丁需不需要先合入其他补丁？
> 没有关联补丁的时候，凭什么说"不需要"？

### 2.1 什么是关联补丁

在 Linux 内核 CVE 修复的回合 (backporting) 场景中，"关联补丁"指的是：

- **前置补丁 (Prerequisite Patch)**：修复补丁依赖的、必须先合入的其他补丁。缺少它们，修复补丁可能无法应用、无法编译、或产生语义错误。
- **后置补丁 (Post Patch)**：修复补丁合入之后，上游社区对同一修复的追加修正或增强。

前置补丁产生的根本原因是：**上游主线 (mainline) 和目标内核版本之间的代码已经产生了差异**。上游的修复补丁是基于最新主线写的，它默认周围的代码是最新状态。如果目标版本缺少某些中间改动，修复补丁就可能：

1. **文本层面冲突** — 补丁要删除的代码行在目标版本中不存在（已被其他补丁修改过），或要添加代码的上下文不匹配
2. **编译层面失败** — 补丁引用了新的数据结构字段、新的 API 函数、新的宏定义，这些是由前置补丁引入的
3. **语义层面错误** — 补丁能应用也能编译，但逻辑不正确，因为它假设了前置补丁已经改变的行为

### 2.2 前置补丁发现算法

工具通过以下流程检测前置补丁（`agents/dependency.py`）：

```
输入:
  - fix_patch: 社区修复补丁 (含 diff、修改的文件列表、commit message)
  - cve_info: CVE 信息 (含引入 commit、修复 commit)
  - target_version: 目标内核分支

                    ┌─────────────────────────────────┐
                    │ Step 1: 确定搜索范围 (时间窗口)    │
                    └──────────┬──────────────────────┘
                               ▼
                    ┌─────────────────────────────────┐
                    │ Step 2: 收集候选 commit           │
                    │   git log --follow 修改同文件     │
                    └──────────┬──────────────────────┘
                               ▼
                    ┌─────────────────────────────────┐
                    │ Step 3: 排除已知 commit           │
                    │   (fix commit / intro commit /   │
                    │    Fixes: 标签引用)               │
                    └──────────┬──────────────────────┘
                               ▼
                    ┌─────────────────────────────────┐
                    │ Step 4: Hunk 级精细分析           │
                    │   逐个候选 ←→ fix_patch 对比     │
                    └──────────┬──────────────────────┘
                               ▼
                    ┌─────────────────────────────────┐
                    │ Step 5: 评分与分级               │
                    │   strong / medium / weak         │
                    └─────────────────────────────────┘
```

#### Step 1: 时间窗口限定

如果漏洞的引入 commit (introduced commit) 已知，则只搜索**引入 commit 之后**的 commit。
理由：引入 commit 之前的修改不可能是修复补丁的前置依赖，因为修复补丁针对的是引入 commit 之后的代码状态。

```python
# 确定时间窗口起点
if intro_search and intro_search.target_commit:
    after_ts = intro_commit_timestamp  # 从引入时间开始
```

#### Step 2: 收集候选 commit

在目标分支上执行 `git log`，查找**修改了同一组文件**的 commit：

```python
intervening = git_mgr.search_by_files(
    modified_files,       # fix_patch 涉及的文件 (+ 路径映射扩展)
    target_version,       # 目标分支
    limit=50,             # 最多 50 个候选
    after_ts=after_ts,    # 时间窗口
    no_merges=True,       # 排除 merge commit
)
```

- **路径映射** (`PathMapper`)：内核代码经常重命名路径（如 `drivers/usb/core/` → `drivers/usb/common/`），工具通过 8 组内置映射规则 + 自定义扩展，将一个文件路径展开为一组等价路径来搜索
- **排除大重构**：修改超过 20 个文件的 commit 直接跳过，这类通常是 tree-wide 重构而非功能相关的前置补丁

#### Step 3: 排除已知 commit

从候选中排除：
- 修复 commit 本身
- 引入 commit 本身
- Fixes: 标签引用的 commit（这些是修复补丁的修复目标，不是前置依赖）

#### Step 4: Hunk 级精细分析

这是核心算法。对每个候选 commit，提取其 diff 的 hunk 信息，与 fix_patch 的 hunk 进行**行范围交叉比对**：

```python
# 每个 hunk 有: file, old_start, old_end, new_start, new_end
# 两种重叠判定:
#   直接重叠: 两个 hunk 的行范围在同一文件中有交集
#   相邻重叠: 行范围在 ±50 行内 (ADJACENT_MARGIN = 50)

for hunk_a in fix_hunks:
    for hunk_b in candidate_hunks:
        if 同一文件:
            if 行范围直接相交:
                direct_overlaps += 1    # 强信号: 候选补丁修改了修复补丁同一段代码
            elif 行范围在 ±50 行内:
                adjacent_overlaps += 1  # 中信号: 修改了相邻代码区域
```

同时提取函数级重叠：

```python
func_overlap = fix_functions ∩ candidate_functions
# 两个补丁修改了同一个函数 → 强信号
```

#### Step 5: 评分与三级分类

```
评分公式:
  score  = min(direct_overlaps × 0.3, 0.6)     # hunk 直接重叠权重最高
         + min(adjacent_overlaps × 0.1, 0.2)    # 相邻重叠次之
         + min(len(func_overlap) × 0.15, 0.3)   # 函数重叠

分级规则:
  strong  ← (direct_overlaps > 0 且 有函数重叠) 或 score ≥ 0.5
  medium  ← direct_overlaps > 0 或 adjacent_overlaps > 0 或 score ≥ 0.2
  weak    ← 其他 (仅同文件关联)
```

**strong (强依赖)** 的含义：候选补丁修改了与修复补丁**完全相同的代码行和函数**。这意味着修复补丁假设这些代码行处于候选补丁修改后的状态。不先合入该候选补丁，修复补丁大概率无法正确应用。

**medium (中依赖)** 的含义：候选补丁修改了修复补丁**附近的代码**（同文件、相邻行）。虽然不直接阻断修复补丁的应用，但可能影响上下文匹配或功能完整性。

**weak (弱关联)** 的含义：仅修改了同一文件，没有行级或函数级重叠。通常不影响合入，但提供了上下文信息。

### 2.3 "无前置补丁"的判定逻辑与解释

当工具报告"无前置补丁"时，**不是简单地返回空结果**，而是基于以下多维度分析得出结论：

#### 判定依据一：DryRun 可干净应用

```
如果修复补丁通过 DryRun (git apply) 在目标版本上干净应用:
  → 说明补丁的删除行在目标版本中确实存在 (上下文匹配)
  → 说明补丁的添加行可以正确插入 (行号偏移在可接受范围内)
  → 即: 目标版本在该补丁涉及的代码区域与上游主线是一致的
  → 结论: 不存在因"缺失前置补丁"导致的文本冲突
```

**DryRun 能干净应用是最强的"无需前置"信号**——如果中间有改动缺失，git apply 大概率会因上下文不匹配而拒绝应用。

#### 判定依据二：时间窗口内无候选

```
如果 git log 搜索在时间窗口内找不到修改同文件的其他 commit:
  → 说明从漏洞引入到当前版本，没有人动过修复补丁涉及的文件
  → 目标版本该文件的代码与上游是相同的
  → 结论: 无前置依赖
```

#### 判定依据三：修改范围集中

```
如果修复补丁仅修改 1-2 个文件、改动行数少:
  → 被其他补丁交叉依赖的概率低
  → 越是局部修改，越容易独立合入
```

#### 判定依据四：无新数据结构依赖

```
如果 PatchReview 分析发现补丁未引入新的数据结构 (struct 字段、锁变量、API):
  → 不依赖前置补丁提供这些定义
  → 可独立编译
```

#### 什么情况下 DryRun 能过但仍需前置补丁？

这是一个重要的边界情况，工具会明确说明：

> "尽管存在前置补丁，修复补丁本身可干净应用。这说明前置补丁提供的是**编译/运行时依赖** (如数据结构定义、API 声明)，而非文本层面的上下文冲突。"

典型场景：前置补丁在另一个头文件中新增了一个 struct 字段定义，修复补丁引用了这个字段。`git apply` 只检查 diff 上下文匹配，不检查编译依赖，所以补丁能 apply 但编译会失败。

工具通过 **Hunk 级分析 + 函数重叠检测** 来捕捉这类跨文件依赖。

### 2.4 后置补丁发现逻辑

后置补丁通过两种方式检测（`core/risk_benefit.py`）：

#### 方式一：Fixes 标签反查

```python
git log --grep="Fixes: <fix_commit_short_id>" --all
```

内核社区规范要求，如果一个补丁修复了另一个补丁引入的问题，必须在 commit message 中添加 `Fixes:` 标签。通过反向搜索引用了修复补丁 ID 的 commit，可以找到上游对本修复的追加修正。

**含义**：存在后续修复意味着社区发现原始修复不完善（如遗漏边界条件、引入回归），建议一并合入。

#### 方式二：同函数后续修改

```python
git log -S<func_name> -- <file_path>  # 在 fix 之后搜索修改同函数的 commit
```

查找修复补丁涉及的函数，是否有后续 commit 也修改了这些函数。

**含义**：同函数的后续修改可能是功能增强或独立修复，需评估是否影响本修复的正确性。

### 2.5 "无后置补丁"的含义

当报告"无后置补丁"时：

> "未检测到后续关联补丁，说明该修复在上游社区是自包含的，无需额外的追加修正。"

这意味着：
1. 没有任何后续 commit 通过 `Fixes:` 标签引用本修复 → 社区没有发现本修复有问题
2. 本修复涉及的函数在之后没有被其他安全修复修改 → 本修复是完备的

---

## 三、核心技术原理：补丁回合 (Backporting) 逻辑

### 3.1 整体流水线

```
CVE ID + 目标内核版本
  │
  ├─ Stage 1: Crawler (情报收集)
  │    ├─ 从 MITRE/NVD 获取 CVE 基本信息
  │    ├─ 从 linux-cve-announce 提取 mainline fix commit
  │    └─ 从 git.kernel.org / googlesource / 本地仓库获取补丁内容
  │
  ├─ Stage 2: Analysis (引入/修复检测)
  │    ├─ 引入检测: 漏洞引入 commit 是否存在于目标版本 → 是否受影响
  │    ├─ 修复检测: 修复 commit 是否已合入目标版本 → 是否已修复
  │    └─ Stable backport 检测: 是否有该版本的官方 backport
  │
  ├─ Stage 3: Dependency (前置依赖分析)
  │    └─ 如上 2.2 节所述
  │
  ├─ Stage 4: DryRun (多级自适应补丁试应用)
  │    └─ 如下 3.2 节所述
  │
  └─ Stage 5 (可选 --deep): 深度分析
       ├─ VulnAnalysis (漏洞类型/根因/触发)
       ├─ PatchReview (代码走读/安全检视)
       ├─ RiskBenefit (风险收益评估)
       └─ MergeAdvisor (合入建议)
```

### 3.2 多级自适应 DryRun

DryRun 是补丁回合的核心环节——验证社区补丁能否在目标版本上正确应用，并在可能时自动适配生成可用补丁。

```
L0: strict (git apply --check)
 │  原始补丁直接应用，3 行上下文完全匹配
 │  ✔ → 最高置信度，补丁可直接 cherry-pick
 │  ✘ ↓
L1: context-C1 (git apply -C1)
 │  降低上下文要求到 1 行，容忍少量行偏移
 │  ✔ → 高置信度，偏移通常是无关紧要的
 │  ✘ ↓
L2: 3way (git apply --3way)
 │  三路合并，利用 git 内置冲突解决
 │  ✔ → 中置信度，建议人工确认合并结果
 │  ✘ ↓
L5: verified-direct (Python 内存级)
 │  绕过 git apply:
 │    1. 读取目标文件内容
 │    2. 在内存中定位每个 hunk 的精确位置
 │    3. 应用修改 (删除行→添加行)
 │    4. difflib.unified_diff 生成新 patch
 │  ✔ → 中置信度，已验证每个 hunk 的语义正确性
 │  ✘ ↓
L3: regenerated (上下文重生成)
 │  从目标文件中重新提取 hunk 上下文:
 │    1. 定位 "-" 行在目标文件中的精确位置
 │    2. 用目标文件的真实上下文替换原始上下文
 │    3. 重新计算行号偏移
 │    4. 生成适配后的 patch
 │  ✔ → 中低置信度，上下文已重写
 │  ✘ ↓
L3.5: zero-context (零上下文)
 │  极端策略: 删除所有上下文行，仅保留 +/- 行
 │  配合 --unidiff-zero 应用
 │  ✔ → 低置信度，仅适用上下文严重损坏的场景
 │  ✘ ↓
L4: conflict-adapted (冲突适配)
 │  逐 hunk 分析冲突原因:
 │    - 符号/宏重命名 → 自动映射替换
 │    - 缩进风格差异 → 自动适配
 │    - 行偏移 → 重新定位
 │  ✔ → 低置信度，需人工审查适配结果
 │  ✘ ↓
失败 → 报告冲突详情，建议人工处理
```

### 3.3 什么时候需要看前置补丁，什么时候不需要

| 场景 | 是否需要前置 | 原因 |
|------|-------------|------|
| DryRun strict 通过 + 无前置补丁检出 | **不需要** | 补丁可直接应用，代码上下文完全一致 |
| DryRun 通过 (非 strict) + 无前置 | **基本不需要** | 有少量行偏移但已自动适配，不影响正确性 |
| DryRun 通过 + 有前置补丁检出 | **需要评估** | 补丁文本能应用，但可能依赖前置补丁的编译期/运行时改动 |
| DryRun 失败 + 有强依赖前置 | **需要** | 冲突原因可能是缺少前置补丁的代码改动 |
| DryRun 失败 + 无前置检出 | **需人工分析** | 目标版本与上游差异太大，可能需手动适配 |

**核心原则**：

1. **DryRun 是最直接的判据** — 如果补丁能在目标版本上干净应用，99% 的情况不需要前置补丁
2. **Hunk 重叠是最准确的依赖信号** — 两个补丁修改了同一段代码的同一行，几乎必然存在依赖
3. **函数重叠是补充信号** — 修改同一函数不一定有依赖，但值得关注
4. **"无前置"不等于没有分析** — 工具会解释为什么判定为无前置（DryRun 通过、无候选、范围集中等）

---

## 四、当前遗留问题

### 已解决 ✅

| 问题 | 解决方式 |
|------|---------|
| DryRun L0-L2 全败时无法生成补丁 | 新增 L5 Verified-Direct + L3.5 Zero-Context |
| 宏/常量重命名导致补丁无法应用 | 符号映射自动检测 + 替换 |
| 缩进风格差异 (tab/space) 导致拒绝 | 缩进适配算法 |
| validate 模式下 DryRun 被跳过 | `force_dryrun` 修正 |
| 开发者看不懂工具输出 | Analysis Narrative 结构化叙述 |
| 风险收益展示裸数值无法理解 | 改为等级标签 + 详细文字描述 |
| 函数名提取到 static/int 等噪声词 | C 函数名智能提取 (跳过类型修饰符) |
| LLM 返回 None 导致 strip() 崩溃 | `(content or "").strip()` 防护 |
| 无前置补丁时不解释原因 | 关联补丁完整分析（无论有无都给理由） |

### 仍存在 ⚠️

| 编号 | 问题 | 说明 |
|------|------|------|
| 1 | `normalize_subject` 前缀不灵活 | 企业内核自定义前缀 `[hulk]` 等无法处理 |
| 2 | FTS5 关键词搜索过严 | AND 连接要求全部命中，backport subject 修改后易漏 |
| 3 | L3 搜索性能瓶颈 | 100 个候选各执行 git show ~50ms |
| 4 | Stable backport 版本匹配硬编码 | `ver.startswith("5.10")` 仅支持 5.10 |
| 5 | `verify=False` 未配置化 | 安全风险 |
| 6 | 阈值硬编码 | L2/L3 相似度阈值应可配置 |
| 7 | Fixes 标签链未递归 | 仅追踪第一层引用 |
| 8 | L6 AI 补丁未接入主链路 | 需手动配置 |

---

## 五、下一阶段优化方向

### P-Near — 搜索质量增强 (1-2 周)

| 编号 | 项目 | 复杂度 |
|------|------|--------|
| N.1 | `normalize_subject` 正则化 — 去除所有 `[...]` 前缀，支持配置 | 低 |
| N.2 | FTS5 搜索改 OR + 权重 | 中 |
| N.3 | L3 延迟 diff 获取 — `git show --stat` 预过滤 | 中 |
| N.4 | diff LRU 内存缓存 | 低 |

### P-Mid — Pipeline 通用化 (2-4 周)

| 编号 | 项目 | 复杂度 |
|------|------|--------|
| M.1 | Stable backport 版本自动匹配 | 低 |
| M.2 | 引入 commit 缺失的降级策略 | 中 |
| M.3 | L6 AI 补丁生成接入主链路 | 中 |
| M.4 | `verify=False` 可配置 | 低 |
| M.5 | 阈值配置化 | 低 |
| M.6 | Fixes 标签链递归 (限深 3 层) | 中 |

### P-Far — 扩展能力 (1-3 月)

| 编号 | 项目 | 复杂度 |
|------|------|--------|
| F.1 | CI/CD 集成模式 (`--json` + 非零退出码) | 中 |
| F.2 | 多仓库并行分析 | 高 |
| F.3 | CVE 订阅与增量扫描 | 高 |
| F.4 | Web Dashboard | 高 |
| F.5 | 扩大基准测试集 50+ CVE | 中 |

---

## 六、建议执行路径

```
已完成 ✅:
  Phase 0-2: 基础架构 + 搜索引擎 + 路径映射 + Diff 包含度
  Phase 3:   多级 DryRun (L0-L5 + L3.5 + L4) + 符号映射 + 缩进适配
  Phase 4:   batch-validate + CVE 级聚合 + 前置补丁交叉验证
  Phase 5:   Analysis Narrative
  Phase 6:   Validate 修复 (force_dryrun / worktree)
  Phase 7:   v2.0 深度分析 (漏洞/社区/检视/风险/建议/关联补丁完整分析)

近期 (1-2 周):
  ├─ N.1 normalize_subject 正则化
  ├─ N.4 diff LRU 缓存
  ├─ M.1 Stable backport 版本自动匹配
  └─ M.4 + M.5 配置化 (verify / 阈值)

中期 (2-4 周):
  ├─ N.2 FTS5 搜索改 OR
  ├─ N.3 L3 延迟 diff
  ├─ M.3 L6 AI 接入主链路
  └─ M.6 Fixes 标签链递归

远期 (1-3 月):
  ├─ F.1 CI/CD 集成
  ├─ F.5 基准测试集 50+ CVE
  └─ F.2 + F.3 多仓库 / CVE 订阅
```
