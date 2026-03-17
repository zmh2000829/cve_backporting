# 五级自适应 DryRun 引擎 — 算法原理与技术规范

> **文档版本**: v2.0 | **适用模块**: `agents/dryrun.py` | **核心创新**: 锚点行定位 + 逐行投票 + 偏移传播 + 代码语义匹配

---

## 1. 问题定义与工程背景

### 1.1 核心挑战

在 Linux 内核 CVE 安全补丁回溯（backporting）场景中，社区发布的修复补丁（mainline patch）通常基于上游内核主线版本生成。当需要将该补丁应用到企业自维护的下游内核分支时，会遇到以下技术障碍：

| 障碍类型 | 技术表现 | 根因 |
|----------|---------|------|
| **Context 偏移** | 补丁的 context 行在目标文件中位置不同 | 中间 commit 在补丁相邻区域插入/删除了代码 |
| **Context 序列断裂** | 补丁的连续 context 行被额外代码打断 | 企业自定义补丁插入了行，破坏了 context 连续性 |
| **路径不一致** | 补丁中的文件路径在目标仓库不存在 | 内核版本演进中子系统目录重组（如 `fs/cifs/` → `fs/smb/client/`） |
| **代码行变更** | 补丁待删除的行在目标文件中内容不同 | 中间 commit 修改了补丁涉及的同一行代码 |

标准的 `git apply` 仅支持精确 context 匹配，对上述任何一种障碍均无法处理。

### 1.2 设计目标

五级自适应 DryRun 引擎的设计目标为：

1. **最大化自动适配率**：通过渐进式降级策略，尽可能在无人工干预的情况下完成补丁应用
2. **精确冲突诊断**：当自动适配失败时，提供行级精度的冲突分析报告，降低人工审查成本
3. **安全性保证**：生成的适配补丁保持原始补丁的核心修改不变（+/- 行），仅调整 context

---

## 2. 五级策略架构

引擎采用**渐进式降级**（Progressive Fallback）架构，从最严格的精确匹配逐级放宽约束，直到找到可行的应用方案或所有策略耗尽：

```
补丁输入 (mainline patch)
  │
  ├─ Level 0: Strict（严格精确匹配）
  │   └─ 算法: git apply --check
  │       成功 ✔ → 返回 (最高可信度)
  │       失败 ↓
  │
  ├─ Level 1: Context-C1（降低 Context 约束）
  │   └─ 算法: git apply --check -C1
  │       成功 ✔ → 返回
  │       失败 ↓
  │
  ├─ Level 2: 3-Way Merge（三方合并）
  │   └─ 算法: git apply --check --3way
  │       成功 ✔ → 返回
  │       失败 ↓
  │
  ├─ Level 3: Regenerated（上下文重建）⭐ 核心创新
  │   └─ 算法: 锚点行定位 + 目标文件 context 重建
  │       成功 ✔ → 返回
  │       失败 ↓
  │
  ├─ Level 4: Conflict-Adapted（冲突适配）
  │   └─ 算法: 逐 hunk 冲突分析 + 适配补丁生成
  │       成功 ✔ → 返回 (需人工审查)
  │       失败 ↓
  │
  └─ Level 5: AI-Generated（AI 辅助生成）🤖 AI
      └─ 算法: LLM 分析上下文差异并生成适配补丁
          成功 ✔ → 返回 (需人工审查)
          失败 ↓ → 输出完整冲突诊断报告
```

---

## 3. 各级策略详细原理

### 3.1 Level 0: Strict 模式 — 精确 Context 匹配

**算法原理**

Strict 模式调用 Git 原生的补丁应用检查机制 `git apply --check`。该机制要求补丁中的 **每一行 context**（即 unified diff 中以空格开头的行）在目标文件中精确匹配。匹配过程遵循以下规则：

1. 根据补丁 hunk header 中的行号 `@@ -start,count +start,count @@` 定位目标文件的对应区域
2. 逐行比较 context 行与目标文件对应位置的内容（忽略行末空白）
3. 若所有 context 行均精确匹配，且 `-` 行（待删除行）内容一致，则判定补丁可直接应用

**适用场景**

- 补丁来自与目标仓库同一分支或相近版本
- 目标文件在补丁涉及区域未被其他 commit 修改
- 行号偏移为零或在 Git 默认容差范围内（±3 行）

**失败条件**

- 目标文件路径不存在
- 任一 context 行或 `-` 行内容不匹配
- 行号偏移超出默认容差

**技术实现**

```python
r0 = self._apply_check(mapped_diff, repo_path, [])
# 内部执行: git apply --check --verbose <patch>
```

---

### 3.2 Level 1: Context-C1 模式 — 降低 Context 匹配约束

**算法原理**

Git 的 `-C` 参数控制 context 行匹配的严格程度。`-C1` 将最低 context 匹配行数降为 1（默认为全部 context 行数）。其工作原理为：

1. 保持 `-` 行精确匹配的要求不变
2. context 行匹配要求从全部降为最少 1 行
3. Git 在目标文件中以递增偏移量搜索匹配窗口

**与 Strict 模式的差异**

| 特征 | Strict | Context-C1 |
|------|--------|------------|
| Context 匹配行数 | 全部 | 最少 1 行 |
| 允许的偏移量 | ±3 行 | 更大的偏移范围 |
| `-` 行要求 | 精确匹配 | 精确匹配（不变） |

**适用场景**

- 中间 commit 修改了补丁 context 区域的部分行，但未触及补丁的核心代码（+/- 行）
- 行号偏移在数行范围内

**失败条件**

- 偏移过大导致匹配窗口找不到足够的 context 行
- 补丁的 `-` 行在目标文件中内容不同

---

### 3.3 Level 2: 3-Way Merge 模式 — 三方合并算法

**算法原理**

三方合并（3-Way Merge）是分布式版本控制系统中的经典冲突解决算法。其核心思想是利用三个版本的文件进行差异推导：

```
Base (共同祖先版本)
  │
  ├─ Theirs (社区补丁修改后版本)
  │
  └─ Ours (目标文件当前版本)
```

**算法步骤**

1. **Base 重建**：Git 从补丁中的 `index` 行提取 blob hash，在对象库中查找对应的原始文件（base）
2. **差异计算**：分别计算 Base→Theirs（补丁引入的变更）和 Base→Ours（目标文件的本地变更）
3. **冲突检测**：若两个差异修改了不同的区域，则可自动合并；若修改了相同区域，则产生冲突

**适用场景**

- Git 对象库中存在补丁对应的 base blob（通常要求共享部分提交历史）
- 补丁的变更与目标文件的本地变更在代码区域上不重叠

**失败条件**

- Base blob 不在对象库中（补丁来自独立仓库，无共同历史）
- 变更区域重叠，三方合并产生冲突标记

**技术实现**

```python
r2 = self._apply_check(mapped_diff, repo_path, ["--3way"])
# 内部执行: git apply --check --3way <patch>
```

---

### 3.4 Level 3: Regenerated 模式 — 上下文重建 ⭐ 核心创新

**问题背景**

当 Level 0-2 均失败时，意味着补丁的 context 行在目标文件中已经严重偏移或被打断。此时需要一种**不依赖 context 序列连续性**的定位算法。

**核心思想**

Level 3 的核心思想是：**补丁的 +/- 行（核心修改）通常未被其他 commit 修改，只是 context 行发生了偏移**。因此，可以在目标文件中重新定位变更点，从目标文件提取正确的 context 行，保留原始补丁的 +/- 行不变，重建一个与目标文件兼容的新补丁。

#### 3.4.1 两层定位架构

**第一层：Hunk 级分类定位（`_locate_hunk`）**

每个 hunk 根据是否包含 `-` 行分为两类，采用不同的定位策略：

| Hunk 类型 | 特征 | 定位方法 | 返回值 |
|-----------|------|---------|--------|
| **Removal Hunk** | 包含 `-` 行 | `_locate_removal_hunk` | (change_pos, n_remove) |
| **Addition Hunk** | 仅包含 `+` 行 | `_locate_addition_hunk` | (insert_pos, 0) |

**Removal Hunk 定位策略**

```
_locate_removal_hunk(hunk_lines, file_lines, hint, func_name)
  │
  ├─ 策略 A: 直接搜索 removed 行序列
  │   在目标文件中搜索与补丁 `-` 行完全匹配的连续序列
  │
  ├─ 策略 B: Before-Context 末行锚点定位
  │   以 context 中变更点前最后一行作为锚点
  │   在目标文件中搜索锚点行，change_pos = anchor_pos + 1
  │
  └─ 策略 C: After-Context 首行锚点定位
      以 context 中变更点后第一行作为锚点
      在目标文件中搜索锚点行，change_pos = anchor_pos - n_remove
```

**Addition Hunk 定位策略**

```
_locate_addition_hunk(hunk_lines, file_lines, hint, func_name)
  │
  ├─ 策略 A: Before-Context 末行锚点 → insert = anchor + 1
  ├─ 策略 B: After-Context 首行锚点 → insert = anchor
  ├─ 策略 C: 整段 Before-Context 序列搜索
  ├─ 策略 D: 整段 After-Context 序列搜索
  └─ 策略 E: 全 hunk 非 `+` 行投票定位
```

#### 3.4.2 锚点行定位算法

**算法定义**

锚点行定位（Anchor Line Positioning）是解决"Context 序列断裂"问题的核心算法。其基本思想是：**不搜索整段连续的 context 序列，而是选取单行高辨识度的"锚点行"进行定位，从而绕过 context 序列中额外插入行导致的断裂问题**。

**锚点行选取规则**

- **Before-Context 锚点**：选取 context 中变更点前最后一行（`ctx_before[-1]`）
- **After-Context 锚点**：选取 context 中变更点后第一行（`ctx_after[0]`）
- 这两行距离变更点最近，被中间 commit 修改的概率最低

**搜索过程**

1. 根据 hint（行号提示 + 偏移传播修正）确定搜索窗口（±300 行）
2. 在窗口内逐行进行精确匹配（strip 后完全一致）
3. 若精确匹配失败，使用 SequenceMatcher 进行模糊匹配（阈值 ≥ 0.85）
4. 返回最佳匹配行的位置

**对比示例**

```
社区补丁 hunk（纯添加）:
  ctx_before[-1] = "static struct kmem_cache *dquot_cachep;"  ← 锚点行
  + static struct workqueue_struct *dquot_wq;                  ← 新增代码
  + static DEFINE_MUTEX(dquot_lock);
  ctx_after[0]   = "static int nr_dquots;"

目标文件:
  line 162: static struct kmem_cache *dquot_cachep;  ← 锚点命中
  line 163: /* 企业自定义注释 */                       ← 额外插入行
  line 164: static int nr_dquots;

传统 context 序列匹配: 失败（6 行连续序列被额外行打断）
锚点行定位: 成功（单行搜索不受额外行影响）
  → 锚点位于 line 162 → insert_point = 163
```

**算法复杂度**

- 时间: O(window_size) ≈ O(600)，其中 window_size 为搜索窗口大小
- 空间: O(1)

#### 3.4.3 七策略序列搜索引擎（`_locate_in_file`）

当锚点行搜索不适用或失败时（如 Removal Hunk 的直接搜索），系统回退到七策略序列搜索引擎。七个策略按精确度从高到低排列，形成完整的搜索兜底链：

| 策略编号 | 名称 | 算法原理 | 适用条件 |
|---------|------|---------|---------|
| L1 | **精确序列匹配** | 在文件中搜索与目标序列 strip 后完全一致的连续子序列 | 代码内容完全相同，仅行号偏移 |
| L2 | **函数名锚点搜索** | 从 hunk header `@@` 行提取函数名，限定搜索范围至该函数体内 | hunk header 包含函数签名 |
| L3 | **行号窗口搜索** | 以 hint（行号 + 偏移修正）为中心，在 ±300 行窗口内搜索 | 有可靠的行号提示 |
| L4 | **全局模糊匹配** | 滑动窗口逐位置计算加权相似度，阈值 ≥ 0.45（短序列）/0.50 | 代码有微小差异（变量重命名等） |
| L5 | **Context 行重试** | 使用补丁的 context 行（而非 removed 行）作为搜索目标 | removed 行被修改但 context 未变 |
| L6 | **逐行投票** | 每行独立搜索并估算序列起始位置，取估算值的众数 | 部分行匹配即可推断位置 |
| L7 | **最长行匹配** | 选取序列中长度最大的行进行搜索（高辨识度行） | 序列中存在特征性长行 |

#### 3.4.4 逐行投票算法

**算法定义**

逐行投票（Line-by-Line Voting）是一种基于统计众数（mode）的序列定位算法。其核心思想是：**让每一行独立估算整个序列的起始位置，然后通过投票选出最一致的估算值**。

**数学原理**

设目标序列长度为 $n$，序列第 $i$ 行（$0$-indexed）在文件中找到的位置为 $f(i)$。若序列从文件的第 $s$ 行开始，且没有额外插入行，则理想情况下 $f(i) = s + i$。

因此每行的起始位置估算为：

$$\hat{s}_i = f(i) - i$$

取所有估算值的众数：

$$s^* = \text{mode}(\{\hat{s}_0, \hat{s}_1, \ldots, \hat{s}_{n-1}\})$$

**鲁棒性分析**

即使目标文件中存在额外插入行导致部分行的估算偏离，只要**多数行**的估算值一致，众数仍能给出正确结果。

**实现示例**

```
目标序列 (needle):
  [0] "dquot_cachep;"        → 在文件 line 4 找到 → 估算: 4 - 0 = 4
  [1] "nr_dquots;"           → 在文件 line 5 找到 → 估算: 5 - 1 = 4
  [2] "reserved_space;"      → 在文件 line 7 找到 → 估算: 7 - 2 = 5 (偏离)
  [3] "quota_format;"        → 在文件 line 8 找到 → 估算: 8 - 3 = 5

投票结果: {4: 2, 5: 2} → 取最小值 4 作为起始位置
```

**分桶策略**

当精确众数票数不足时，采用分桶投票（bucket size = 2）增强鲁棒性：

```python
grouped = {}
for e in estimates:
    bucket = round(e / 2) * 2
    grouped[bucket] = grouped.get(bucket, 0) + 1
best_est = max(grouped, key=grouped.get)
```

#### 3.4.5 跨 Hunk 偏移传播

**算法原理**

同一文件中的多个 hunk 通常具有相关的行号偏移。Level 3 利用**偏移传播**（Offset Propagation）机制，将前一个 hunk 定位成功后计算出的实际偏移量传递给后续 hunk，作为搜索起点的修正值。

**数学表示**

设第 $k$ 个 hunk 的补丁起始行号为 $h_k$，实际定位到的起始行号为 $a_k$，则累积偏移为：

$$\Delta_k = a_k - h_k$$

第 $k+1$ 个 hunk 的搜索起始 hint 修正为：

$$\text{hint}_{k+1} = h_{k+1} + \Delta_k$$

**效果**

随着同文件中 hunk 的逐个定位，偏移量估算越来越精准，后续 hunk 的搜索窗口自动缩小，定位速度和准确率均提升。

#### 3.4.6 补丁重建过程

定位成功后，从目标文件直接读取 context 行，结合原始补丁的 +/- 行，重建新补丁：

```python
# 直接从目标文件的变更点读取 (不走查 hunk_lines)
ctx_before  = target_lines[change_pos - 3 : change_pos]    # 前 3 行 context
removed     = target_lines[change_pos : change_pos + n_remove]  # 目标文件的实际 - 行
added       = original_added_lines                            # 原始补丁的 + 行（不变）
ctx_after   = target_lines[change_pos + n_remove : change_pos + n_remove + 3]
```

**关键设计决策**：不逐行走查 `hunk_lines` 对齐目标文件（额外行会导致对齐错位），而是以定位到的 `change_pos` 为基准直接从目标文件读取。这一设计彻底解决了额外插入行导致的补丁对齐错位问题。

---

### 3.5 Level 4: Conflict-Adapted 模式 — 冲突适配

**问题背景**

当 Level 3 失败时，通常意味着补丁的 `-` 行（待删除代码）在目标文件中的内容已经被中间 commit 修改。此时无法简单替换 context，需要对冲突进行分析和适配。

**算法步骤**

1. **逐 Hunk 定位**：使用 `_locate_in_file` 在目标文件中定位每个冲突 hunk
2. **Expected vs Actual 对比**：提取补丁期望的 `-` 行（expected）和目标文件中的实际行（actual）
3. **逐行差异分析**：标记每行的具体差异内容
4. **冲突分级**：根据行级相似度进行三级分类
5. **适配补丁生成**：对 L1/L2 级冲突，用目标文件 actual 行替换补丁 `-` 行，保留 `+` 行

**冲突三级分类**

| 级别 | 行相似度阈值 | 语义含义 | 处理策略 |
|------|------------|---------|---------|
| **L1 轻微** | ≥ 85% | 变量重命名、空格/缩进变动、注释修改 | 自动适配（高置信度） |
| **L2 中度** | 50% - 85% | 局部代码重构、参数变更、条件逻辑调整 | 自动适配 + 标记需人工审查 |
| **L3 重大** | < 50% | 代码大幅改写、函数签名变更、逻辑重构 | 无法自动适配，需人工手动合入 |

**适配补丁生成原理**

```
原始补丁:
  - static int old_field;         ← 补丁期望删除的行
  + static struct wq *dquot_wq;   ← 补丁新增的行

目标文件实际:
    static int old_field;         ← 内容匹配 (L1)
    /* custom field */            ← 额外行

适配后补丁:
  - static int old_field;         ← 用 actual 替换（此处一致）
  - /* custom field */            ← 额外行也需删除
  + static struct wq *dquot_wq;   ← + 行保持不变
```

**安全保证**：适配补丁的 `+` 行（新增代码）**始终保持与原始补丁完全一致**，确保安全修复逻辑不被改变。修改仅限于 context 行和 `-` 行的适配。

---

### 3.5 Level 5: AI-Generated 模式 — AI 辅助补丁生成 🤖

> **标注：本级策略使用大语言模型（LLM）进行辅助分析和补丁生成**

**问题背景**

当 Level 0-4 所有基于规则的策略均失败时，通常意味着补丁涉及的代码已经发生了结构性变更，超出了模式匹配算法的处理能力。此时引入 AI 辅助分析。

**算法原理**

Level 5 使用大语言模型（LLM）作为补丁生成的辅助引擎：

1. **上下文构建**：将原始补丁、目标文件相关区域的代码、冲突分析结果组装为结构化 prompt
2. **LLM 推理**：LLM 分析代码差异的语义含义，理解变更意图，生成适配补丁
3. **格式验证**：对 LLM 生成的补丁进行 unified diff 格式校验
4. **应用性验证**：通过 `git apply --check` 验证补丁可应用性

**配置方式**

```yaml
ai_patch_generation:
  enabled: false          # 默认关闭
  provider: "openai"      # 支持 OpenAI / DeepSeek / Azure / vLLM 等兼容 API
  model: "gpt-4o"
  # 复用 llm 配置中的 api_key 和 base_url
```

**安全约束**

- AI 生成的补丁必须通过 `git apply --check` 验证
- 生成结果标记为 `ai-generated`，**强制要求人工审查**
- LLM 指令中明确要求保持原始补丁的 `+` 行不变

**核心模块**：`core/ai_patch_generator.py` — `AIPatchGenerator` 类

---

## 4. 代码语义匹配（Level 8 策略） 🤖

> **标注：本策略的多维度相似度计算采用 NLP 领域的编辑距离和集合匹配算法，非 AI 模型推理。但在未来版本中可集成嵌入向量模型进行语义匹配。**

### 4.1 问题定义

当 Level 3 的锚点行定位和七策略序列搜索均失败时，通常是因为代码的"形式"发生了变化但"语义"保持不变。Level 8 策略在所有传统匹配失败后触发，用代码内容的**语义特征**而非 context 序列进行匹配。

### 4.2 多维度相似度模型

**算法定义**

代码语义匹配采用三维度加权融合模型：

$$\text{score} = w_1 \times S_{\text{structure}} + w_2 \times S_{\text{identifier}} + w_3 \times S_{\text{keyword}}$$

其中权重为 $w_1 = 0.5$，$w_2 = 0.3$，$w_3 = 0.2$。

**维度一：结构相似度（$S_{\text{structure}}$）**

基于 Ratcliff/Obershelp 算法（Python `SequenceMatcher`），计算两段代码去除空白后的编辑距离比率：

$$S_{\text{structure}} = \frac{2 \times |\text{LCS}(a, b)|}{|a| + |b|}$$

其中 LCS 为最长公共子序列。该指标反映代码的整体结构保留程度。

**维度二：标识符匹配率（$S_{\text{identifier}}$）**

从代码中提取所有标识符（变量名、函数名、类型名），计算 Jaccard 相似系数：

$$S_{\text{identifier}} = \frac{|I_a \cap I_b|}{|I_a \cup I_b|}$$

标识符通过正则表达式 `[a-zA-Z_][a-zA-Z0-9_]{2,}` 提取，过滤 C 语言关键字。

**维度三：关键字序列相似度（$S_{\text{keyword}}$）**

提取 C 语言关键字（`if`, `for`, `while`, `return`, `struct` 等）的出现序列，使用 SequenceMatcher 计算序列相似度。该指标反映代码的控制流结构。

### 4.3 搜索流程

```
输入: 补丁代码片段 (removed/added)
  │
  ├─ Step 1: PatchContextExtractor 提取元数据
  │   ├─ 标识符集合 (identifier set)
  │   ├─ 关键字序列 (keyword sequence)
  │   └─ 代码结构特征 (structure features)
  │
  ├─ Step 2: 在目标文件中滑动窗口扫描
  │   ├─ 窗口大小 = 补丁代码片段行数 ± 容差
  │   └─ 每个窗口计算三维度相似度
  │
  └─ Step 3: 返回最高分位置（阈值 ≥ 0.70）
```

**核心模块**：`core/code_matcher.py` — `PatchContextExtractor` + `CodeMatcher` 类

---

## 5. 路径映射感知

### 5.1 设计背景

Linux 内核在版本演进中会重组子系统目录结构。DryRun 引擎在两个层面集成路径映射：

1. **Diff 路径重写**：将补丁中的 upstream 路径替换为 local 路径
2. **文件查找回退**：定位阶段先查原始路径，失败则尝试所有映射变体

### 5.2 内置映射规则

| 上游路径 (mainline) | 本地路径 (enterprise) | 起始版本 |
|---------------------|----------------------|---------|
| `fs/smb/client/` | `fs/cifs/` | 6.2 |
| `fs/smb/server/` | `fs/ksmbd/` | 6.2 |
| `fs/smb/common/` | `fs/smbfs_common/` | 6.2 |
| `drivers/gpu/drm/amd/display/dc/link/` | `drivers/gpu/drm/amd/display/dc/core/` | 6.2 |
| `drivers/gpu/drm/i915/display/` | `drivers/gpu/drm/i915/` | 5.18 |
| `drivers/net/wireless/realtek/rtw89/` | `drivers/staging/rtw89/` | 5.16 |
| `drivers/net/wireless/ath/ath12k/` | `drivers/staging/ath12k/` | 6.5 |
| `fs/netfs/` | `fs/fscache/` | 6.1 |

规则可通过 `config.yaml` 的 `path_mappings` 字段自定义扩展。

---

## 6. Stable Backport 补丁优先策略

### 6.1 设计原理

CVE 修复补丁在 Linux 社区通常有多个版本：mainline 补丁和各 stable 分支的 backport 补丁。Stable backport 补丁的 context 行和文件路径与目标分支更一致，使用 backport 补丁可显著提高 DryRun 成功率。

### 6.2 选择策略

```
CVE 版本映射:
  - mainline (7.x)
  - 6.6 stable backport
  - 6.1 stable backport
  - 5.15 stable backport
  - 5.10 stable backport  ← 目标版本

选择逻辑:
  1. 查找与目标版本 major.minor 完全匹配的 backport → 优先使用
  2. 回退到最近的低版本 backport
  3. 最后使用 mainline 补丁
```

---

## 7. 函数级影响分析

> **标注：函数定义提取使用正则表达式模式匹配，非 AI 模型。**

**核心模块**：`core/function_analyzer.py` — `FunctionAnalyzer` 类

### 7.1 功能

- 从 C 源代码中提取函数定义（基于正则表达式匹配函数签名模式）
- 分析补丁修改的函数及其调用关系（caller/callee）
- 生成函数级影响范围报告

### 7.2 输出结构

```python
{
    "modified_functions": [FunctionInfo(...)],   # 被补丁直接修改的函数
    "affected_functions": [FunctionInfo(...)],   # 调用被修改函数的函数（影响范围）
    "impact_summary": "修改了 2 个函数，影响 5 个调用者"
}
```

---

## 8. 性能特性

| 指标 | 数据 | 说明 |
|------|------|------|
| 单 Hunk 平均定位时间 | < 100ms | 包含锚点行搜索和偏移传播 |
| 七策略全路径耗时 | ~500ms | 最坏情况：所有策略均尝试 |
| 内存复杂度 | O(file_size) | 目标文件全量加载 |
| 偏移传播命中率提升 | ~80% | 同文件后续 hunk 的搜索效率提升 |
| 代码语义匹配耗时 | < 200ms | 滑动窗口扫描单文件 |

---

## 9. AI 技术使用标注

本系统中以下组件使用了 AI/机器学习技术：

| 组件 | AI 技术 | 用途 | 是否默认启用 |
|------|---------|------|------------|
| **Level 5: AI-Generated** | 大语言模型 (LLM) | 生成适配补丁 | 否（需配置启用） |
| **LLM 差异分析** | 大语言模型 (LLM) | 验证失败时的根因分析 | 否（需配置启用） |
| **代码语义匹配 (L8)** | SequenceMatcher + 集合运算 | 多维度代码相似度计算 | 是（纯算法，非模型推理） |
| **Diff 包含度检测** | Multiset 计数 | 识别 squash commit 中的补丁包含关系 | 是（纯算法） |

**说明**：Level 0-4 的核心定位与适配算法均为**确定性算法**，不依赖任何 AI 模型，具备完全的可重现性和可解释性。AI 辅助功能（Level 5 和 LLM 分析）为可选增强，默认关闭。

---

## 10. 附录：算法伪代码

### 10.1 check_adaptive 主流程

```python
def check_adaptive(patch, target_version):
    diff = extract_and_rewrite_paths(patch)
    
    # Level 0: Strict
    if git_apply_check(diff, []):
        return DryRunResult(method="strict")
    
    # Level 1: Context-C1
    if git_apply_check(diff, ["-C1"]):
        return DryRunResult(method="context-C1")
    
    # Level 2: 3-Way Merge
    if git_apply_check(diff, ["--3way"]):
        return DryRunResult(method="3way")
    
    # Level 3: Regenerated
    adapted = regenerate_patch(diff, target_file)
    if adapted and git_apply_check(adapted, []):
        return DryRunResult(method="regenerated", adapted_patch=adapted)
    
    # Level 4: Conflict-Adapted
    analysis = analyze_conflicts(diff, target_file)
    if analysis.adapted_diff and git_apply_check(analysis.adapted_diff, []):
        return DryRunResult(method="conflict-adapted", adapted_patch=analysis.adapted_diff)
    
    # Level 5: AI-Generated (可选)
    if ai_enabled:
        ai_patch = ai_generate_patch(patch, target_file, analysis)
        if ai_patch and git_apply_check(ai_patch, []):
            return DryRunResult(method="ai-generated", adapted_patch=ai_patch)
    
    # 全部失败
    return DryRunResult(conflict_hunks=analysis.hunks)
```

### 10.2 锚点行定位

```python
def find_anchor_line(anchor, file_lines, hint, window=300):
    search_range = range(
        max(0, hint - window),
        min(len(file_lines), hint + window)
    )
    
    # 精确匹配优先
    for i in search_range:
        if file_lines[i].strip() == anchor.strip():
            return i
    
    # 模糊匹配回退
    best_pos, best_ratio = None, 0.0
    for i in search_range:
        ratio = SequenceMatcher(None, anchor.strip(), file_lines[i].strip()).ratio()
        if ratio > best_ratio and ratio >= 0.85:
            best_pos, best_ratio = i, ratio
    
    return best_pos
```
