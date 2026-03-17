# 多级自适应算法参考手册

> **适用范围**: CVE Backporting Engine 全链路算法  
> **文档定位**: 为安全工程师和内核开发者提供算法原理的完整参考

---

## 目录

- [1. 系统算法全景](#1-系统算法全景)
- [2. Commit 搜索算法（三级渐进式）](#2-commit-搜索算法三级渐进式)
- [3. Diff 包含度检测算法](#3-diff-包含度检测算法)
- [4. 前置依赖分析算法](#4-前置依赖分析算法)
- [5. 五级自适应 DryRun 算法](#5-五级自适应-dryrun-算法)
- [6. 锚点行定位算法](#6-锚点行定位算法)
- [7. 七策略序列搜索引擎](#7-七策略序列搜索引擎)
- [8. 逐行投票定位算法](#8-逐行投票定位算法)
- [9. 代码语义匹配算法](#9-代码语义匹配算法)
- [10. 冲突分析与适配算法](#10-冲突分析与适配算法)
- [11. 路径映射算法](#11-路径映射算法)
- [12. 验证框架算法](#12-验证框架算法)
- [13. AI 辅助算法](#13-ai-辅助算法)
- [附录 A: 算法复杂度汇总](#附录-a-算法复杂度汇总)
- [附录 B: 阈值参数参考](#附录-b-阈值参数参考)

---

## 1. 系统算法全景

CVE Backporting Engine 包含多个层次的算法，从情报获取到补丁应用形成完整的分析链路：

```
┌─────────────────────────────────────────────────────────────────┐
│                        算法全景图                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  情报层      三级补丁源回退 + 部分结果互补合并                    │
│  ────────────────────────────────────────────                   │
│  搜索层      L1 精确 ID → L2 Subject 语义 → L3 Diff 匹配        │
│              含 Diff 包含度检测 (Multiset)                       │
│  ────────────────────────────────────────────                   │
│  依赖层      Hunk 行范围重叠 + 函数名交集 + 三级评分             │
│  ────────────────────────────────────────────                   │
│  应用层      五级自适应 DryRun                                   │
│              L0 Strict → L1 -C1 → L2 3way                       │
│              → L3 锚点行定位 + context 重建                      │
│              → L4 冲突适配                                       │
│              → L5 AI 辅助生成 🤖                                 │
│  ────────────────────────────────────────────                   │
│  验证层      Worktree 回退 + P/R/F1 量化 + LLM 分析 🤖          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Commit 搜索算法（三级渐进式）

### 2.1 设计原理

在企业自维护内核仓库中搜索社区 commit 面临的核心挑战是：**commit ID 可能因 cherry-pick/rebase 而改变，subject 可能被修改，diff 可能因 squash 而被合并到更大的 commit 中**。因此设计了三级渐进式搜索，每级使用不同维度的匹配特征。

### 2.2 Level 1: 精确 ID 匹配

**算法**：使用 `git cat-file -t <commit_id>` 检查对象存在性，再用 `git merge-base --is-ancestor <commit_id> <branch>` 验证该 commit 是否在目标分支的历史上。

**复杂度**：O(log n)，其中 n 为仓库 commit 数。Git 内部使用 DAG 遍历优化。

**置信度**：100%（完全确定性匹配）

### 2.3 Level 2: Subject 语义匹配

**算法**：

1. **预处理**：去除 subject 中的 `[backport]`、`[PATCH]` 等前缀，标准化空白
2. **精确搜索**：`git log --grep="<normalized_subject>"` 在 FTS5 索引中全文匹配
3. **关键词搜索**：提取 subject 中的关键词（去停用词），OR 组合搜索
4. **相似度计算**：对候选结果使用 Python `SequenceMatcher`（Ratcliff/Obershelp 算法），阈值 ≥ 85%

**SequenceMatcher 算法原理**：

Ratcliff/Obershelp 算法计算两个序列的相似度比率：

$$\text{ratio} = \frac{2 \times M}{|S_1| + |S_2|}$$

其中 $M$ 是最长公共子序列（通过递归分割和匹配计算），$|S_1|$、$|S_2|$ 分别为两个序列的长度。

**置信度**：85% - 100%

### 2.4 Level 3: Diff 代码级匹配

**算法**：

1. **候选筛选**：`git log -- <files>` 获取修改相同文件的 commit
2. **双向相似度**：提取 +/- 行，用 SequenceMatcher 计算
3. **单向包含度**：Multiset 包含度检测（详见第 3 节）
4. **综合评分**：

| 模式 | 公式 |
|------|------|
| 包含度优先 (引入搜索) | `file_sim × 0.3 + containment × 0.7` |
| 相似度优先 (修复搜索) | `file_sim × 0.4 + similarity × 0.6` |

**置信度**：70% - 100%

---

## 3. Diff 包含度检测算法

### 3.1 问题定义

企业内核仓库的常见实践是将社区多个 patch 合并（squash）为一个 commit。此时社区补丁的改动被**完整包含**在一个更大的本地 commit 中。传统双向相似度因分母包含大量无关行而显著偏低，导致匹配失败。

### 3.2 算法定义

**输入**：源 diff（社区补丁）和目标 diff（候选 commit）

**步骤**：

1. **变更行提取**：从两个 diff 中分别提取 `+` 行（added）和 `-` 行（removed），去掉 diff 前缀符号，过滤长度 < 4 的噪声行（`}`、`{`、`return;` 等短行匹配率过高会产生误报）

2. **分类匹配**：added 只与 added 匹配，removed 只与 removed 匹配，保证语义方向正确

3. **Multiset 计数**：使用 Python `Counter` 作为多重集合（multiset）。对每条源 diff 行，在目标 Counter 中查找并消耗一次匹配。每条目标行只能匹配一次，防止重复计数。

4. **包含度计算**：

$$\text{containment} = \frac{|\text{matched}|}{|\text{source\_lines}|}$$

### 3.3 数学性质

- **范围**：[0, 1]
- **非对称性**：containment(A, B) ≠ containment(B, A)
- **精确性**：Multiset 语义确保每行仅匹配一次

### 3.4 应用场景控制

| 搜索场景 | 使用包含度 | 原因 |
|----------|-----------|------|
| 引入 commit 搜索 | 是 | 本地仓库常 squash 社区多 patch |
| 修复 commit 搜索 | 否 | 修复补丁优先通过 L2 subject 定位 |
| check-intro 命令 | 是 | 判断引入代码是否存在 |
| check-fix 命令 | 否 | 判断修复补丁是否已合入 |

---

## 4. 前置依赖分析算法

### 4.1 问题定义

当修复补丁无法直接 cherry-pick 时，需要识别**哪些中间 commit 修改了相同代码区域**，导致修复补丁产生冲突。

### 4.2 Hunk 重叠检测

**从 diff 中提取 hunk 位置**：解析每个 `@@ -old_start,old_count +new_start,new_count @@` 行，计算行范围。

**重叠判定**：

| 类型 | 条件 | 含义 |
|------|------|------|
| **直接重叠** | $a_{start} \leq b_{end}$ 且 $b_{start} \leq a_{end}$（同文件） | 修改了完全相同的代码行 |
| **相邻重叠** | 行范围不相交但间距 ≤ 50 行 | 修改了相邻区域，可能产生 context 冲突 |

### 4.3 函数级重叠

从 Git diff 的 `@@ ... @@ function_name` 行提取函数名，取交集得到共同修改的函数。

### 4.4 评分公式

$$\text{score} = \min(d \times 0.3, 0.6) + \min(a \times 0.1, 0.2) + \min(f \times 0.15, 0.3)$$

其中 $d$ = 直接重叠 hunk 数，$a$ = 相邻重叠 hunk 数，$f$ = 重叠函数数。

### 4.5 三级分级

| 等级 | 条件 | 含义 |
|------|------|------|
| **强 (strong)** | $(d > 0 \wedge f > 0) \vee \text{score} \geq 0.5$ | 修改了相同代码行和函数，几乎必须先合入 |
| **中 (medium)** | $d > 0 \vee a > 0 \vee \text{score} \geq 0.2$ | 修改了相邻区域，大概率产生冲突 |
| **弱 (weak)** | 其余 | 修改了同文件不相关区域，通常不影响合入 |

---

## 5. 五级自适应 DryRun 算法

### 5.1 渐进式降级策略

五个 Level 按约束严格程度从高到低排列。每级失败后降级到下一级，最终要么找到可行方案，要么输出完整冲突诊断：

| Level | 策略 | 算法基础 | 约束条件 |
|-------|------|---------|---------|
| L0 | Strict | git apply --check | Context 全部精确匹配 |
| L1 | Context-C1 | git apply -C1 | 至少 1 行 context 匹配 |
| L2 | 3-Way | git apply --3way | Base blob 可用 |
| L3 | Regenerated | 锚点定位 + context 重建 | 变更点可定位 |
| L4 | Conflict-Adapted | 冲突分析 + 适配补丁 | 冲突为 L1/L2 级 |
| L5 | AI-Generated 🤖 | LLM 辅助生成 | AI 已启用且生成补丁有效 |

### 5.2 安全性保证

所有自动生成的适配补丁遵循核心原则：**补丁的 + 行（新增安全修复代码）始终保持与原始补丁完全一致**。修改仅限于：
- Context 行（从目标文件重新提取）
- `-` 行（用目标文件实际行替换）
- Hunk header 中的行号

### 5.3 详细原理

各级策略的完整算法原理、适用条件、失败条件详见 [ADAPTIVE_DRYRUN.md](ADAPTIVE_DRYRUN.md)。

---

## 6. 锚点行定位算法

### 6.1 核心思想

锚点行定位是解决"Context 序列断裂"问题的核心算法。在企业内核中，社区补丁的 6 行连续 context 中间可能被插入了 1-2 行自定义代码，导致连续序列匹配失败。

**关键洞察**：不搜索整段连续序列，选取**单行高辨识度的锚点行**进行定位。单行搜索天然免疫 context 序列中额外插入行的干扰。

### 6.2 锚点选取策略

| 锚点类型 | 选取规则 | 定位公式 |
|----------|---------|---------|
| Before-Context 锚点 | `ctx_before[-1]`（变更点前最后一行） | `change_pos = anchor_pos + 1` |
| After-Context 锚点 | `ctx_after[0]`（变更点后第一行） | `change_pos = anchor_pos - n_remove` |

选取离变更点最近的行作为锚点，因其被中间 commit 修改的概率最低。

### 6.3 搜索过程

```
输入: anchor_line, file_lines, hint (行号 + 偏移修正)
  │
  ├─ 1. 计算搜索窗口: [hint - 300, hint + 300]
  │
  ├─ 2. 精确匹配: 在窗口内逐行比较 strip() 后的内容
  │     → 若命中，返回位置
  │
  └─ 3. 模糊匹配: SequenceMatcher ratio ≥ 0.85
        → 返回最高匹配位置
```

### 6.4 复杂度分析

- 时间: O(W) 其中 W = 窗口大小 (默认 600)
- 空间: O(1)
- 窗口大小随偏移传播自动缩小

---

## 7. 七策略序列搜索引擎

### 7.1 策略链

当锚点行搜索不适用时（如搜索 Removal 行序列），回退到七策略序列搜索引擎。策略按精确度从高到低排列：

### 7.2 策略 1: 精确序列匹配

**算法**：在文件中搜索与目标序列 `strip()` 后完全一致的连续子序列。

**复杂度**：O(F × N) 其中 F = 文件行数，N = 序列长度

### 7.3 策略 2: 函数名锚点搜索

**算法**：从 hunk header `@@ ... @@ function_name(...)` 提取函数名。在文件中搜索函数定义（正则匹配 `function_name\s*\(`），将搜索范围限定在函数体内。

**适用条件**：hunk header 包含有效的函数签名

### 7.4 策略 3: 行号窗口搜索

**算法**：以 hint（原始行号 + 偏移修正）为中心，在 ±300 行窗口内搜索精确匹配。偏移修正来自跨 hunk 偏移传播。

### 7.5 策略 4: 全局模糊匹配

**算法**：滑动窗口遍历文件，对每个位置计算加权模糊评分：

$$\text{score}(pos) = \frac{\sum_{i} w_i \times s_i}{\sum_{i} w_i}$$

其中 $w_i = \max(1, |a_i| / 10)$（长行权重更高），$s_i$ 为第 $i$ 行的 SequenceMatcher 比率。

**阈值**：短序列 (≤3 行) 0.45，长序列 0.50

### 7.6 策略 5: Context 行重试

**算法**：使用补丁的 context 行（而非 removed 行）作为搜索目标。当 removed 行被修改但 context 行未变时有效。

### 7.7 策略 6: 逐行投票

**算法**：详见第 8 节

### 7.8 策略 7: 最长行匹配

**算法**：选取序列中字符数最多的行（高辨识度），在文件中搜索该行的最佳匹配位置（SequenceMatcher ≥ 0.60），根据该行在序列中的偏移推算整个序列的起始位置。

---

## 8. 逐行投票定位算法

### 8.1 算法定义

逐行投票（Line-by-Line Voting）是一种基于统计众数的序列定位算法。每行独立估算序列起始位置，通过投票选出最一致的估算值。

### 8.2 数学基础

设目标序列为 $\{l_0, l_1, \ldots, l_{n-1}\}$，各行在文件中的匹配位置为 $\{f(0), f(1), \ldots, f(n-1)\}$。

每行的起始位置估算：

$$\hat{s}_i = f(i) - i$$

最终位置为估算值的众数：

$$s^* = \text{mode}(\{\hat{s}_i \mid i = 0, 1, \ldots, n-1\})$$

### 8.3 匹配策略

每行先尝试精确匹配（strip 后完全一致），失败则使用 SequenceMatcher 模糊匹配（阈值 ≥ 0.70）。过滤长度 < 5 的短行（辨识度不足）。

### 8.4 分桶增强

当精确众数票数不足（< 30% 的有效估算数）时，使用分桶投票（bucket size = 2）：

$$\text{bucket}(\hat{s}_i) = \text{round}(\hat{s}_i / 2) \times 2$$

取票数最高的 bucket 值作为最终位置。分桶策略容忍 ±1 行的估算偏差。

### 8.5 鲁棒性

- 容忍最多 70% 的行匹配失败
- 容忍额外插入行导致的部分估算偏离
- 要求至少 30% 的有效估算值一致

---

## 9. 代码语义匹配算法

### 9.1 问题定义

当所有基于 context 序列的策略失败时，说明代码"形式"变化但"语义"可能不变。代码语义匹配用代码内容特征而非 context 位置进行定位。

### 9.2 三维度融合模型

$$\text{score} = 0.5 \times S_{\text{structure}} + 0.3 \times S_{\text{identifier}} + 0.2 \times S_{\text{keyword}}$$

**维度一：结构相似度 $S_{\text{structure}}$**

基于 Ratcliff/Obershelp 算法的序列相似度：

$$S_{\text{structure}} = \frac{2 \times |\text{LCS}(a, b)|}{|a| + |b|}$$

**维度二：标识符匹配率 $S_{\text{identifier}}$**

Jaccard 相似系数：

$$S_{\text{identifier}} = \frac{|I_a \cap I_b|}{|I_a \cup I_b|}$$

标识符通过 `[a-zA-Z_][a-zA-Z0-9_]{2,}` 提取，过滤 C 语言关键字。

**维度三：关键字序列相似度 $S_{\text{keyword}}$**

提取 C 语言保留关键字出现序列，用 SequenceMatcher 计算序列相似度。反映代码控制流结构。

### 9.3 搜索流程

1. `PatchContextExtractor` 从补丁提取元数据（标识符集合、关键字序列、结构特征）
2. 在目标文件中滑动窗口扫描，窗口大小 = 补丁行数 ± 容差
3. 每个窗口计算三维度相似度，返回最高分位置（阈值 ≥ 0.70）

### 9.4 技术标注

> 代码语义匹配采用确定性算法（SequenceMatcher + 集合运算），**不涉及 AI 模型推理**。"语义"一词指代码的结构和标识符级别的含义，而非自然语言语义。

---

## 10. 冲突分析与适配算法

### 10.1 逐 Hunk 冲突分析

**输入**：补丁 diff + 目标文件

**处理流程**：

1. 解析 diff 为 (file_path, header, hunks) 结构
2. 对每个 hunk，提取 ctx_before / expected(-行) / added(+行) / ctx_after
3. 使用 `_locate_hunk` 在目标文件中定位
4. 提取 actual 行（目标文件中对应位置的代码）
5. 逐行计算 expected vs actual 的 SequenceMatcher 相似度
6. 按相似度分级（L1 ≥ 85% / L2 ≥ 50% / L3 < 50%）

### 10.2 适配补丁生成

对 L1/L2 级冲突 hunk：

```
新补丁 = context_before (从目标文件读取)
       + actual 行标记为 "-"  (替换原始 expected)
       + added 行标记为 "+"  (保持不变)
       + context_after (从目标文件读取)
```

生成后通过 `git apply --check` 验证可应用性。

---

## 11. 路径映射算法

### 11.1 PathMapper 双向翻译

**设计背景**：Linux 内核版本演进中的子系统目录重组。

**核心方法**：

| 方法 | 作用 | 使用场景 |
|------|------|---------|
| `translate(path)` | 返回路径所有等价形式 | 内部搜索 |
| `expand_files(files)` | 扩展文件列表加入所有映射 | L3 搜索 / 依赖分析 |
| `normalize_for_compare(path)` | 统一规范到 upstream 形式 | 文件相似度比较 |

### 11.2 在 DryRun 中的集成

1. **Diff 路径重写**（`_rewrite_diff_paths`）：补丁中 upstream 路径 → local 路径
2. **文件查找回退**（`_resolve_file_path`）：原始路径失败 → 尝试所有映射变体

---

## 12. 验证框架算法

### 12.1 Git Worktree 回退验证

**核心技术**：`git worktree add --detach` 在修复前 commit 创建轻量工作区，共享 .git 对象库，秒级创建/清理。

**回滚点计算**：
- 无 known_prereqs → `known_fix~1`
- 有 known_prereqs → 最早 prereq 的父节点

### 12.2 前置依赖比较

双重匹配策略：

1. **ID 前缀匹配**：前 12 字符比较
2. **Subject 相似度匹配**：SequenceMatcher ≥ 80%（覆盖 cherry-pick 导致 ID 变化的情况）

**指标计算**：

$$\text{Precision} = \frac{|TP|}{|\text{推荐}|}, \quad \text{Recall} = \frac{|TP|}{|\text{真实}|}, \quad F_1 = \frac{2 \times P \times R}{P + R}$$

### 12.3 LLM 差异分析 🤖

> **标注：本功能使用大语言模型进行辅助分析**

当验证结果为 FAIL 时，可选调用 LLM 分析：
- 逐项根因分析
- 工具推荐与真实情况的差异原因
- DryRun 预测不准确的可能原因
- 改进建议

**模块**：`core/llm_analyzer.py`

---

## 13. AI 辅助算法

### 13.1 AI 技术使用范围

| 组件 | AI 技术 | 是否默认启用 | 核心算法是否依赖 AI |
|------|---------|------------|-------------------|
| Level 5 补丁生成 | LLM (GPT-4o 等) | 否 | 否（仅在规则全部失败后触发） |
| LLM 差异分析 | LLM | 否 | 否（仅用于验证失败的辅助分析） |
| 代码语义匹配 | SequenceMatcher | 是 | 否（纯确定性算法） |
| Diff 包含度 | Multiset 计数 | 是 | 否（纯确定性算法） |

### 13.2 AI 补丁生成流程

```
输入:
  - 原始补丁 (diff)
  - 目标文件相关代码段
  - 冲突分析结果 (expected vs actual)

→ Prompt 构建 (结构化上下文)
→ LLM 调用 (OpenAI 兼容 API)
→ 输出解析 (提取 unified diff)
→ 格式校验 (diff header / hunk header)
→ 应用性验证 (git apply --check)
→ 标记为 ai-generated (强制人工审查)
```

**核心模块**：`core/ai_patch_generator.py` — `AIPatchGenerator` 类

### 13.3 设计原则

1. **AI 作为最后手段**：仅在 Level 0-4 全部失败后触发
2. **输出必须可验证**：AI 生成的补丁必须通过 `git apply --check`
3. **强制人工审查**：AI 输出标记为需审查，不允许自动合入
4. **可选配置**：默认关闭，需显式启用

---

## 附录 A: 算法复杂度汇总

| 算法 | 时间复杂度 | 空间复杂度 | 备注 |
|------|-----------|-----------|------|
| L1 ID 匹配 | O(log n) | O(1) | Git DAG 遍历 |
| L2 Subject 匹配 | O(k × m) | O(k) | k=候选数, m=subject长度 |
| L3 Diff 匹配 | O(c × d) | O(d) | c=候选数, d=diff行数 |
| Diff 包含度 | O(s + t) | O(t) | s=源行数, t=目标行数 |
| 锚点行定位 | O(W) | O(1) | W=窗口大小(600) |
| 精确序列匹配 | O(F × N) | O(1) | F=文件行数, N=序列长度 |
| 模糊序列匹配 | O(F × N × L) | O(1) | L=平均行长度 |
| 逐行投票 | O(N × F) | O(N) | N=序列行数 |
| 代码语义匹配 | O(F × W × L) | O(W) | W=窗口大小 |
| 冲突分析 | O(H × F) | O(F) | H=hunk数 |

---

## 附录 B: 阈值参数参考

| 参数 | 默认值 | 含义 | 可调整位置 |
|------|--------|------|-----------|
| Subject 相似度阈值 | 0.85 | L2 subject 匹配最低相似度 | `agents/analysis.py` |
| Diff 相似度阈值 | 0.70 | L3 diff 匹配最低得分 | `agents/analysis.py` |
| 锚点行精确匹配 | 1.0 | 完全一致 | `agents/dryrun.py` |
| 锚点行模糊匹配 | 0.85 | SequenceMatcher 最低比率 | `agents/dryrun.py` |
| 模糊序列匹配 (短) | 0.45 | ≤3 行序列的最低得分 | `agents/dryrun.py` |
| 模糊序列匹配 (长) | 0.50 | >3 行序列的最低得分 | `agents/dryrun.py` |
| 投票行最低长度 | 5 | 参与投票的行最短字符数 | `agents/dryrun.py` |
| 投票行模糊匹配 | 0.70 | 单行匹配最低比率 | `agents/dryrun.py` |
| 最长行匹配 | 0.60 | 最长行搜索最低比率 | `agents/dryrun.py` |
| 冲突 L1 阈值 | 0.85 | 轻微差异 | `agents/dryrun.py` |
| 冲突 L2 阈值 | 0.50 | 中度差异 | `agents/dryrun.py` |
| 代码语义匹配 | 0.70 | 多维度综合最低得分 | `core/code_matcher.py` |
| 搜索窗口大小 | 300 | 行号 hint ± 窗口 | `agents/dryrun.py` |
| 依赖相邻重叠距离 | 50 | hunk 间距判定阈值 | `agents/dependency.py` |
| 包含度噪声行长度 | 4 | 过滤短行的最短字符数 | `core/matcher.py` |
