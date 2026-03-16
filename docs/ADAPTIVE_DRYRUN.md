# 五级自适应 DryRun 算法详解

## 概述

DryRun Agent 实现了一个**五级渐进式补丁试应用引擎**，从严格的 `strict` 模式逐步降级到高度自适应的 `conflict-adapted` 模式，最终提供精确的逐 hunk 冲突分析。这个设计解决了社区补丁在企业自维护仓库中无法直接应用的核心难题。

## 五级策略概览

```
补丁输入
  │
  ├─ Level 0: strict
  │   └─ git apply --check
  │       成功 ✔ → 返回 (apply_method="strict")
  │       失败 ↓
  │
  ├─ Level 1: context-C1
  │   └─ git apply --check -C1
  │       成功 ✔ → 返回 (apply_method="context-C1")
  │       失败 ↓
  │
  ├─ Level 2: 3way
  │   └─ git apply --check --3way
  │       成功 ✔ → 返回 (apply_method="3way")
  │       失败 ↓
  │
  ├─ Level 3: regenerated
  │   └─ _regenerate_patch (从目标文件重建 context)
  │       成功 ✔ → 返回 (apply_method="regenerated")
  │       失败 ↓
  │
  ├─ Level 4: conflict-adapted
  │   └─ _analyze_conflicts + 冲突适配
  │       成功 ✔ → 返回 (apply_method="conflict-adapted")
  │       失败 ↓
  │
  └─ 全部失败
      └─ 返回完整冲突分析报告 (conflict_hunks)
```

## 详细算法

### Level 0: Strict 模式

**命令**：`git apply --check`

**原理**：标准 Git 补丁应用检查，要求 context 行精确匹配。

**适用场景**：
- 补丁来自同一分支或版本
- 目标文件未经修改
- 无任何 context 偏移

**失败原因**：
- Context 行不匹配（中间 commit 修改了相邻行）
- 文件路径不存在（跨版本路径重组）
- 补丁涉及的代码已被修改

---

### Level 1: Context-C1 模式

**命令**：`git apply --check -C1`

**原理**：降低 context 匹配要求，仅需 1 行 context 匹配而非全部。

**适用场景**：
- 中间 commit 修改了补丁 context 的部分行
- 行号偏移不超过几行
- 补丁核心代码（+/- 行）未被修改

**失败原因**：
- Context 偏移超过 1 行
- 补丁涉及的代码被修改
- 3-way merge 无法自动解决

---

### Level 2: 3-Way Merge 模式

**命令**：`git apply --check --3way`

**原理**：使用三方合并算法，利用 base blob（补丁生成时的原始文件）进行智能冲突解决。

**适用场景**：
- Base blob 在 Git 对象库中可用
- 目标文件与 base 有共同祖先
- 冲突可通过三方合并自动解决

**失败原因**：
- Base blob 不可用（补丁来自不同仓库）
- 三方合并产生冲突标记
- 补丁和目标文件的修改无法自动合并

---

### Level 3: 上下文重生成模式

**命令**：`_regenerate_patch(patch, target_file)`

**原理**：
1. 在目标文件中定位补丁的变更点（使用两层定位架构）
2. 从目标文件提取正确的 context 行
3. 保留补丁的 +/- 行不变
4. 重建补丁并尝试应用

**核心算法：两层定位架构**

#### 第一层：`_locate_hunk` — Hunk 级变更点定位

返回 `(change_pos, n_remove)`：
- `change_pos`：变更点在目标文件中的行号
- `n_remove`：需删除的行数（纯添加 hunk 为 0）

**有删除行的 hunk**：
```python
def _locate_removal_hunk(removed, ctx_before, ctx_after, file_lines, hint_line, func_name):
    # A) 直接搜索 removed 行序列
    pos = _locate_in_file(removed, ctx_all, file_lines, hint_line, func_name)
    if pos: return pos, len(removed)
    
    # B) before-context 最后一行做锚点
    if ctx_before:
        anchor = _find_anchor_line(ctx_before[-1], file_lines, hint_line)
        if anchor: return anchor + 1, len(removed)
    
    # C) after-context 第一行做锚点
    if ctx_after:
        anchor = _find_anchor_line(ctx_after[0], file_lines, hint_line)
        if anchor: return max(0, anchor - len(removed)), len(removed)
    
    # D) Level 8: 代码语义匹配
    pos = code_matcher.find_removed_lines(removed, file_lines, hint_line)
    if pos: return pos, len(removed)
    
    return None, len(removed)
```

**纯添加的 hunk**：
```python
def _locate_addition_hunk(ctx_before, ctx_after, added, file_lines, hint_line, func_name):
    # A) before-context 最后一行做锚点 → 插入点 = 锚点 + 1  ★关键
    if ctx_before:
        anchor = _find_anchor_line(ctx_before[-1], file_lines, hint_line)
        if anchor: return anchor + 1, 0
    
    # B) after-context 第一行做锚点 → 插入点 = 锚点
    if ctx_after:
        anchor = _find_anchor_line(ctx_after[0], file_lines, hint_line)
        if anchor: return anchor, 0
    
    # ... 其他策略 ...
    
    # F) Level 8: 代码语义匹配
    pos = code_matcher.find_insertion_point(ctx_before, ctx_after, file_lines, hint_line)
    if pos: return pos, 0
    
    return None, 0
```

**锚点行定位的关键创新**：

```
问题场景:
  Mainline patch (纯添加 hunk):
    ctx_before[-1] = "static struct kmem_cache *dquot_cachep;"  ← 锚点行
    + 新增代码
    ctx_after[0]  = "static int nr_dquots;"

  企业内部文件:
    line 1: ...module_names[] = INIT_QUOTA_MODULE_NAMES;
    line 2: (empty)
    line 3: /* custom comment */  ← 额外行, 打断了 context 序列
    line 4: static struct kmem_cache *dquot_cachep;  ← 锚点命中!
    line 5: static int nr_dquots;

解法:
  不搜索整段 6 行 context，而是只搜索变更边界的单行锚点
  → 单行搜索不受 context 序列中间额外行的影响
  → 利用行号 hint + 偏移修正缩小搜索窗口 (±300 行)
  → 先精确匹配，再 SequenceMatcher ≥ 0.85 模糊匹配
  → anchor = 4 → insert_point = 5 ✔
```

#### 第二层：`_locate_in_file` — 序列级搜索引擎

当锚点行搜索不适用时（如 removed 行序列搜索），使用七策略渐进式搜索：

| 策略 | 算法 | 适用场景 |
|------|------|---------|
| 1 | 精确序列匹配 | 序列在文件中完全一致（strip 后） |
| 2 | 函数名锚点搜索 | 从 `@@` 行提取函数名，限定函数作用域 |
| 3 | 行号提示窗口 | 利用 hunk header 行号 hint，±300 行窗口搜索 |
| 4 | 全局逐行模糊匹配 | SequenceMatcher 加权评分，短序列阈值 0.45 |
| 5 | Context 行重试 | 用 context 行重新尝试策略 1-4 |
| 6 | 逐行投票 | 每行独立匹配，位置估算众数 |
| 7 | 最长行最佳匹配 | 选信息量最大的行做 fuzzy match |

**逐行投票算法**（策略 6）：

```python
def _find_by_line_voting(needle, haystack):
    """
    每行独立匹配，收集位置估算，取众数
    """
    votes = Counter()
    
    for needle_idx, needle_line in enumerate(needle):
        # 在 haystack 中找最匹配的行
        best_match_idx = _find_best_line_match(needle_line, haystack)
        if best_match_idx is not None:
            # 估算序列起始位置
            estimate = best_match_idx - needle_idx
            votes[estimate] += 1
    
    if votes:
        best_start, _ = votes.most_common(1)[0]
        return best_start
    return None
```

**示例**：
```
needle:                          haystack 匹配    estimate = file_pos - idx
  [0] "dquot_cachep;"    →    line 4      →  4 - 0 = 4
  [1] "nr_dquots;"       →    line 5      →  5 - 1 = 4
  [2] "reserved_space;"  →    line 6      →  6 - 2 = 4
  [3] "quota_format;"    →    line 7      →  7 - 3 = 4

votes: {4: 4} → best_start = 4 ✔
即使中间有额外行，大多数行对起始位置的估算仍一致
```

**跨 hunk 偏移传播**：

```python
file_offset = 0  # 同文件的累积偏移

for hunk_header, hunk_lines in hunks:
    # 定位 hunk
    change_pos, n_remove = _locate_hunk(hunk_lines, file_lines, 
                                        hint_line + file_offset, func_name)
    
    if change_pos is not None and hint_line:
        # 计算实际偏移
        expected_start = hint_line - 1
        actual_start = change_pos - len(ctx_before)
        file_offset = actual_start - expected_start  # ← 传播到下一个 hunk
```

**补丁重建**：

```python
def _regenerate_patch(patch_diff, target_file):
    """
    从目标文件重建补丁，保证 context 正确
    """
    for file_path, hunks in parsed_hunks:
        for hunk_header, hunk_lines in hunks:
            # 定位变更点
            change_pos, n_remove = _locate_hunk(hunk_lines, file_lines, ...)
            
            if change_pos is None:
                continue  # 无法定位，保留原始 hunk
            
            # 从目标文件提取 context
            ctx_n = 3
            start = max(0, change_pos - ctx_n)
            end = min(len(file_lines), change_pos + n_remove + ctx_n)
            
            # 重建 hunk
            rebuilt = []
            for i in range(start, change_pos):
                rebuilt.append(" " + file_lines[i])  # context
            for i in range(change_pos, change_pos + n_remove):
                rebuilt.append("-" + file_lines[i])  # 实际 - 行
            for a in added_lines:
                rebuilt.append("+" + a)  # 原始 + 行不变
            for i in range(change_pos + n_remove, end):
                rebuilt.append(" " + file_lines[i])  # context
            
            # 生成新 hunk header
            oc = sum(1 for l in rebuilt if l.startswith(" ") or l.startswith("-"))
            nc = sum(1 for l in rebuilt if l.startswith(" ") or l.startswith("+"))
            new_header = f"@@ -{start+1},{oc} +{start+1},{nc} @@"
            
            output.append(new_header)
            output.extend(rebuilt)
```

**适用场景**：
- Context 严重偏移（中间 commit 修改了多行相邻代码）
- 补丁核心代码（+/- 行）未被修改
- 行号偏移可通过定位算法精确计算

**失败原因**：
- 无法定位变更点（代码结构完全改变）
- 补丁涉及的代码被修改
- 多个 hunk 的偏移不一致

---

### Level 4: 冲突适配模式

**算法**：`_analyze_conflicts` + 冲突适配补丁生成

**原理**：
1. 对每个 hunk 执行定位和对比
2. 提取补丁期望的 `-` 行和文件实际行
3. 逐行比较，计算相似度
4. 分级：L1 (≥85%) / L2 (50-85%) / L3 (<50%)
5. 对 L1/L2 级 hunk 生成冲突适配补丁
6. 尝试应用适配补丁

**冲突分级**：

| 级别 | 相似度 | 含义 | 处理 |
|------|--------|------|------|
| **L1** | ≥ 85% | 轻微差异（变量重命名、空格变动） | 自动适配 |
| **L2** | 50-85% | 中度差异（部分重构） | 自动适配 + 人工审查 |
| **L3** | < 50% | 重大差异（代码大幅改写） | 需人工手动合入 |

**冲突适配补丁生成**：

```python
def _generate_adapted_patch(hunk_header, expected, added, actual, file_lines, change_pos):
    """
    用目标文件实际行替换补丁的 - 行，保留 + 行
    """
    ctx_n = 3
    start = max(0, change_pos - ctx_n)
    
    rebuilt = []
    
    # Context 行（before）
    for i in range(start, change_pos):
        rebuilt.append(" " + file_lines[i])
    
    # 替换 - 行为实际行
    for actual_line in actual:
        rebuilt.append("-" + actual_line)
    
    # 保留 + 行不变
    for added_line in added:
        rebuilt.append("+" + added_line)
    
    # Context 行（after）
    end = min(len(file_lines), change_pos + len(actual) + ctx_n)
    for i in range(change_pos + len(actual), end):
        rebuilt.append(" " + file_lines[i])
    
    return rebuilt
```

**示例**：

```
原始补丁:
  @@ -162,6 +162,9 @@
   static struct kmem_cache *dquot_cachep;
  +static struct workqueue_struct *dquot_wq;
  +static DEFINE_MUTEX(dquot_lock);
  +static int dquot_count;
   static int nr_dquots;

文件实际内容（line 162-167）:
  162: static struct kmem_cache *dquot_cachep;
  163: /* custom field */
  164: static int nr_dquots;
  165: ...

冲突分析:
  expected: ["static struct kmem_cache *dquot_cachep;"]
  actual:   ["static struct kmem_cache *dquot_cachep;", "/* custom field */"]
  相似度: 0.5 → L2 级冲突

冲突适配补丁:
  @@ -162,7 +162,10 @@
   static struct kmem_cache *dquot_cachep;
  -/* custom field */
  +static struct workqueue_struct *dquot_wq;
  +static DEFINE_MUTEX(dquot_lock);
  +static int dquot_count;
   static int nr_dquots;
```

**适用场景**：
- 中间 commit 修改了补丁涉及的同一行代码
- 修改是局部的（不影响整体逻辑）
- 补丁的 + 行（新增代码）仍然有效

**失败原因**：
- 冲突过于复杂（多行交叉修改）
- 适配后的补丁仍无法应用
- 需要人工审查和手动合入

---

## 路径映射感知

DryRun Agent 在两个层面应用路径映射：

### 1. Diff 路径重写

```python
def _rewrite_diff_paths(self, diff_text: str) -> str:
    """
    将补丁中的 upstream 路径替换为 local 路径
    例如: fs/smb/client/ → fs/cifs/
    """
    lines = diff_text.split("\n")
    result = []
    for line in lines:
        if line.startswith("diff --git"):
            for up, lo in self.path_mapper._rules:
                line = line.replace(f"a/{up}", f"a/{lo}")
                line = line.replace(f"b/{up}", f"b/{lo}")
        elif line.startswith("--- a/") or line.startswith("+++ b/"):
            prefix = line[:6]
            path = line[6:]
            for up, lo in self.path_mapper._rules:
                if path.startswith(up):
                    path = lo + path[len(up):]
                    break
            line = prefix + path
        result.append(line)
    return "\n".join(result)
```

### 2. 文件查找回退

```python
def _resolve_file_path(self, file_path: str, repo_path: str) -> Optional[str]:
    """
    先查原始路径，失败则尝试所有映射变体
    """
    target = os.path.join(repo_path, file_path)
    if os.path.isfile(target):
        return target
    
    if self.path_mapper:
        for variant in self.path_mapper.translate(file_path):
            if variant != file_path:
                t = os.path.join(repo_path, variant)
                if os.path.isfile(t):
                    return t
    
    return None
```

---

## Stable Backport 补丁优先

Pipeline 在执行 DryRun 前，自动从 CVE 的 `version_commit_mapping` 中查找与目标分支版本最匹配的 stable backport 补丁。

```python
def _find_stable_patch(self, cve_info, target_version: str):
    """
    从 target_version (如 "5.10-hulk") 提取 major.minor 前缀 "5.10"
    在 version_commit_mapping 中查找 5.10.x 的 backport commit
    """
    tv_prefix = target_version.split("-")[0]  # "5.10"
    
    # 查找匹配的 backport
    for version, commit_id in cve_info.version_commit_mapping.items():
        if version.startswith(tv_prefix):
            return commit_id
    
    # 回退到最近低版本 backport
    return None
```

**优势**：
- Stable backport 的路径和 context 与目标分支更一致
- 大幅提高 DryRun 的成功率
- 减少冲突分析的复杂性

---

## 代码语义匹配（Level 8 策略）

当所有传统序列匹配策略失败时，使用代码语义匹配作为最后手段。

**多维度相似度**：

```python
score = 0.5 × structure_sim (SequenceMatcher 编辑距离)
      + 0.3 × identifier_match_rate (变量名/函数名交集)
      + 0.2 × keyword_sequence_sim (关键字序列相似度)
```

**示例**：

```
目标代码:
  ["int dquot_cachep;", "int nr_dquots;"]

文件内容:
  line 1: // quota system
  line 2: static struct dquot_hash_table {
  line 3:     struct hlist_head *hash;
  line 4:     int dquot_cachep;
  line 5:     int nr_dquots;
  line 6:     spinlock_t lock;
  line 7: } dquot_table;

匹配过程:
  1. 提取目标标识符: {int, dquot_cachep, nr_dquots}
  2. 在文件中搜索包含这些标识符的行
  3. line 4-5 匹配度最高 (0.94)
  4. 返回 line 4 作为定位点
```

---

## 性能特性

| 指标 | 数据 |
|------|------|
| 平均定位时间 | < 100ms (单 hunk) |
| 最坏情况 | 七策略全部尝试 (~500ms) |
| 内存占用 | O(file_size) 用于文件内容缓存 |
| 缓存命中率 | 同文件多 hunk 的偏移传播提高 ~80% 命中率 |

---

## 总结

五级自适应 DryRun 算法通过**渐进式降级策略**和**两层定位架构**，在面对复杂的补丁应用场景时提供了最大的灵活性和准确性。从严格的 `strict` 模式到高度自适应的 `conflict-adapted` 模式，每一级都针对特定的冲突类型进行了优化，最终为分析人员提供了精确的冲突诊断和自动适配能力。
