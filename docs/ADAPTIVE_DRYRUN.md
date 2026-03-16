# 五级自适应 DryRun 算法详解

## 🎯 核心概念（用生活类比理解）

想象你要把一份**社区食谱**（mainline patch）应用到你的**家庭厨房**（企业仓库）。但问题是：

- **社区食谱**是基于标准厨房写的
- **你的厨房**经过了多次改装（中间 commit 修改了代码）
- 有些工具位置不同（路径重组）
- 有些食材已经换过（代码被修改）

**五级自适应 DryRun** 就像一个聪明的厨师，他会：

1. **先试试原始食谱** — 也许你的厨房还是标准的
2. **放宽一些要求** — 也许只需要找到关键工具就行
3. **用三方参考** — 也许能从原始厨房的照片推断出来
4. **重新调整食谱** — 根据你的厨房实际情况改写食谱
5. **创意改编** — 用你现有的食材和工具完成菜肴

---

## 📊 五级策略概览

```
补丁输入
  │
  ├─ Level 0: strict (严格模式)
  │   └─ 要求: 完全匹配
  │       成功 ✔ → 返回
  │       失败 ↓ (补丁和文件不匹配)
  │
  ├─ Level 1: context-C1 (放宽要求)
  │   └─ 要求: 至少 1 行匹配
  │       成功 ✔ → 返回
  │       失败 ↓ (偏移太大)
  │
  ├─ Level 2: 3way (三方合并)
  │   └─ 要求: 有原始版本参考
  │       成功 ✔ → 返回
  │       失败 ↓ (无法自动合并)
  │
  ├─ Level 3: regenerated (重建补丁)
  │   └─ 要求: 能找到变更点
  │       成功 ✔ → 返回
  │       失败 ↓ (找不到位置)
  │
  ├─ Level 4: conflict-adapted (冲突适配)
  │   └─ 要求: 能理解冲突
  │       成功 ✔ → 返回
  │       失败 ↓ (冲突太复杂)
  │
  └─ 全部失败
      └─ 返回详细冲突分析报告
```

---

## 🔍 详细算法

### Level 0: Strict 模式 — "完美匹配"

**类比**：就像拼图，要求每一块都完全吻合

**工作原理**：
```
社区补丁的 context 行:
  line 1: static struct kmem_cache *dquot_cachep;
  line 2: static int nr_dquots;

你的文件:
  line 162: static struct kmem_cache *dquot_cachep;
  line 163: static int nr_dquots;

结果: ✔ 完全匹配！补丁可以直接应用
```

**何时成功**：
- 补丁来自同一分支（比如都是 5.10 版本）
- 你的文件没有被其他 commit 修改过
- 行号完全对齐

**何时失败**：
- 中间有其他 commit 修改了相邻的行
- 文件路径在不同版本中不同
- 补丁涉及的代码已经被改过

---

### Level 1: Context-C1 模式 — "放宽要求"

**类比**：不要求完全匹配，只要找到关键特征就行

**工作原理**：
```
社区补丁期望的 context:
  line 1: static struct kmem_cache *dquot_cachep;
  line 2: static int nr_dquots;

你的文件（中间多了一行）:
  line 162: static struct kmem_cache *dquot_cachep;
  line 163: /* custom comment */  ← 额外的行
  line 164: static int nr_dquots;

strict 模式: ✘ 失败（3 行不匹配 2 行）
-C1 模式: ✔ 成功（至少有 1 行匹配）
```

**何时成功**：
- 中间 commit 只修改了几行
- 补丁的核心代码（+/- 行）没被改过
- 偏移不超过几行

**何时失败**：
- 偏移太大（超过 1 行）
- 补丁要删除的代码已经被改过
- 无法自动合并

---

### Level 2: 3-Way Merge 模式 — "三方参考"

**类比**：就像调解纠纷，有三方信息：原始版本、社区版本、你的版本

**工作原理**：
```
原始版本 (base):
  static struct kmem_cache *dquot_cachep;
  static int nr_dquots;

社区版本 (patch):
  static struct kmem_cache *dquot_cachep;
  + static struct workqueue_struct *dquot_wq;
  static int nr_dquots;

你的版本 (target):
  static struct kmem_cache *dquot_cachep;
  /* custom comment */
  static int nr_dquots;

三方合并: 
  ✔ 可以推断出: 在 dquot_cachep 后面插入新代码，
    即使中间多了一行注释
```

**何时成功**：
- Git 对象库中有原始版本（base blob）
- 冲突可以自动解决
- 三方合并能推断出正确的结果

**何时失败**：
- 原始版本不可用（补丁来自不同仓库）
- 冲突太复杂，无法自动解决
- 补丁和你的修改有真正的语义冲突

---

### Level 3: Regenerated 模式 — "重建补丁" ⭐ 核心创新

**类比**：就像一个聪明的编辑，根据你的文件重新写补丁

**核心问题**：
```
社区补丁说: "在第 162 行后面插入新代码"
但你的文件: 第 162 行是对的，但第 163 行多了一行注释
           所以实际应该在第 164 行后面插入

怎么办？ → 重新定位！找到真正的插入点
```

#### 🎯 两层定位架构

**第一层：锚点行定位** — 找到关键的"地标"

```
问题: 补丁的 context 被打断了
  社区补丁:
    ctx_before[-1] = "static struct kmem_cache *dquot_cachep;"  ← 地标
    + 新增代码
    ctx_after[0]  = "static int nr_dquots;"

  你的文件:
    line 162: static struct kmem_cache *dquot_cachep;  ← 找到地标！
    line 163: /* custom comment */  ← 额外行（被打断）
    line 164: static int nr_dquots;

解法: 不搜索整段 context，只搜索单行地标
  → 单行搜索不受中间额外行的影响
  → 找到地标后，插入点 = 地标行号 + 1 = 163
```

**为什么这样做**：
- 传统方法：搜索 6 行连续的 context → 失败（被打断了）
- 新方法：只搜索 1 行地标 → 成功（不受打断影响）

**第二层：七策略序列搜索** — 如果地标也找不到

当锚点行搜索失败时，使用 7 个递进式策略：

| 策略 | 做什么 | 何时用 |
|------|--------|--------|
| 1 | 精确匹配 | 代码完全一样 |
| 2 | 函数名搜索 | 知道在哪个函数里 |
| 3 | 行号窗口 | 知道大概在哪个范围 |
| 4 | 模糊匹配 | 代码有点不一样 |
| 5 | Context 重试 | 用 context 行重新尝试 |
| 6 | 逐行投票 | 多行投票找位置 |
| 7 | 最长行匹配 | 用最有特征的行 |

**逐行投票的妙处**：

```
假设要找这 4 行代码的位置:
  [0] "dquot_cachep;"
  [1] "nr_dquots;"
  [2] "reserved_space;"
  [3] "quota_format;"

在文件中逐行搜索:
  [0] "dquot_cachep;" → 找到在 line 4
  [1] "nr_dquots;" → 找到在 line 5
  [2] "reserved_space;" → 找到在 line 6
  [3] "quota_format;" → 找到在 line 7

计算每行的"起始位置估算":
  line 4 - 0 = 4
  line 5 - 1 = 4
  line 6 - 2 = 4
  line 7 - 3 = 4

投票结果: 4 票都投给位置 4 → 确定起始位置是 4 ✔

即使中间有额外行，大多数行的估算仍然一致！
```

**跨 hunk 偏移传播**：

```
同一个文件有多个 hunk:

Hunk 1: 定位成功，发现实际偏移 = +2 行
        → 记录这个偏移

Hunk 2: 使用 Hunk 1 的偏移信息
        → 搜索范围自动调整
        → 定位更精准

Hunk 3: 使用 Hunk 1+2 的累积偏移
        → 越来越精准
```

**补丁重建过程**：

```
原始补丁:
  @@ -162,6 +162,9 @@
   static struct kmem_cache *dquot_cachep;
  +static struct workqueue_struct *dquot_wq;
  +static DEFINE_MUTEX(dquot_lock);
  +static int dquot_count;
   static int nr_dquots;

定位结果: 变更点在 line 162

从你的文件提取 context:
  line 159-161: context before
  line 162-162: 要删除的行（这里没有）
  line 163-165: context after

重建补丁:
  @@ -159,9 +159,12 @@
   ... context before ...
   static struct kmem_cache *dquot_cachep;
  +static struct workqueue_struct *dquot_wq;
  +static DEFINE_MUTEX(dquot_lock);
  +static int dquot_count;
   /* custom comment */  ← 从你的文件提取
   static int nr_dquots;
   ... context after ...

关键: + 行完全不变，只更新了 context 行
```

**何时成功**：
- 能找到变更点（通过锚点或七策略）
- 补丁的 +/- 行没被改过
- 行号偏移可以计算

**何时失败**：
- 代码结构完全改变，找不到变更点
- 补丁要删除的代码已经被改过
- 多个 hunk 的偏移不一致

---

### Level 4: Conflict-Adapted 模式 — "冲突适配"

**类比**：就像一个灵活的编辑，能理解冲突并创意改编

**工作原理**：

```
补丁期望删除:
  - static int old_field;

你的文件实际有:
  - static int old_field;
  - /* custom field */

冲突分析:
  期望: ["static int old_field;"]
  实际: ["static int old_field;", "/* custom field */"]
  相似度: 50% → L2 级冲突（中度）

冲突适配:
  用你的文件实际行替换补丁的 - 行:
  - static int old_field;
  - /* custom field */
  
  保留补丁的 + 行不变:
  + static struct workqueue_struct *dquot_wq;
  + static DEFINE_MUTEX(dquot_lock);
  + static int dquot_count;

结果: ✔ 生成适配补丁，可以应用
```

**冲突分级**：

| 级别 | 相似度 | 含义 | 例子 |
|------|--------|------|------|
| **L1** | ≥ 85% | 轻微差异 | 变量重命名、空格变动 |
| **L2** | 50-85% | 中度差异 | 部分重构、多了几行 |
| **L3** | < 50% | 重大差异 | 代码大幅改写 |

**何时成功**：
- 冲突是局部的（不影响整体逻辑）
- 补丁的新增代码（+ 行）仍然有效
- L1/L2 级冲突可以自动适配

**何时失败**：
- 冲突太复杂（多行交叉修改）
- 补丁的新增代码与现有代码冲突
- 需要人工审查和手动合入

---

## 🗺️ 路径映射感知

**问题**：Linux 内核在版本演进中会重组目录

```
社区补丁 (mainline 6.2):
  fs/smb/client/connect.c

你的仓库 (5.10):
  fs/cifs/connect.c

怎么办？ → 自动翻译路径
```

**解决方案**：

```python
# 内置映射规则
fs/smb/client/ → fs/cifs/
fs/smb/server/ → fs/ksmbd/
drivers/gpu/drm/i915/display/ → drivers/gpu/drm/i915/

# 应用到补丁
补丁中的路径: fs/smb/client/connect.c
翻译后: fs/cifs/connect.c
在你的仓库中查找: ✔ 找到！
```

---

## 🎁 Stable Backport 补丁优先

**概念**：优先使用为你的版本专门制作的补丁

```
CVE 修复有多个版本:
  - mainline (7.x) 的修复
  - 5.15 stable backport
  - 5.10 stable backport  ← 你的版本！
  - 5.4 stable backport

选择策略:
  1. 查找 5.10 backport → ✔ 找到！使用它
  2. 如果没有，查找 5.4 backport
  3. 最后才用 mainline

为什么？
  - 5.10 backport 的 context 和路径与你的仓库最匹配
  - 大幅提高成功率
  - 减少冲突
```

---

## 🧠 代码语义匹配（Level 8 策略）

**问题**：当所有传统方法都失败时怎么办？

**解决方案**：用代码的"意思"而不是"形式"来匹配

```
补丁要找的代码:
  int dquot_cachep;
  int nr_dquots;

你的文件中:
  line 1: // quota system
  line 2: static struct dquot_hash_table {
  line 3:     struct hlist_head *hash;
  line 4:     int dquot_cachep;  ← 找到！
  line 5:     int nr_dquots;     ← 找到！
  line 6:     spinlock_t lock;
  line 7: } dquot_table;

匹配过程:
  1. 提取关键词: {int, dquot_cachep, nr_dquots}
  2. 在文件中搜索包含这些关键词的行
  3. line 4-5 匹配度最高 (94%)
  4. 返回 line 4 作为定位点 ✔
```

**多维度相似度**：

```
score = 0.5 × 结构相似度 (编辑距离)
      + 0.3 × 标识符匹配率 (变量名/函数名)
      + 0.2 × 关键字相似度 (关键字序列)

例子:
  补丁代码: "int dquot_cachep;"
  文件代码: "static int dquot_cachep;"
  
  结构相似度: 0.9 (只多了 static)
  标识符匹配: 1.0 (完全相同)
  关键字相似度: 0.8 (都有 int)
  
  最终分数: 0.5×0.9 + 0.3×1.0 + 0.2×0.8 = 0.91 ✔
```

---

## 📈 性能特性

| 指标 | 数据 | 含义 |
|------|------|------|
| 平均定位时间 | < 100ms | 单个 hunk 的定位很快 |
| 最坏情况 | ~500ms | 七策略全部尝试 |
| 内存占用 | O(file_size) | 与文件大小成正比 |
| 缓存命中率 | ~80% 提升 | 偏移传播大幅提高命中率 |

---

## 🎓 总结

**五级自适应 DryRun** 就像一个聪明的厨师：

1. **先试试原始食谱** — 也许能直接用
2. **放宽一些要求** — 也许只需要关键部分匹配
3. **用三方参考** — 也许能从原始版本推断
4. **重新调整食谱** — 根据你的厨房重建食谱
5. **创意改编** — 理解冲突并创意解决

每一级都针对特定的问题场景优化，最终为你提供：
- ✔ 补丁能否应用
- ✔ 如何应用
- ✔ 哪里有冲突
- ✔ 如何解决冲突

**核心创新**：
- 🎯 **锚点行定位** — 不受 context 被打断的影响
- 📊 **逐行投票** — 多行投票找位置
- 🔄 **偏移传播** — 同文件多 hunk 越来越精准
- 🧠 **代码语义匹配** — 用代码的"意思"而不是"形式"
