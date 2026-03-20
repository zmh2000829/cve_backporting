---
marp: true
theme: default
paginate: true
backgroundColor: #fff
style: |
  section {
    font-family: 'PingFang SC', 'Microsoft YaHei', sans-serif;
  }
  h1 { color: #1a1a2e; }
  h2 { color: #16213e; }
  strong { color: #e94560; }
  code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; }
  table { font-size: 0.8em; }
  .columns { display: flex; gap: 2em; }
  .col { flex: 1; }
---

<!-- _class: lead -->
<!-- _backgroundColor: #0f3460 -->
<!-- _color: white -->

# CVE Backporting Engine

### Linux 内核漏洞补丁智能回溯引擎

**一条命令，从 CVE 编号到可落地的 Backport 方案**

<br>

汇报人：XXX
日期：2026年3月

---

# 目录

1. **项目背景与痛点** — 为什么需要这个工具
2. **核心价值** — 对比传统流程的效率提升
3. **系统架构** — 四大 Agent 协同流水线 + 每个 Agent 详解
4. **核心技术创新**
   - 4A: 多级自适应 DryRun 引擎 — 每一级解决什么场景
   - 4B: 七策略序列搜索引擎 — 每种策略的适用场景与示例
   - 4C: 全流程串联示例 — 从 CVE 编号到可用补丁的完整过程
5. **关键算法** — Diff 包含度 / 代码语义匹配 / 算法协作关系
6. **AI 集成能力** — LLM 辅助补丁生成与根因分析
7. **v2.0 深度分析** — 漏洞分析 / 关联补丁完整分析 / 风险收益 / 合入建议
8. **分析过程可视化** — Analysis Narrative + 深度分析 TUI 面板
9. **性能指标与验证** — 闭环量化评估
10. **Demo 演示** — 真实 CVE 分析全流程
11. **原理深度剖析** — 前置补丁决策 / 符号映射 / L5 原理 / 闭环验证
12. **质疑与挑战回应** — 12 个常见技术质疑的详细回应
13. **总结与展望**

---

<!-- _class: lead -->
<!-- _backgroundColor: #e94560 -->
<!-- _color: white -->

# 01 项目背景与痛点

---

# 企业 Linux 内核安全维护的困境

### 背景

企业自维护 Linux 内核分支（如 5.10-hulk）需要持续跟踪并修复上游社区披露的 **CVE 安全漏洞**。

### 核心痛点

| 痛点 | 影响 |
|------|------|
| 📋 **情报分散** | CVE 信息分布在 MITRE、googlesource、邮件列表等多处，人工逐一查找耗时 |
| 🔍 **定位困难** | 企业仓库 commit ID 因 cherry-pick 改变，subject 被修改，传统搜索失效 |
| 🧩 **Squash 盲区** | 企业常将多个社区补丁合并提交，传统 diff 对比完全失效 |
| 📂 **路径重组** | 内核版本演进中子系统目录变更，搜索存在盲区 |
| ⚠️ **冲突不可控** | `git apply` 失败后只有晦涩报错，无法指导修复 |
| ⏱️ **效率瓶颈** | 单个 CVE 人工分析需 **2-4 小时**，百万级 commit 搜索更是漫长 |

---

# 规模与挑战

```
企业内核仓库规模
  ├─ 千万级 Commit 历史
  ├─ 数百个自定义补丁（偏离上游）
  ├─ 跨版本目录重组（8+ 子系统迁移）
  └─ 每年 1000+ CVE 需要评估

传统流程 (人工)                    自动化目标
  ┌──────────────┐                ┌──────────────┐
  │ 2-4 小时/CVE  │  ──────────►  │ 15-30 秒/CVE  │
  │ 人工搜索比对  │               │ 全自动分析     │
  │ 冲突黑箱      │               │ 精确冲突诊断   │
  │ 无法量化      │               │ P/R/F1 评估    │
  └──────────────┘                └──────────────┘
```

**目标：将 CVE 补丁回溯从"手工艺"变为"工业流水线"**

---

<!-- _class: lead -->
<!-- _backgroundColor: #1a1a2e -->
<!-- _color: white -->

# 02 核心价值

---

# 传统流程 vs 本工具

| 环节 | 传统人工流程 | CVE Backporting Engine |
|------|------------|----------------------|
| 情报获取 | 手动查 MITRE、googlesource、邮件列表 | **Crawler Agent** 三级数据源自动回退 |
| Commit 搜索 | `git log --grep` + 肉眼比对 | **三级搜索引擎** ID→Subject→Diff |
| Squash 识别 | 完全失效 | **Diff 包含度算法** (Multiset) |
| 路径适配 | 手动查找旧路径 | **PathMapper** 双向路径翻译 |
| 性能 | 百万 commit → 分钟级 | **SQLite+FTS5** 缓存 → 秒级 |
| 依赖分析 | 凭经验猜测 | **Hunk 级依赖分析** 三级分级 |
| 补丁应用 | `git apply` 失败 → 束手无策 | **多级自适应** DryRun → 自动适配 |
| 分析过程 | 不透明，开发者无法理解决策逻辑 | **Analysis Narrative** 结构化分析叙述 |
| 质量度量 | 无 | **闭环验证** P/R/F1 量化 |

> **效率提升：单 CVE 分析从 2-4 小时 → 15-30 秒**

---

<!-- _class: lead -->
<!-- _backgroundColor: #16213e -->
<!-- _color: white -->

# 03 系统架构

---

# 四大 Agent 协同流水线

```
                    ┌──────────────────────────┐
                    │   Pipeline 编排器          │
                    └──────────┬───────────────┘
           ┌───────────┬───────┴───────┬────────────┐
           ▼           ▼               ▼            ▼
     ┌──────────┐ ┌──────────┐ ┌────────────┐ ┌──────────┐
     │ Crawler  │ │ Analysis │ │ Dependency  │ │  DryRun  │
     │  Agent   │ │  Agent   │ │   Agent     │ │  Agent   │
     └────┬─────┘ └────┬─────┘ └─────┬──────┘ └────┬─────┘
          │            │             │              │
     MITRE API    三级搜索       Hunk 级重叠     多级自适应
     git.kernel   ID→Subject    函数名交集      补丁应用
     googlesource  →Diff        三级评分        AI 辅助 🤖
```

**设计原则：各 Agent 独立可测试、可单独使用、关注点分离**

---

# Agent 职责一览

| Agent | 输入 | 输出 | 核心算法 |
|-------|------|------|---------|
| **Crawler** | CVE ID | CveInfo + PatchInfo | 三级数据源回退 + 结果互补合并 |
| **Analysis** | 补丁 + 目标仓库 | SearchResult | L1精确ID → L2语义Subject → L3 Diff/包含度 |
| **Dependency** | 修复补丁 + 引入搜索 | 前置依赖列表 | Hunk行范围重叠 + 函数交集 + 评分分级 |
| **DryRun** | 补丁 + 目标仓库 | DryRunResult | **多级自适应** + 内存直改 + 锚点定位 + 语义匹配 |

### 数据流

```
CVE ID → 情报采集 → 引入检测 → 修复定位 → 依赖分析 → 冲突预检 → 决策报告
                                   │
                                   └─ Stable Backport 补丁优先选用
```

---

# Crawler Agent — 多源情报采集

### 功效：**将分散在 3+ 数据源的 CVE 信息，30 秒内聚合为结构化情报**

```
                ┌─────────────────┐
                │  CVE-2024-26633 │
                └────────┬────────┘
                         │
     ┌───────────────────┼───────────────────┐
     ▼                   ▼                   ▼
┌──────────┐      ┌──────────────┐    ┌──────────────┐
│ MITRE API│      │ git.kernel.org│   │ googlesource │
│          │      │  /stable     │    │  (备选)      │
│ 漏洞描述  │      │  /torvalds   │    │  base64 解码  │
│ Fix ID   │      │  format-patch │   │              │
│ Intro ID │      │  完整 diff    │    │              │
│ 版本映射  │      └──────┬───────┘    └──────┬───────┘
└────┬─────┘             │                    │
     │                   │     ← 回退重试 →    │
     └───────────────────┴────────────────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │  CveInfo + PatchInfo │
              │                      │
              │  fix_commit: abc123  │
              │  intro_commit: def456│
              │  5.4→xyz, 5.10→uvw  │  ← 7 个版本映射
              │  diff: 3 files, +42  │
              └──────────────────────┘
```

### 实际示例

```
输入:  CVE-2024-26633
输出:  ├─ mainline fix = 7d4e9532 (v6.8)
       ├─ introduced = a1b2c3d4 (v5.6)
       ├─ 影响范围: v5.6 ~ v6.8
       ├─ 版本映射: {5.4: xxx, 5.10: yyy, 5.15: zzz, 6.1: ...}
       └─ diff: net/ipv6/ip6_output.c (+12 -3)
```

**功效：一次 API 调用 → 获得传统人工需 30 分钟检索的全部情报**

---

# Analysis Agent — 三级搜索引擎

### 功效：**在千万级 commit 仓库中秒级定位补丁，解决 4 类搜索失败场景**

```
┌──────────────────────────────────────────────────────────────────────┐
│ L1: Commit ID 精确匹配                                               │
│                                                                      │
│   场景: 直接 cherry-pick，commit ID 未变                              │
│   方法: git_mgr.commit_exists("7d4e9532")                           │
│   耗时: < 1ms                                                       │
│   示例: 目标仓库直接 cherry-pick 了上游 7d4e9532                      │
│         → L1 命中, confidence = 100%, 短路返回                       │
├──────────────────────────────────────────────────────────────────────┤
│ L2: Subject 语义匹配                                                 │
│                                                                      │
│   场景: cherry-pick 时 commit ID 变了，但 subject 保留/微调           │
│   方法: SQLite FTS5 关键词检索 + SequenceMatcher 语义相似度           │
│   耗时: < 500ms (FTS5 索引加速)                                      │
│   示例: 上游 subject = "ipv6: fix skb_over_panic"                    │
│         企业 subject = "[backport 5.10] ipv6: fix skb_over_panic"    │
│         → normalize 后相似度 0.95 → L2 命中                          │
├──────────────────────────────────────────────────────────────────────┤
│ L3: Diff 代码匹配                                                    │
│                                                                      │
│   场景 A: Subject 被改写 → Diff 双向相似度                           │
│   场景 B: 多个补丁被 squash 成一个 → Diff 包含度 (Multiset)         │
│   方法: PathMapper 路径翻译 + 文件重合度 + 代码匹配                  │
│   耗时: 2-5s                                                        │
│   示例: 企业将 3 个社区补丁合并为 1 个大 commit                      │
│         传统 diff 相似度仅 30% → 失败                                │
│         Multiset 包含度 = 100% (3 个补丁行全部包含) → L3 命中       │
└──────────────────────────────────────────────────────────────────────┘
```

### PathMapper 解决路径盲区

```
上游路径: fs/cifs/cifssmb.c          企业路径: fs/smb/client/cifssmb.c
上游路径: drivers/gpu/drm/i915/...    企业路径: drivers/gpu/drm/xe/...

不做路径映射 → L3 因路径不匹配直接跳过 → 漏检!
PathMapper 双向翻译 → 自动发现等价路径 → 正确匹配
```

---

# Dependency Agent — 前置依赖分析

### 功效：**自动识别"必须先合入哪些补丁"，避免 cherry-pick 后编译/功能异常**

```
修复补丁 abc123 修改了: net/ipv6/ip6_output.c 的 line 162-175

                 时间窗口
                 │← intro_commit ─────────────── HEAD →│
                 │                                      │
  ┌──────────────┼──────────────────────────────────────┤
  │ commit 1     │ 修改 line 100-120  无重叠 → 忽略     │
  │ commit 2     │ 修改 line 170-180  相邻50行内 → 中依赖│
  │ commit 3     │ 修改 line 165-172  直接重叠 → 强依赖 │  ← 必须先合入!
  │ commit 4     │ 修改 line 500-510  无关联 → 忽略      │
  └──────────────┴──────────────────────────────────────┘
```

### 三级评分规则

| 等级 | 条件 | 含义 | 动作建议 |
|------|------|------|---------|
| **强依赖** | 行范围直接重叠 **且** 函数名交集非空 | 必须先合入 | 自动标红提醒 |
| **中依赖** | 行范围相邻(±50行) **或** 仅函数名交集 | 建议审查 | 列出供参考 |
| **弱依赖** | 仅同文件修改 | 可能相关 | 低优先级展示 |

### 实际示例

```
分析 CVE-2024-50154 的修复补丁:
  修改文件: net/sched/sch_api.c, line 842-856, 函数 qdisc_destroy()

  发现前置依赖:
    [强] commit e1a2b3 "sched: add qdisc_lock() helper" — line 840-850 重叠
         → 该补丁引入了 qdisc_lock()，修复补丁调用了它 → 必须先合入
    [中] commit f4g5h6 "sched: refactor notify chain" — line 860-870 相邻
         → 在附近重构了通知链，可能影响上下文
```

---

# DryRun Agent — 多级自适应试应用

### 功效：**将 `git apply` 失败率从 ~60% 降至 ~5%，自动生成可用补丁**

```
传统做法                             多级自适应做法
┌─────────────────────┐            ┌──────────────────────────────────┐
│ git apply patch.diff │            │ L0 失败 → L1 失败 → L2 失败     │
│                      │            │ → L3 锚点定位成功!               │
│ 失败，报错:          │            │   ↓                              │
│ "patch does not      │            │ 自动生成适配补丁                 │
│  apply"              │            │ git apply --check ✔              │
│                      │            │                                  │
│ 束手无策...          │            │ 输出: 可直接使用的 .patch 文件    │
└─────────────────────┘            └──────────────────────────────────┘
```

**核心数据：L3 Regenerated 策略解决了 ~40% 的传统冲突**

---

<!-- _class: lead -->
<!-- _backgroundColor: #e94560 -->
<!-- _color: white -->

# 04 核心技术创新
## 多级自适应 DryRun 引擎

---

# 多级渐进式降级 — 每一级解决什么问题？

```
补丁输入
  │
  ├─ L0:   Strict ──────────── 上下文完全一致    → 最理想情况
  │                            失败 ↓
  ├─ L1:   Context-C1 ──────── 行号小幅偏移      → 附近有少量新增代码
  │                            失败 ↓
  ├─ L2:   3-Way Merge ─────── 双方都有修改      → 同区域非冲突改动
  │                            失败 ↓
  ├─ L5:   Verified-Direct ─── ⭐ 绕过 git apply  → 宏重命名/空白差异/上下文偏移
  │                            失败 ↓
  ├─ L3:   Regenerated ─────── context 被打断    → 企业插入自定义代码
  │                            失败 ↓
  ├─ L3.5: Zero-Context ────── 零上下文 diff     → 上下文严重损坏
  │                            失败 ↓
  ├─ L4:   Conflict-Adapted ── 代码发生实质变更   → removed 行在目标已不同
  │                            失败 ↓
  └─ L6:   AI-Generated ────── 🤖 所有规则失效   → 跨版本大面积重构
```

---

# L0 Strict — 精确匹配，直接应用

### 解决场景

补丁的 context 行与目标文件**完全一致**，行号也对得上。

### 典型情况

- Stable backport 补丁（同大版本内的修复，context 几乎不变）
- 刚发布不久的 CVE 修复（目标分支与 mainline 差异很小）

### 实际示例

```
CVE-2025-40196 的 5.10 stable backport 补丁:
  → 该补丁由社区维护者为 5.10 版本专门生成
  → context 行与目标仓库 5.10-hulk 100% 一致
  → L0 Strict: git apply --check ✔ 直接通过
  → 无需任何适配，可直接 git apply
```

**频率：~20% 的 CVE 补丁可以 L0 通过（主要是 stable backport 场景）**

---

# L1 Context-C1 — 放宽上下文匹配

### 解决场景

补丁 context 中有 **1-2 行** 发生了微小变化（注释修改、空行变动）。

### 原理

`git apply -C1` 将 context 匹配要求从默认 3 行放宽到 1 行。

### 实际示例

```
mainline 补丁 context:                  5.10-hulk 实际文件:
  line 160: /* Initialize quota */        line 160: /* Init quota system */  ← 注释微改
  line 161: dquot_init();                 line 161: dquot_init();
  line 162: + 安全修复代码                 line 162: (待插入)

L0 Strict: ✘ 第 160 行注释不一致, context 匹配失败
L1 -C1:    ✔ 只需 1 行 context 匹配 (line 161 一致), 通过!
```

**频率：~15% 的补丁在 L1 通过（注释修改、格式调整等低影响变更）**

---

# L2 3-Way Merge — 三方合并

### 解决场景

目标文件和 mainline 在**相同区域都有修改**，但修改**不冲突**。

### 原理

利用 git 的三方合并算法：找到补丁的 base blob（原始版本），
与目标文件和补丁同时 merge。

### 实际示例

```
Base (补丁原始版本):        Mainline (安全修复):       5.10-hulk (企业修改):
  err = -EINVAL;              err = -EINVAL;             err = -EINVAL;
  goto out;                   + if (skb) kfree(skb);     goto out_unlock;  ← 企业改动
                              goto out;

3-Way Merge:
  err = -EINVAL;
  + if (skb) kfree(skb);      ← 来自 mainline 补丁
  goto out_unlock;             ← 保留企业改动
  → 两者修改不冲突 → merge 成功!
```

**频率：~10% 的补丁在 L2 通过（企业有小修改但与安全修复不冲突）**

---

# L3 Regenerated — 核心创新 ⭐

### 解决场景

企业仓库在 context 行之间**插入了大量自定义代码**，导致 L0/L1/L2 全部失败。
这是企业内核最常见的困难场景。

### 原理

**不依赖 context 序列连续性，而是在目标文件中重新定位每个 hunk 的变更点。**

```
mainline 补丁 (连续 context):          5.10-hulk 文件 (context 被打断):
 ┌─────────────────────┐              ┌──────────────────────────────┐
 │ ctx: spin_lock(lock)│              │ line 200: spin_lock(lock)    │
 │ ctx: old = data->val│              │ line 201: trace_point(...)   │ ← 企业插入
 │ -   data->val = 0;  │              │ line 202: perf_counter(...)  │ ← 企业插入
 │ +   data->val = new;│              │ line 203: old = data->val    │
 │ ctx: spin_unlock()  │              │ line 204: data->val = 0;     │ ← 要修改的行
 └─────────────────────┘              │ line 205: spin_unlock()      │
                                      └──────────────────────────────┘
L0/L1/L2: ✘ context 序列 spin_lock→old=data 不连续 (中间插了 2 行)

L3 Regenerated:
  Step 1: 锚点行定位 → 搜索 "old = data->val" → 命中 line 203
  Step 2: 确认 removed 行 "data->val = 0" 存在于 line 204 ✔
  Step 3: 从目标文件 line 200-205 读取实际 context → 重建 hunk
  Step 4: 新 hunk 的 context 包含企业插入的行 → git apply ✔
```

**核心能力：在 context 被任意打断的情况下重新定位并重建补丁**
**频率：~40% 的困难补丁通过 L3 解决 — 这是最核心的创新点**

---

# L4 Conflict-Adapted — 冲突适配

### 解决场景

补丁中的 **removed 行在目标文件中已经不存在或已被修改**——真正的代码冲突。

### 原理

定位 hunk 变更点后，用目标文件的实际行替换 removed 行，保留 added 行。

```
mainline 补丁:                           5.10-hulk 实际代码:
 -  err = -EINVAL;     ← 要删除           err = -EPERM;    ← 企业改为 EPERM
 +  err = validate(x); ← 安全修复

L3: 定位成功，但 removed 行不匹配 (-EINVAL ≠ -EPERM)

L4 Conflict-Adapted:
 -  err = -EPERM;      ← 用目标实际行替换
 +  err = validate(x); ← 保留安全修复
 → 标记 severity = L2 (语义冲突，需人工审查:
    原修复意图是改 -EINVAL，企业版本已改为 -EPERM，
    需确认 validate(x) 是否仍适用)
```

### 冲突严重性三级分类

| 级别 | 含义 | 建议 |
|------|------|------|
| L1 | 仅 context 不匹配，核心改动一致 | 可直接应用 |
| L2 | removed 行不同，核心改动存在 | 需审查语义 |
| L3 | 整段代码重构，结构不同 | 需手动适配 |

---

# L5 Verified-Direct — 内存直改，绕过 git apply ⭐

### 解决场景

补丁核心改动与目标文件**语义一致**，但存在宏/常量重命名、缩进风格差异、
空白字符不同等"适配性"差异，导致 `git apply` 拒绝应用。

### 原理

**完全绕过 `git apply`**，在 Python 内存中直接读取目标文件、定位变更点、修改内容。

```
┌─────────────────────────────────────────────────────────────────────┐
│  L0 ✘ → L1 ✘ → L2 ✘ → 触发 L5 Verified-Direct                     │
│                                                                     │
│  Step 1: 读取目标文件内容到内存                                       │
│  Step 2: 逐 hunk 定位变更点 (复用 S1-S7 七策略搜索)                  │
│  Step 3: 符号映射 — 自动检测宏/常量重命名                             │
│          HFSPLUS_UNICODE_MAX_LEN → HFSPLUS_MAX_STRLEN               │
│  Step 4: 缩进适配 — 匹配目标文件的 tab/space 风格                    │
│  Step 5: 在内存中直接修改目标文件内容                                 │
│  Step 6: difflib.unified_diff 生成标准 diff                          │
│  Step 7: 验证 similarity > 0.30 确保语义正确                         │
│                                                                     │
│  输出: 可直接 git apply 的适配补丁                                    │
│  标记: method = "verified-direct"                                    │
└─────────────────────────────────────────────────────────────────────┘
```

### 典型案例: CVE-2025-40082

```
社区补丁使用 HFSPLUS_UNICODE_MAX_LEN    企业仓库使用 HFSPLUS_MAX_STRLEN
hfsplus_uni2asc() 参数列表不同           缩进从 tab 改为 space
git apply L0-L2 全部失败                 传统做法: 束手无策

L5 Verified-Direct:
  → 符号映射检测到 HFSPLUS_UNICODE_MAX_LEN → HFSPLUS_MAX_STRLEN
  → 自动替换 added 行中的宏名
  → 适配缩进风格
  → 在内存中完成修改 → 生成标准 diff → 验证通过 ✔
```

**设计哲学：当 git apply 因非本质差异拒绝补丁时，用 Python 直接绕过**

---

# L6 AI-Generated — 智能兜底 🤖

### 解决场景

目标文件经历了**大规模重构**，函数签名变更、代码结构调整，
所有确定性策略均失败。

### 原理

将 mainline 补丁、目标文件内容、冲突分析结果组装为结构化 Prompt，
调用 LLM 生成最小化修改补丁。

```
┌────────────────────────────────────────────────────────────────────┐
│  L0 ✘ → L1 ✘ → L2 ✘ → L5 ✘ → L3 ✘ → L4 ✘ → 触发 L6             │
│                                                                    │
│  输入 LLM:                                                         │
│    ├─ mainline patch (原始修复意图)                                 │
│    ├─ target file content (企业实际代码)                            │
│    └─ conflict analysis (L4 的冲突诊断)                            │
│                                                                    │
│  LLM 输出:                                                         │
│    ├─ 最小化适配补丁                                                │
│    └─ 修改理由说明                                                  │
│                                                                    │
│  安全校验:                                                         │
│    ├─ diff 格式合法性检查                                           │
│    ├─ git apply --check 验证                                       │
│    └─ 标记 method = "ai-generated" → 强制人工审查                  │
└────────────────────────────────────────────────────────────────────┘
```

**设计哲学：确定性算法优先 (L0-L5)，AI 仅作为最后防线**

---

# 多级策略效果统计

```
典型企业内核仓库中各级策略的解决占比:

┌────────────────┬──────────────────────────────────────────────┐
│   Level        │  ██████████████████████████████████████████  │
├────────────────┼──────────────────────────────────────────────┤
│ L0 Strict      │  ████████████                    ~20%        │
│ L1 Context-C1  │  █████████                       ~15%        │
│ L2 3-Way       │  ██████                          ~10%        │
│ L5 Verified ⭐ │  ██████████████████████          ~15%  ←NEW  │
│ L3 Regen       │  ████████████████████            ~25%  ←关键 │
│ L3.5 Zero-Ctx  │  █████                           ~5%         │
│ L4 Adapted     │  █████                           ~5%         │
│ L6 AI 🤖      │  ███                             ~3%         │
├────────────────┼──────────────────────────────────────────────┤
│ 自动化率       │  █████████████████████████████████ ~95%      │
│ 仍需纯人工     │  ███                              ~5%       │
└────────────────┴──────────────────────────────────────────────┘

L5 Verified-Direct + L3 Regenerated 联合解决了 ~40% 的困难补丁
```

---

<!-- _class: lead -->
<!-- _backgroundColor: #0f3460 -->
<!-- _color: white -->

# 04-B 七策略序列搜索引擎
## L3 Regenerated 的定位核心

---

# 七策略搜索 — 为什么需要 7 种策略？

### 企业仓库中一个 hunk 可能面临的 7 类定位困难

```
                              目标文件
                         ┌─────────────────────┐
   S1 精确序列 ─────────►│ 行号偏移但代码不变   │  最简单
   S2 锚点行 ──────────►│ 中间插入额外代码     │  常见
   S3 函数作用域 ───────►│ context 全改但函数在  │  函数级定位
   S4 行号窗口 ────────►│ 有跨hunk偏移先验     │  利用已有信息
   S5 全局模糊 ────────►│ 代码有小修改(变量名) │  容忍差异
   S6 分段context ─────►│ 一半context变一半没变│  分段独立搜
   S7 逐行投票 ────────►│ 多行散落匹配        │  最困难
                         └─────────────────────┘
```

**按优先级逐策略尝试，首个成功即返回 — 兼顾精度与覆盖率**

---

# S1 精确序列匹配 — 最快最准

### 解决场景
目标文件中代码**完全相同**，只是行号发生了偏移（前面多了/少了几行）。

### 示例

```
mainline hunk removed 序列:             5.10-hulk 文件:
  "err = -EINVAL;"                        line 295: err = -EINVAL;  ← 完全一致!
  "goto out;"                             line 296: goto out;       ← 完全一致!

补丁标注行号 162, 实际在 295 → 偏移了 +133 行
S1 在全文搜索这两行的连续序列 → 命中 line 295 → 定位成功
```

**适用率高，约 30% 的 hunk 通过 S1 直接定位**

---

# S2 锚点行定位 — 免疫 context 断裂

### 解决场景
企业在 mainline context 的行之间**插入了自定义代码**，
连续序列被打断，但**边界行仍然存在**。

### 示例

```
mainline context:                   5.10-hulk 文件:
  ctx_before[-1] = "mutex_lock()"     line 400: mutex_lock()       ← 锚点!
  (连续→)                              line 401: enterprise_hook()  ← 企业插入
                                       line 402: trace_event()      ← 企业插入
  ctx_after[0] = "list_add()"         line 403: list_add()

S1: ✘ "mutex_lock" 和 "list_add" 之间多了 2 行, 序列不连续
S2: ✔ 搜索锚点行 "mutex_lock()" → 命中 line 400
     → 变更点 = 401 → 从这里开始重建 context
```

**最核心策略：约 35% 的困难 hunk 通过 S2 解决**

---

# S3 函数作用域搜索 — 大范围偏移

### 解决场景
context 行被大幅修改，但 hunk header 中的**函数名**仍然有效。

```
@@ -162,6 +162,9 @@ static int qdisc_destroy(struct Qdisc *q)
                        └───── 函数名锚点 ─────┘
```

### 示例

```
mainline context 在企业仓库中完全不存在（函数体大规模重写）

S1: ✘ 序列不存在
S2: ✘ 锚点行也被改了
S3: 在目标文件中搜索 "qdisc_destroy" 函数体
    → 找到 line 500-580 是该函数范围
    → 在 line 500-580 内搜索 removed 行
    → 命中! 定位成功
```

**利用 hunk header 的函数签名缩小搜索范围到精确函数体**

---

# S4 行号窗口 + 跨 Hunk 偏移传播

### 解决场景
同一文件的前序 hunk 已成功定位，**累积偏移量**可作为后续 hunk 的搜索先验。

### 示例

```
文件 net/ipv6/ip6_output.c 有 3 个 hunk:

Hunk 1: 补丁标注 line 162 → S1 定位到 line 295
        偏移 = 295 - 162 = +133

Hunk 2: 补丁标注 line 300
        S1/S2/S3 失败, 进入 S4:
        搜索窗口 = (300 + 133) ± 300 = line 133 ~ 733
        在窗口内逐行搜索 removed 行 → 命中 line 438
        新偏移 = 438 - 300 = +138

Hunk 3: 补丁标注 line 450
        S4 搜索窗口 = (450 + 138) ± 300 = line 288 ~ 888
        → 命中 line 591
```

**越往后的 hunk 定位越精准 — 偏移传播形成正反馈**

---

# S5 全局模糊匹配 — 容忍代码差异

### 解决场景
目标文件中代码存在**微小修改**（变量重命名、类型变更、宏替换）。

```
mainline: "int ret = skb_copy(skb, GFP_KERNEL);"
企业版:   "int ret = skb_copy(skb, GFP_ATOMIC);"     ← GFP 标志不同
                                    └───────┘
S1: ✘ 不完全一致
S5: SequenceMatcher 相似度 = 0.92 > 阈值 0.7 → 匹配成功
```

---

# S6 分段 Context — Before/After 独立搜索

### 解决场景
hunk 的 before-context 被修改但 **after-context 仍然完整**，或反过来。

```
mainline hunk:                      5.10-hulk:
  before[0] = "old_api_call()"        → 企业已改为 new_api_call()  ✘
  before[1] = "check_flag()"          → 企业已删除               ✘
  - removed line
  + added line
  after[0] = "return 0;"              → line 550: return 0;      ✔
  after[1] = "}"                       → line 551: }              ✔

S1: ✘ removed 序列找不到 (前面 context 全变了)
S2: ✘ before-context 最后一行被改了
S6: 单独用 after-context ["return 0;", "}"] 搜索
    → 命中 line 550 → 变更点 = 550 - 1 = 549
```

**将一个搜索问题拆成两个独立子问题，成功率翻倍**

---

# S7 逐行投票 — 统计定位

### 解决场景
代码零散分布，没有连续匹配，但**多数行各自能在目标文件中找到**。

### 算法原理

```
removed + context 共 6 行, 每行独立搜索目标文件:

line 1 "spin_lock()"    → 在目标文件 line 200, 450, 680 出现
line 2 "old = data"     → 在目标文件 line 201, 451 出现
line 3 "if (old > 0)"   → 在目标文件 line 203, 700 出现
line 4 "data->val = 0"  → 在目标文件 line 204 出现
line 5 "spin_unlock()"  → 在目标文件 line 205, 680 出现
line 6 "return old"     → 在目标文件 line 206 出现

每行推算起始位置:
  line 1 → 起始 = 200-0=200, 450-0=450, 680-0=680
  line 2 → 起始 = 201-1=200, 451-1=450
  line 3 → 起始 = 203-2=201, 700-2=698
  line 4 → 起始 = 204-3=201
  line 5 → 起始 = 205-4=201, 680-4=676
  line 6 → 起始 = 206-5=201

投票统计: {200: 2票, 201: 4票, 450: 2票, ...}
众数 = 201 (4票) → 变更点 = line 201
```

**即使只有 60% 的行匹配，也能通过统计方式准确定位**

---

# 七策略协同效果

```
                      困难 hunk 的定位成功率

  ┌────────────────────────────────────────────────────────┐
  │ 仅 S1              ████████████          ~30%          │
  │ + S2 锚点          █████████████████████  ~65%  +35%  │
  │ + S3 函数名        ██████████████████████ ~72%  +7%   │
  │ + S4 偏移传播      ████████████████████████ ~80% +8%  │
  │ + S5 模糊匹配      █████████████████████████ ~85% +5% │
  │ + S6 分段          ██████████████████████████ ~90% +5%│
  │ + S7 投票          ███████████████████████████ ~95%+5%│
  └────────────────────────────────────────────────────────┘

  单策略 30% → 七策略组合 95% → 配合代码语义匹配 ~98%

  每增加一种策略，覆盖一类新的边界场景
```

---

<!-- _class: lead -->
<!-- _backgroundColor: #16213e -->
<!-- _color: white -->

# 04-C 全流程串联示例
## 从 CVE 编号到可用补丁

---

# 完整示例：CVE-2024-XXXXX 分析全过程

### 场景设定

```
CVE:           CVE-2024-XXXXX (内核网络子系统空指针解引用)
Mainline Fix:  commit abc1234 (v6.8)
目标分支:      5.10-hulk (企业内核)
困难点:        企业在相关文件中插入了 tracing + 性能监控代码
```

---

# Step 1 → Crawler Agent 情报采集

```
输入: CVE-2024-XXXXX

  MITRE API 查询:
    ├─ 漏洞描述: "NULL pointer dereference in net/ipv6/..."
    ├─ 严重性: HIGH (CVSS 7.5)
    ├─ mainline fix: abc1234 (v6.8)
    ├─ introduced: def5678 (v5.6)
    └─ 版本映射: {5.4: aaa, 5.10: bbb, 5.15: ccc, 6.1: ddd, 6.6: eee}

  git.kernel.org 获取补丁:
    ├─ subject: "ipv6: fix NULL ptr deref in ip6_output"
    ├─ 修改文件: net/ipv6/ip6_output.c
    ├─ diff: -3 +8 (修复空指针检查)
    └─ 同时获取 5.10 stable backport 补丁 (commit bbb)

耗时: ~3s (含网络请求)
```

---

# Step 2 → Analysis Agent 搜索定位

```
引入 commit 搜索 (def5678):
  L1: commit_exists("def5678") → ✘ 不存在 (cherry-pick 换了 ID)
  L2: FTS5 搜索 "ipv6 add route lookup" → 命中 commit e1f2g3h
      subject 相似度 = 0.91 → ✔ 引入 commit 找到!
      → 结论: 目标仓库包含漏洞引入代码 ⚠️

修复 commit 搜索 (abc1234):
  L1: commit_exists("abc1234") → ✘
  L2: FTS5 搜索 "ipv6 fix NULL ptr deref" → ✘ subject 不匹配
  L3: PathMapper 翻译路径 → 搜索修改 net/ipv6/ 的 commits
      → diff_containment() = 0 → ✘ 修复补丁未合入
      → 结论: 漏洞未修复，需要 backport! 🔴

耗时: ~5s
```

---

# Step 3 → Dependency Agent 依赖分析

```
分析 abc1234 的修复补丁:
  修改: net/ipv6/ip6_output.c, line 162-175, 函数 ip6_output()

  时间窗口: def5678 (v5.6 引入) → HEAD
  候选 commit: 筛选同文件修改 → 23 个候选

  Hunk 级重叠分析:
    [强依赖] commit i7j8k9 "ipv6: add skb validation helper"
             修改 line 160-168 (直接重叠)
             函数 ip6_output() 交集
             → 该 commit 引入了 validate_skb()，修复补丁调用了它

    [中依赖] commit l0m1n2 "ipv6: refactor route lookup"
             修改 line 180-195 (相邻 50 行内)
             → 重构了附近的路由查找逻辑

  → 建议: 先合入 i7j8k9, 审查 l0m1n2

耗时: ~3s
```

---

# Step 4 → DryRun Agent 多级自适应

```
优先使用 5.10 stable backport 补丁 (更匹配目标分支)

L0 Strict:  git apply --check
            → ✘ 失败 (企业在 ip6_output.c 插入了 tracing 代码)

L1 -C1:     git apply --check -C1
            → ✘ 失败 (context 偏移超过 1 行容忍度)

L2 3-Way:   git apply --check --3way
            → ✘ 失败 (base blob 不在本地仓库中)

L3 Regenerated:  ⭐ 逐 hunk 处理
  ┌─ Hunk 1/2: net/ipv6/ip6_output.c @@ -162,6 +162,9 @@
  │  S1 精确序列: ✘ (中间插了 trace_point 调用)
  │  S2 锚点行:   ✔ 搜索 "skb_dst(skb)" → 命中 line 198
  │  定位: change_pos = 199, 偏移 = +37
  │  从目标文件 line 195-205 重建 context → 新 hunk 生成
  │
  └─ Hunk 2/2: @@ -250,3 +253,5 @@
     S1 精确序列: ✘
     S2 锚点行:   ✘ (锚点行也被改了)
     S4 行号窗口:  利用 Hunk 1 偏移 +37 → 搜索 (250+37)±300
     → ✔ 命中 line 290
     从目标文件 line 287-296 重建 context → 新 hunk 生成

  组装完整补丁 → git apply --check ✔ 验证通过!

结果:
  method = "regenerated"
  adapted_patch = (可直接 git apply 的补丁文件)

耗时: ~2s
```

---

# 全流程汇总

```
┌─────────────────────────────────────────────────────────────────────┐
│  CVE-2024-XXXXX 分析报告                          总耗时: 13s      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ① Crawler    ✔ 情报采集完成                                       │
│     mainline fix = abc1234, introduced = def5678                   │
│     5.10 stable backport = bbb                                     │
│                                                                     │
│  ② Analysis   ⚠ 漏洞已引入(e1f2g3h via L2 91%), 修复未合入        │
│                                                                     │
│  ③ Dependency  1 强依赖 + 1 中依赖                                  │
│     [强] i7j8k9 "add skb validation helper" → 必须先合入           │
│                                                                     │
│  ④ DryRun     ✔ L3 Regenerated 成功                                │
│     尝试路径: ✘ strict → ✘ C1 → ✘ 3way → ✔ regenerated            │
│     已生成适配补丁 (output/CVE-2024-XXXXX.patch)                   │
│                                                                     │
│  行动建议:                                                          │
│   1. 先 cherry-pick 前置 commit i7j8k9                             │
│   2. 然后 git apply output/CVE-2024-XXXXX.patch                    │
│   3. 编译测试 + 功能验证                                            │
│                                                                     │
│  传统人工: ~3 小时  →  本工具: 13 秒  →  效率提升 830x             │
└─────────────────────────────────────────────────────────────────────┘
```

---

<!-- _class: lead -->
<!-- _backgroundColor: #0f3460 -->
<!-- _color: white -->

# 05 关键算法
## 支撑全链路的核心算法集

---

# Diff 包含度算法 — 识别 Squash Commit

### 问题：企业仓库常将多个社区补丁合并提交，传统 diff 对比完全失效

```
场景: 企业将 3 个社区补丁 squash 成 1 个大 commit

  社区修复补丁 (3 行):          企业 squash commit (200 行):
    +line_a                       +unrelated_1
    +line_b                       +line_a      ✓ 匹配
    -line_c                       +line_b      ✓ 匹配
                                  -line_c      ✓ 匹配
                                  +line_d (来自另一个补丁)
                                  +line_e (来自另一个补丁)
                                  ... (180+ 行其他补丁)

  传统双向相似度: ~30% → 判定为"不匹配" ✘ 漏检!
  Multiset 包含度: 100% (3/3 全部包含) → 判定为"已合入" ✔
```

### 算法核心

```
将 source 和 target 的 diff 行分别构建 Counter (多重集合):
  source_added = Counter(["line_a", "line_b"])
  target_added = Counter(["unrelated_1", "line_a", "line_b", "line_d", ...])

对每条 source 行, 在 target Counter 中消耗 (避免重复计数):
  "line_a" → target 中存在 → 消耗 1 → matched += 1
  "line_b" → target 中存在 → 消耗 1 → matched += 1

包含度 = matched / total = 2/2 = 100%
```

**在 Analysis Agent L3 阶段使用，专解 squash 场景**

---

# 代码语义匹配 — 七策略全失败后的终极兜底

### 问题：当代码被大面积改写，连模糊匹配都无法命中

```
场景: 企业对函数体做了重构，变量重命名 + 类型变更 + 宏替换

mainline 代码:                    企业代码:
  int ret = -EINVAL;                long result = -EPERM;
  if (!skb) goto out;              if (unlikely(!skb)) goto err_out;
  ret = skb_copy(skb, GFP_KERNEL); result = skb_clone(skb, GFP_ATOMIC);

S1-S7 全部失败 (代码差异太大) → 触发代码语义匹配
```

### 三维度加权融合模型

```
score = 0.5 × S_structure  (SequenceMatcher 编辑距离)
      + 0.3 × S_identifier (变量名/函数名 Jaccard 系数)
      + 0.2 × S_keyword    (C 语言关键字序列)

计算示例:
  S_structure  = 0.72 (结构相似: 赋值→判空→调用 模式一致)
  S_identifier = 0.60 (skb 相同, ret↔result 不同, copy↔clone 不同)
  S_keyword    = 0.85 (int, if, goto 等关键字高度重合)

  score = 0.5×0.72 + 0.3×0.60 + 0.2×0.85 = 0.71 > 阈值 0.6 → ✔ 匹配
```

**用代码的"语义含义"而非"字面形式"定位 — 在 DryRun L3 阶段使用**

---

# 算法与 Agent 的协作关系

```
┌─────────────────────────────────────────────────────────────────────┐
│                        算法如何服务于 Agent                          │
│                                                                     │
│  Crawler Agent                                                      │
│    └─ 三级数据源回退算法                                             │
│                                                                     │
│  Analysis Agent                                                     │
│    ├─ L1: Commit ID 精确匹配                                        │
│    ├─ L2: Subject 语义匹配  ←── SequenceMatcher + FTS5              │
│    └─ L3: Diff 代码匹配    ←── PathMapper + Diff 包含度 (Multiset)  │
│                                                                     │
│  Dependency Agent                                                   │
│    └─ Hunk 行范围重叠      ←── extract_hunks + compute_overlap      │
│                                                                     │
│  DryRun Agent                                                       │
│    ├─ L0-L2: Git 内置策略                                            │
│    ├─ L5: Verified-Direct  ←── 内存直改 + 符号映射 + 缩进适配 ⭐     │
│    ├─ L3: Regenerated       ←── 七策略搜索 + 代码语义匹配            │
│    │     ├─ S1: 精确序列                                             │
│    │     ├─ S2: 锚点行定位                                           │
│    │     ├─ S3: 函数作用域                                           │
│    │     ├─ S4: 行号窗口 + 跨hunk偏移传播                            │
│    │     ├─ S5: 全局模糊匹配                                         │
│    │     ├─ S6: 分段 context                                         │
│    │     ├─ S7: 逐行投票                                             │
│    │     └─ 兜底: CodeMatcher 语义匹配                               │
│    ├─ L3.5: Zero-Context   ←── 零上下文 diff + --unidiff-zero        │
│    ├─ L4: Conflict-Adapted ←── 冲突分析 + 严重性分级                 │
│    └─ L6: AI-Generated 🤖 ←── AIPatchGenerator                     │
│                                                                     │
│  每个算法都在特定 Agent 的特定阶段被调用                              │
│  形成 情报→搜索→依赖→定位→适配→验证 的完整算法链路                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

<!-- _class: lead -->
<!-- _backgroundColor: #16213e -->
<!-- _color: white -->

# 06 AI 集成能力 🤖

---

# AI 在系统中的定位

### 设计原则：AI 作为增强手段，核心算法完全确定性

| 组件 | 技术 | 默认状态 | 定位 |
|------|------|---------|------|
| L0-L5 DryRun | 确定性算法 | ✅ 启用 | **核心 — 可重现、可解释** |
| 代码语义匹配 | SequenceMatcher | ✅ 启用 | 纯算法，非 AI |
| Diff 包含度 | Multiset 计数 | ✅ 启用 | 纯算法，非 AI |
| **L6 AI 补丁生成** | **LLM (GPT-4o等)** | ❌ 可选 | 规则全部失败后的最后手段 |
| **LLM 根因分析** | **LLM** | ❌ 可选 | 验证失败时的辅助诊断 |

### AI 补丁生成流程

```
所有规则策略失败 → 构建结构化 Prompt
  → LLM 分析代码差异 → 生成适配补丁
  → 格式校验 → git apply --check 验证
  → 标记 ai-generated → 强制人工审查
```

**安全约束：AI 输出必须通过验证，且强制人工审查后方可合入**

---

<!-- _class: lead -->
<!-- _backgroundColor: #0f3460 -->
<!-- _color: white -->

# 07 v2.0 深度分析能力
## 从"能不能合"到"该怎么合、风险多大"

---

# v2.0 解决什么问题？

### v1 的局限

v1 回答了：**补丁能不能应用到目标版本？需要哪些前置补丁？**

但分析人员还需要知道：

| 问题 | v1 | v2 |
|------|----|----|
| 这个漏洞到底是什么类型？根因是什么？ | ❌ | ✅ VulnAnalysis |
| 社区怎么讨论这个 CVE 的？有争议吗？ | ❌ | ✅ Community |
| 修复补丁的代码逻辑是什么？安全吗？ | ❌ | ✅ PatchReview |
| 合入的风险有多大？收益够不够高？ | ❌ | ✅ RiskBenefit |
| 为什么说不需要前置补丁？理由是什么？ | 只给结论 | ✅ 完整分析+理由 |
| 最终建议是合入还是跳过？ | ❌ | ✅ MergeAdvisor |

> **v2 = v1 基础分析 + 深度洞察，用 `--deep` 标志一键触发**

---

# v2.0 架构：5 个深度分析 Agent

```
CVE ID + 目标版本
  │
  ├─ v1 Pipeline (不变): Crawler → Analysis → Dependency → DryRun
  │                             │
  │                             ▼  AnalysisResult (v1)
  │
  └─ v2 深度分析 (--deep 触发):
       │
       ├─ CommunityAgent ───── 社区讨论收集 (lore.kernel.org / bugzilla)
       │
       ├─ VulnAnalysisAgent ── 漏洞类型分类 + 根因 + 触发路径 + 检测方法
       │
       ├─ PatchReviewAgent ─── 代码走读 + 调用拓扑 + 数据结构 + 安全检视
       │
       ├─ RiskBenefitAnalyzer ─ 四维风险收益评估 + 后置补丁检测
       │
       └─ MergeAdvisorAgent ── 关联补丁完整分析 + 合入建议 + 检视清单
                │
                ▼
           AnalysisResultV2 → TUI 面板 + JSON 报告
```

**设计原则：LLM 增强 + 确定性兜底 — 无 LLM 时也输出完整结构化分析**

---

# 漏洞深度分析 — VulnAnalysisAgent

### 功效：让分析人员理解"修的是什么漏洞，危害多大"

```
输入: CVE 描述 + 修复补丁 diff

输出:
  ┌─────────────────────────────────────────────────────────────────┐
  │  漏洞类型: Use-After-Free (释放后使用)                           │
  │  严重度:   高危                                                  │
  │  影响子系统: net/netfilter                                       │
  │                                                                 │
  │  技术根因:                                                       │
  │    CVE 描述指出 netfilter 子系统存在释放后使用问题。             │
  │    补丁修改了 nft_set_elem_init、nft_set_destroy 等函数，        │
  │    涉及 net/netfilter/ 下的文件。                                │
  │    典型的 UAF 模式: 对象在一个路径中被释放后，另一个并发路径      │
  │    仍持有该对象的引用并尝试访问。                                 │
  │                                                                 │
  │  触发路径:                                                       │
  │    攻击者通过特定的 netlink 消息序列触发 nft_set 元素的           │
  │    并发创建和销毁，利用释放后的内存布局实现代码执行。             │
  │                                                                 │
  │  检测方法:                                                       │
  │    使用 KASAN 内存检测器运行相关用例，观察是否有                  │
  │    use-after-free 报告。                                         │
  └─────────────────────────────────────────────────────────────────┘
```

### 确定性分类规则

漏洞类型通过 CVE 描述和 diff 中的关键词匹配自动分类：
`kfree/put → UAF`、`array_index/len > → OOB`、`spin_lock/mutex → race`、`NULL/deref → NULL_deref`

---

# 补丁逻辑检视 — PatchReviewAgent

### 功效：自动进行代码安全审查，输出检视清单

```
输入: 修复补丁 diff + 目标仓库代码

分析维度:
  ┌─────────────────────────────────────────────────────────────────┐
  │ 1. 修改函数映射                                                  │
  │    补丁修改了 nft_set_elem_init、nft_set_destroy 等 3 个函数     │
  │                                                                 │
  │ 2. 调用拓扑                                                      │
  │    nft_set_elem_init → nft_set_elem_alloc → kmalloc              │
  │    (追踪修改函数的上下游调用链)                                   │
  │                                                                 │
  │ 3. 数据结构检测                                                  │
  │    spinlock(nft_set_lock), rcu_read_lock                         │
  │    → 涉及并发同步原语，需重点关注                                │
  │                                                                 │
  │ 4. 安全模式检视                                                  │
  │    [critical] kfree 后未置 NULL — UAF 风险                       │
  │    [warning]  缺少 NULL 指针检查                                  │
  │    [info]     使用了有界拷贝 (strncpy)                           │
  └─────────────────────────────────────────────────────────────────┘
```

### C 函数名智能提取

工具从 diff hunk header 中提取函数名，**自动跳过 C 类型修饰符**：

```
@@ -100,3 +100,5 @@ static ssize_t nft_set_elem_init(struct nft_set *set,

旧方法: 提取到 "static" (❌ 这是关键字不是函数名)
新方法: 跳过 static/ssize_t 等噪声词 → 提取到 "nft_set_elem_init" ✅
```

---

# 关联补丁完整分析 — 核心增强

### 功效：无论有无关联补丁，都给出完整分析和理由

这是分析人员最关心的问题。v2 不再只给结论，而是解释**为什么**。

### 场景一：无前置补丁

```
╭──────────────────────────── 关联补丁分析 ────────────────────────────╮
│ 前置补丁分析                                                         │
│   未检测到前置依赖补丁                                               │
│   • 补丁可在目标版本干净应用，代码上下文与上游一致                   │
│   • 仅修改 2 个文件，改动范围集中                                    │
│   • 未引入或依赖新的数据结构定义                                     │
│   结论: 该补丁可独立合入，不依赖其他前置改动                         │
│                                                                      │
│ 后置补丁分析                                                         │
│   未检测到后续关联补丁                                               │
│   结论: 该修复在上游社区是自包含的，无需额外的追加修正               │
╰──────────────────────────────────────────────────────────────────────╯
```

---

# 关联补丁完整分析 — 有依赖时

### 场景二：存在前置依赖

```
╭──────────────────────────── 关联补丁分析 ────────────────────────────╮
│ 前置补丁分析                                                         │
│   检测到 2 个关联补丁 (强依赖 1 / 中依赖 1 / 弱关联 0)              │
│   强依赖 — 缺失将导致编译失败或语义错误:                             │
│     abc123def456 nft: fix memory allocation in nft_set_elem          │
│       共享函数: nft_set_elem_init, nft_set_cleanup; 3 个重叠代码块   │
│   中依赖 — 建议评估是否需要先合入:                                   │
│     xyz789 nft: add error check for nft_table_lookup                 │
│       重叠函数: nft_table_lookup                                     │
│   注: 补丁本身可干净应用，前置补丁提供的是编译/运行时依赖            │
│       (数据结构、API)，非文本冲突                                    │
│                                                                      │
│ 后置补丁分析                                                         │
│   检测到 2 个后置关联补丁                                            │
│   后续修复 (Fixes: 标签引用本补丁，共 1 个):                         │
│     pp_111222 nft: fix regression in elem init                       │
│     → 建议一并合入这些后续修复                                       │
│   同函数修改 (共 1 个):                                              │
│     pp_333444 nft: optimize set lookup                               │
│     → 建议评估是否影响修复补丁正确性                                 │
╰──────────────────────────────────────────────────────────────────────╯
```

---

# 关联补丁分析的判定逻辑

### 为什么工具有信心说"不需要前置补丁"？

```
判定依据:

  ① DryRun 可干净应用
     → 补丁的删除行在目标版本中存在，添加行可正确插入
     → 最强的 "无需前置" 信号

  ② 时间窗口内无同文件修改
     → 从漏洞引入到 HEAD，无人动过修复补丁涉及的文件
     → 目标版本该文件代码与上游一致

  ③ 修改范围集中 (≤2 文件)
     → 越是局部修改，被其他补丁交叉依赖的概率越低

  ④ 无新数据结构依赖
     → 不依赖前置补丁引入的 struct 字段、锁变量、API
```

### 边界情况说明

```
DryRun 能过 但仍有前置依赖的场景:
  前置补丁在头文件中新增 struct 字段 → 修复补丁引用该字段
  git apply 只检查 diff 上下文 → 通过
  编译时找不到新字段 → 失败!

工具会标注:
  "尽管补丁可干净应用，前置补丁提供的是编译/运行时依赖，非文本冲突"
```

---

# 风险收益评估 — RiskBenefitAnalyzer

### 功效：用人话描述合入的风险和价值，替代晦涩的数字

```
╭──────────────────────────── 风险收益评估 ────────────────────────────╮
│                                                                      │
│  合入复杂度: 极低。补丁可通过 DryRun strict 模式干净应用，无文件      │
│  冲突。无前置依赖，补丁可独立合入。                                  │
│                                                                      │
│  回归风险: 低。补丁修改 2 个文件共 3 个代码块 (hunk)，涉及文件:     │
│  net/netfilter/nf_tables_api.c、net/netfilter/nft_set_hash.c。      │
│  修改集中在函数: nft_set_elem_init, nft_set_destroy。               │
│  修改范围小且集中，未涉及高风险并发原语，回归风险可控。             │
│                                                                      │
│  安全收益: 高。修复 Use-After-Free 类型漏洞，严重度为高危。         │
│  该类漏洞允许攻击者通过控制已释放对象的内存布局实现任意代码执行      │
│  或权限提升。建议优先修复。                                          │
│                                                                      │
│  综合评估: 建议合入。该补丁修复一个高危严重度的 UAF 漏洞。          │
│  安全收益高，合入复杂度极低，回归风险低。                            │
│  补丁可干净应用 (strict 模式直接应用)。                              │
╰──────────────────────────────────────────────────────────────────────╯
```

**注意：不展示裸数字 (如 0.14/1.00)，只用等级标签 + 详细文字说明**

---

# 合入建议 — MergeAdvisorAgent

### 功效：给出最终决策建议和操作清单

```
╭──────────────────────────── 合入建议 ────────────────────────────────╮
│  建议操作: 直接合入 (置信度 90%)                                     │
│                                                                      │
│  建议直接合入该补丁。该补丁修复 CVE-2025-XXXX (高危严重度，         │
│  Use-After-Free 类型漏洞)，影响 netfilter 子系统。                   │
│  DryRun 检测显示补丁可通过 strict 模式直接应用。                     │
│  无前置依赖补丁，该修复可独立合入目标版本。                          │
│  无后续关联补丁，修复在上游是自包含的。                              │
│                                                                      │
│  检视清单:                                                           │
│    □ [低风险] 补丁可自动应用，确认编译通过                           │
│    □ [安全] 确认 UAF 类型漏洞已被完整修复                            │
│    □ [验证] 使用 KASAN 运行相关用例验证                              │
│    □ [通用] 运行相关子系统测试用例                                   │
│    □ [通用] 检查补丁在目标内核版本的编译兼容性                       │
╰──────────────────────────────────────────────────────────────────────╯
```

### 四种决策

| 操作 | 触发条件 | 含义 |
|------|---------|------|
| **直接合入** | DryRun 通过 + 无前置 | 最简单，git apply 即可 |
| **合入 (先处理依赖)** | 有前置补丁 | 需按顺序先合入前置 |
| **需人工审查** | DryRun 失败 | 补丁存在冲突，需手动适配 |
| **无需处理** | 目标版本已修复 | 跳过 |

---

# v2.0 使用方式

### 一条命令触发深度分析

```bash
# 单 CVE 深度分析
python cli.py analyze --cve CVE-2025-XXXX --target 5.10-hulk --deep

# validate 也支持深度分析
python cli.py validate --cve CVE-2025-XXXX --target 5.10-hulk \
  --known-fix abc123 --deep

# 批量验证 + 深度分析
python cli.py batch-validate --file data.json --target 5.10-hulk --deep
```

### 输出格式

- **TUI 面板**：Rich 终端彩色面板，分模块展示每项分析
- **JSON 报告**：完整的 `AnalysisResultV2` 结构化输出，含所有深度分析字段
- **无需客户端页面**：直接在终端或 JSON 中查看

### LLM 增强 (可选)

所有 Agent 都支持 LLM 增强模式（配置 `llm.enabled = true`）：
- 有 LLM → 更深入的根因分析、代码走读、综合建议
- 无 LLM → 完整的确定性分析输出（规则引擎 + 关键词匹配 + 代码模式检测）

---

<!-- _class: lead -->
<!-- _backgroundColor: #0f3460 -->
<!-- _color: white -->

# 08 分析过程可视化
## Analysis Narrative + 深度分析 TUI 面板

---

# 为什么需要分析过程可视化？

### 痛点

开发者反馈："工具给出了结论，但我**看不懂过程**"

```
传统工具输出:                           开发者的困惑:
┌───────────────────────────┐          ┌──────────────────────────────┐
│ applies_cleanly: true     │          │ 为什么可以直接应用？           │
│ method: "regenerated"     │   →?→    │ 需不需要先合入前置补丁？       │
│ prereqs: [abc123]         │          │ 前置补丁为什么需要？           │
│ similarity: 100%          │          │ 这个结论可信吗？               │
└───────────────────────────┘          └──────────────────────────────┘
```

### 解决方案：Analysis Narrative

在输出 JSON 中增加 `analysis_narrative` 字段，用**结构化自然语言**描述工具的完整分析过程。

---

# Analysis Narrative — 五大模块

```json
{
  "analysis_narrative": {
    "workflow": "工具执行了以下步骤: 1. 获取CVE信息... 2. 抓取补丁...",
    "prerequisite_analysis": {
      "conclusion": "无需引入前置补丁",
      "reason": "修复补丁涉及的代码区域无其他强依赖变更",
      "details": "..."
    },
    "patch_applicability": {
      "conclusion": "补丁可直接应用",
      "method": "verified-direct (L5 内存直改)",
      "reason": "L0-L2 因宏名差异失败，L5 自动检测到 HFSPLUS_UNICODE_MAX_LEN
                → HFSPLUS_MAX_STRLEN 的符号映射，在内存中完成适配",
      "direct_applicable": true
    },
    "patch_quality_assessment": {
      "conclusion": "生成补丁与真实修复本质相同",
      "verdict": "本质相同",
      "core_similarity": "100%"
    },
    "developer_action": "可直接合入。补丁已通过自动适配，
                         核心改动与社区修复一致，建议编译验证后合入。"
  }
}
```

---

# Narrative 覆盖三大功能

| 功能 | 输出内容 |
|------|---------|
| **analyze** | workflow + prerequisite_analysis + patch_applicability + developer_action |
| **validate** | 上述全部 + patch_quality_assessment (生成补丁 vs 真实修复对比) |
| **batch-validate** | 每个 CVE 都包含完整 narrative，汇总到批量报告 |

### 实际效果

```
开发者视角:
  ┌─────────────────────────────────────────────────────────────────┐
  │ 1. 工具获取了 CVE-2025-40082 的信息和社区修复补丁               │
  │ 2. 在目标仓库中未找到修复补丁 → 需要回合                        │
  │ 3. 前置依赖分析: 无强依赖，可独立合入                            │
  │ 4. DryRun: L0/L1/L2 因宏名差异失败                             │
  │    → L5 Verified-Direct 检测到符号映射，自动适配成功             │
  │ 5. 结论: 可直接合入，补丁已验证                                  │
  │                                                                 │
  │ → 开发者一目了然: 为什么可以直接合入，工具做了什么              │
  └─────────────────────────────────────────────────────────────────┘
```

**让工具的决策过程透明化，建立开发者信任**

---

<!-- _class: lead -->
<!-- _backgroundColor: #e94560 -->
<!-- _color: white -->

# 09 性能指标与验证

---

# 性能数据

| 指标 | 数据 | 说明 |
|------|------|------|
| 支持仓库规模 | **千万级 commit** | SQLite + FTS5 + WAL + mmap |
| 单 CVE 分析 | **15-30 秒** | 含网络请求 |
| 缓存增量更新 | **< 5 秒** | 自动检测 rebase 并降级全量 |
| 单 hunk 定位 | **< 100ms** | 锚点行 + 偏移传播 |
| 路径映射 | **8+ 内置规则** | 支持自定义扩展 |
| DryRun 策略 | **7+ 级** | Strict → C1 → 3way → Verified-Direct → Regen → Zero-Ctx → Adapted |

### 闭环验证框架

```
已修复 CVE → git worktree 回退到修复前
  → 运行完整 Pipeline → 与真实合入记录对比
  → 输出 Precision / Recall / F1 量化指标
  → [可选] LLM 根因分析失败用例
```

**可量化、可重复、可追溯**

---

# 已验证测试用例

| CVE | 状态 | 验证点 |
|-----|------|--------|
| CVE-2024-26633 | 已修复 | L1 引入检测 ✔ / L2 修复定位 ✔ |
| CVE-2025-40198 | N/A | Mainline 识别 7 版本映射全部正确 ✔ |
| CVE-2024-50154 | 已修复 | L1 引入 + L2 修复 + DryRun 冲突检测 ✔ |
| CVE-2024-26633 | Validate | Worktree 回退验证全通过 ✔ |
| CVE-2025-40196 | 未修复 | 引入 L2 ✔ / Stable backport 自动选择 ✔ / DryRun 3way ✔ |

### 验证方法论

- **fix_correctly_absent**: 工具正确识别"修复未合入"
- **intro_detected**: 工具正确识别"漏洞已引入"
- **dryrun_accurate**: DryRun 冲突预测与实际一致
- **prereq P/R/F1**: 前置依赖推荐精度

---

<!-- _class: lead -->
<!-- _backgroundColor: #0f3460 -->
<!-- _color: white -->

# 10 Demo 演示

---

# 实际使用效果 — 单条命令

```bash
# 一条命令，完整分析一个 CVE
python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk
```

### 输出包含

- ✅ CVE 元数据（严重程度、描述、影响版本）
- ✅ 漏洞引入 commit 在本地仓库的定位
- ✅ 修复补丁在本地仓库的合入状态
- ✅ 前置依赖分析（强/中/弱三级分级）
- ✅ DryRun 冲突预检（多级自适应 + 行级冲突诊断）
- ✅ 适配补丁自动生成（可直接 git apply）
- ✅ **Analysis Narrative** — 结构化分析过程描述，让开发者看懂每一步
- ✅ 结构化行动建议

### 其他命令

```bash
python cli.py check-intro --cve CVE-xxx --target 5.10-hulk     # 引入检测
python cli.py check-fix --cve CVE-xxx --target 5.10-hulk       # 修复检测
python cli.py validate --cve CVE-xxx --known-fix <commit>       # 准确度验证
python cli.py batch-validate --file data.json --target 5.10-hulk # 批量验证
python cli.py benchmark --file benchmarks.yaml                  # 基准测试
```

---

<!-- _class: lead -->
<!-- _backgroundColor: #16213e -->
<!-- _color: white -->

# 11 原理深度剖析
## 面向技术专家的细节说明

---

# 前置补丁：什么时候需要，什么时候不需要？

### 核心判定逻辑

```
修复补丁 P 修改了文件 F 的 line 100-120

                 时间线: 漏洞引入 ─────────────────────────── HEAD
                                    │                         │
                    其他补丁 A: 修改 line 105-115  → 直接重叠 → 必须先合
                    其他补丁 B: 修改 line 150-170  → 无重叠   → 不需要
                    其他补丁 C: 修改 line 125-135  → 相邻50行 → 建议审查
```

### 三种场景的决策规则

| 场景 | 判定条件 | 工具输出 | 开发者动作 |
|------|---------|---------|-----------|
| **无需前置** | 修复补丁涉及区域无其他 commit 修改 | `prerequisite_analysis.conclusion: "无需引入前置补丁"` | 直接 `git apply` |
| **强依赖** | 其他 commit 与修复补丁行范围**直接重叠** + 函数名交集非空 | 列出具体 commit + `grade: strong` | **必须先 cherry-pick** |
| **弱/中依赖** | 仅同文件或相邻区域修改 | 列出供参考 + `grade: medium/weak` | 可选择性审查 |

### 关键细节：为什么不能只看 `git apply` 是否成功？

```
git apply 成功 ≠ 补丁语义正确

场景: 补丁 P 的 context 行是 "old = data->val"
      前置补丁 A 将 data->val 改为 data->new_val
      如果 A 未合入，目标文件仍是 data->val → git apply 能成功!
      但补丁 P 的修复逻辑可能依赖 A 引入的 new_val → 语义错误

工具的做法:
  DryRun 负责 "能不能应用" (文本层面)
  Dependency Agent 负责 "应不应该应用" (语义层面)
  两者结合才是完整判断
```

---

# 符号映射检测原理

### 问题：宏/常量在不同版本被重命名

```
社区 mainline:  HFSPLUS_UNICODE_MAX_LEN       (定义在 hfsplus_raw.h)
企业 5.10-hulk: HFSPLUS_MAX_STRLEN            (早期版本的命名)

补丁中写: if (len > HFSPLUS_UNICODE_MAX_LEN)
企业中是: if (len > HFSPLUS_MAX_STRLEN)
```

### 检测算法 (`_extract_symbol_mapping`)

```
Step 1: 从补丁的 removed 行提取所有标识符 (大写+下划线 token)
        例: ["HFSPLUS_UNICODE_MAX_LEN"]

Step 2: 在目标文件中搜索 removed 行的模糊匹配
        例: "if (len > HFSPLUS_MAX_STRLEN)" 与补丁行相似度 0.85

Step 3: 比对差异 token → 建立映射
        HFSPLUS_UNICODE_MAX_LEN → HFSPLUS_MAX_STRLEN

Step 4: _apply_symbol_mapping 对所有 added 行执行替换
```

### 边界与限制

| 能处理 | 不能处理 |
|--------|---------|
| 宏名 1:1 重命名 | 宏被拆分为多个 |
| 常量名变更 | 函数签名参数增减 |
| 简单类型别名 | 结构体字段重排 |

---

# L5 Verified-Direct vs git apply：为什么要绕过？

### `git apply` 的致命局限

```
git apply 的匹配策略:
  1. 精确匹配 context 行 (逐行字符对比)
  2. 支持 -C<n> 减少 context 要求
  3. 支持 --3way 三方合并
  4. 不支持:
     ✘ 宏重命名后的语义等价匹配
     ✘ tab↔space 差异的智能处理 (--ignore-whitespace 仅忽略 context)
     ✘ 行号大幅偏移 + context 全变的定位
```

### L5 的优势

```
L5 Verified-Direct:
  1. 用七策略搜索引擎定位 hunk 变更点 → 不依赖 context 连续性
  2. 模糊匹配 removed 行 (similarity ≥ 0.30) → 容忍微小差异
  3. 符号映射 → 自动处理宏重命名
  4. 缩进适配 → tab/space 自动转换
  5. 直接在内存中修改文件 → 用 difflib 生成标准 diff

安全校验:
  - 每个 hunk 的 removed 行必须与目标文件匹配 (sim ≥ 0.30)
  - 生成的 diff 通过 git apply --check 二次验证
  - 标记 method = "verified-direct" → 开发者知晓是工具适配
```

---

# Diff 包含度 vs 双向相似度：何时用哪个？

### 本质区别

```
双向相似度:  source 和 target 有多少行是共同的？
             适用于: 1:1 cherry-pick (commit 对 commit)

单向包含度:  source 的行是否全部被 target 包含？
             适用于: 1:N squash (一个补丁被合并到大 commit 中)
```

### 场景选择规则

| 搜索类型 | 使用算法 | 原因 |
|---------|---------|------|
| **修复搜索** | 双向相似度 | 1:1 关系，希望精确匹配特定 commit |
| **引入搜索** | 包含度 | 引入代码可能被 squash 进企业合并 commit |

### 为什么不全用包含度？

```
包含度的假阳性问题:
  社区补丁 "+return 0;" (仅 1 行)
  企业大 commit 中有 100 处 "+return 0;"
  包含度 = 100% → 误判为已合入!

双向相似度避免此问题:
  社区补丁 3 行 vs 企业 commit 200 行
  双向相似度 = ~3% → 正确判定为不匹配
```

---

# 闭环验证原理：如何证明工具是对的？

### 核心思路：用已知答案反向验证

```
前提: 有一批已修复的 CVE，我们知道真实合入了哪些补丁

验证流程:
  1. git worktree 创建修复前快照 (known_fix~1)
  2. 在快照上运行完整 Pipeline
  3. 对比工具输出 vs 真实记录

关键校验项:
  fix_correctly_absent  → 工具是否正确说 "未修复" (应该 100%)
  intro_detected        → 工具是否发现漏洞已引入
  dryrun_applies        → 工具生成的补丁是否能应用
  patch_similarity      → 生成补丁与真实补丁的核心相似度
```

### worktree 的陷阱与修复

```
陷阱: worktree 共享主仓库的 .git 对象库
      → git log 能看到 worktree 之后的 commit
      → Pipeline 的 subject_match 会找到 known_fix → 误判为 "已修复"
      → 导致提前退出，DryRun 不执行

修复:
  1. force_dryrun=True → Pipeline 不提前退出
  2. git merge-base --is-ancestor → 直接检查 known_fix 是否是 HEAD 的祖先
     (在 worktree 中 HEAD = known_fix~1，所以 known_fix 不是其祖先 → 正确)
```

---

<!-- _class: lead -->
<!-- _backgroundColor: #e94560 -->
<!-- _color: white -->

# 12 质疑与挑战回应
## 预设审查者可能提出的问题

---

# Q1: 锚点行定位会不会有误命中？

### 质疑

> `spin_lock(ptl)` 在文件中出现 20 次，锚点行搜索怎么区分？

### 回应

```
工具不是只搜锚点行 — 有完整的交叉验证机制:

1. 锚点行候选: 搜索所有出现位置 → 20 个候选
2. 上下文验证: 检查 ctx_after 是否与文件实际内容吻合
   例: 锚点后应是 "old = data->val" → 只有 line 203 的下一行匹配
3. removed 行验证: 确认 removed 行存在于候选位置附近
4. 多候选评估: 所有候选打分 → 选最高分

实测数据: 七策略组合定位准确率 ~95%
          配合代码语义匹配 ~98%
```

---

# Q2: L5 绕过 git apply 安全吗？

### 质疑

> 不通过 git 正式机制应用补丁，会不会产生错误的 diff？

### 回应

| 安全措施 | 说明 |
|---------|------|
| removed 行验证 | 每个 hunk 的 `-` 行必须在目标文件中找到 (相似度 ≥ 0.30) |
| 符号映射有界 | 只做 1:1 token 替换，不做复杂重写 |
| `difflib.unified_diff` | Python 标准库生成标准 diff，格式保证正确 |
| `git apply --check` 二次验证 | 生成的 diff 必须通过 git 验证 |
| method 标记 | 输出标记 `verified-direct`，开发者明确知道是工具适配 |

**核心原则：L5 只处理"非本质性差异"（宏名、空白、缩进），核心修复逻辑不做任何改写。**

---

# Q3: 前置依赖推荐的误报率高吗？

### 质疑

> 工具推荐了前置补丁，但实际并不需要，增加了工作量。

### 回应

```
误报来源分析:
  1. 同文件修改但不相关 (弱依赖) → 工具已标记为 weak，建议忽略
  2. 相邻行修改但功能独立 (中依赖) → 标记为 medium，开发者审查
  3. 行范围重叠但修改内容互不影响 → 极少数 strong 误报

降低误报的措施:
  - 三级分级: strong / medium / weak → 开发者按需关注
  - 函数名交集: 不仅看行号重叠，还看是否涉及相同函数
  - 时间窗口: 只分析漏洞引入后的 commit → 排除远古历史

实际数据: strong 依赖准确率 ~85%+，weak 可安全忽略
```

### 工具的态度

**宁可多报 (false positive) 也不漏报 (false negative)。** 漏报前置依赖可能导致编译失败或运行时错误，代价远高于多审查几个 commit。

---

# Q4: 为什么不直接全用 AI 生成补丁？

### 质疑

> LLM 这么强，直接让 AI 看代码生成补丁不就行了？

### 回应

| 维度 | 确定性算法 (L0-L5) | AI 生成 (L6) |
|------|-------------------|-------------|
| **可重现** | 100% 确定性，相同输入 → 相同输出 | 不确定，温度参数影响 |
| **可解释** | 每一步有明确的搜索/匹配日志 | "黑箱"，难以追溯出错原因 |
| **速度** | 毫秒级 | 秒级 (API 调用) |
| **成本** | 零 | Token 费用 |
| **离线** | 可完全离线运行 | 需要网络 |
| **审计** | 满足安全审计要求 | 内核安全补丁需要高可信度 |

**设计原则：确定性算法覆盖 ~95% 场景；AI 仅处理剩余 ~5% 的极端重构。**

---

# Q5: 核心相似度 100% 但补丁不完全相同？

### 质疑

> 工具说 "核心相似度 100%"，但生成补丁和真实补丁文本不同。

### 回应

```
"核心相似度" 的定义:

  核心改动 = 补丁中的 +/- 行 (排除 context 行)
  相似度   = 核心改动行的 SequenceMatcher 匹配度

为什么 100% 但文本不同:
  1. context 行不同 — 工具从目标文件重建 context，包含企业自定义代码
     真实补丁的 context 由人工调整，可能包含不同的上下文行
  2. 行号不同 — 工具计算的行号与人工的可能有 ±几行偏差
  3. diff 头部不同 — a/b 路径、index 行等元数据差异

本质判断: 核心改动行 (安全修复逻辑) 完全一致 → 补丁语义正确
         context/行号差异不影响安全修复效果
```

---

# Q6: 千万级 commit 仓库性能能支撑吗？

### 质疑

> 企业内核仓库有 1000 万+ commit，搜索会不会很慢？

### 回应

```
性能架构:

  SQLite + FTS5 全文索引:
    - 构建: 流式写入，50K 批提交 → 千万 commit ~3 分钟 (一次性)
    - 增量: 只拉取新 commit → 日常 < 5 秒
    - 搜索: FTS5 关键词匹配 → < 500ms

  WAL + mmap:
    - Write-Ahead Logging → 读写不阻塞
    - mmap → 热数据常驻内存

  三级短路:
    L1 (commit ID) → < 1ms → 直接返回
    L2 (subject)   → < 500ms → FTS5 索引
    L3 (diff)      → 2-5s → 仅在 L1+L2 未命中时执行

  单 CVE 端到端: 15-30 秒 (含网络请求)
```

---

# Q7: 工具生成的补丁能不能直接合入生产？

### 质疑

> 工具生成的补丁能保证 100% 正确吗？可以免审查直接合入吗？

### 回应

**不能。** 工具的定位是**辅助**而非**替代**人工审查。

```
工具输出的置信度层级:

  L0 Strict 通过:     高置信 → 社区原始补丁，context 完全一致
  L1-L2 通过:         高置信 → git 自身机制保证
  L5 Verified-Direct:  中高置信 → 核心改动不变，context 适配
  L3 Regenerated:     中等置信 → 重建了 context，需确认定位准确
  L4 Conflict-Adapted: 低置信 → 有代码冲突，需人工审查语义

对于所有 L3+ 方法:
  ├─ 补丁标记了 method → 开发者明确知道适配方式
  ├─ analysis_narrative 解释了为什么这样适配
  ├─ 强烈建议: 编译测试 + 功能验证 + 代码审查
  └─ 内核安全补丁: 必须经过完整 CI/CD + 审查流程
```

---

# Q8: 如何判断工具推荐的前置补丁就是真实需要的？

### 质疑

> Dependency Agent 基于行范围重叠推荐前置补丁，会不会漏掉语义依赖？

### 回应

```
工具能检测:
  ✔ 同文件同区域的直接代码变更 (行范围重叠)
  ✔ 同函数体内的关联修改 (函数名交集)
  ✔ 修复补丁引用的新增函数/宏 (如果前置补丁引入了它们)

工具不能检测:
  ✘ 跨文件的数据结构依赖 (A 文件改了 struct，B 文件使用)
  ✘ 间接 API 依赖 (补丁调用 foo()，foo() 的语义被另一个补丁改变)
  ✘ 编译配置依赖 (CONFIG_XXX 开关改变导致的条件编译差异)

缓解措施:
  1. DryRun 会检测编译层面的问题 (git apply 失败/冲突)
  2. analysis_narrative 明确说明工具检测范围和局限
  3. 开发者审查时关注 struct 字段、API 语义、CONFIG 变更
```

---

# Q9: 对比 coccinelle / spatch 等语义补丁工具的优势？

### 质疑

> 业界已有 coccinelle 做语义补丁转换，你们的工具有什么不同？

### 回应

| 维度 | coccinelle/spatch | CVE Backporting Engine |
|------|-------------------|----------------------|
| 定位 | 通用 C 代码转换规则 | CVE 补丁回溯专用 |
| 输入 | 需手写 SmPL 规则 | 全自动，只需 CVE ID |
| 覆盖 | 代码转换 | **全链路**: 情报→搜索→依赖→应用→验证 |
| 搜索 | 无 | 三级搜索引擎 + FTS5 |
| 依赖 | 无 | Hunk 级前置依赖分析 |
| 验证 | 无 | 闭环验证框架 + P/R/F1 |
| 部署 | 需 OCaml 环境 | 纯 Python，pip install |

**核心区别：coccinelle 解决 "如何转换代码"，本工具解决 "CVE 补丁回溯的完整生命周期"。**

---

# Q10: 为什么"无前置补丁"还要啰嗦地解释？

### 质疑

> 没有前置补丁直接说"无"就行了，为什么还要输出一大段分析？

### 回应

```
在真实的 CVE 修复工作流中，分析人员需要对结论负责:

  场景 1: 工具说"无前置补丁"，合入后编译失败
    → 分析人员: "工具说不需要啊"
    → 质疑: "凭什么说不需要？工具分析了什么？"

  场景 2: 工具说"无前置补丁"，并给出理由:
    • DryRun strict 通过 (代码上下文完全一致)
    • 仅修改 1 个文件 (范围集中)
    • 未引入新数据结构 (无编译依赖)
    → 分析人员可以基于理由做判断
    → 如果出问题，可以追溯是哪个判据失效

工具的态度: 结论是给出来参考的，理由是用来追溯的。
           无论正面还是反面的结论，都需要有证据链支撑。
```

---

# Q11: 为什么用行范围重叠而不是 AST 分析做依赖？

### 质疑

> 行范围重叠太粗糙了，用 AST (Abstract Syntax Tree) 分析不是更准？

### 回应

```
权衡考量:

  AST 方案:
    ✔ 语义精确 — 知道哪个变量/函数被谁修改
    ✘ 需要完整编译环境 (内核构建依赖复杂)
    ✘ 跨版本 AST 解析失败率高 (宏展开、条件编译)
    ✘ 性能: 解析单个内核 C 文件需要秒级
    ✘ 分析 50 个候选 commit 需要分钟级

  行范围重叠方案:
    ✔ 零依赖 — 不需要编译环境
    ✔ 毫秒级 — 纯文本行号比对
    ✔ 跨版本稳定 — 不受宏/CONFIG 影响
    ✔ 覆盖率高 — 能检测大部分物理冲突
    ✘ 精度稍低 — 不识别纯语义依赖

工具选择行范围重叠的原因:
  1. 企业场景要求零编译依赖、快速分析
  2. 三级分级 (strong/medium/weak) 补偿精度不足
  3. 配合 DryRun 的实际应用测试兜底
  4. 未来可通过 function_analyzer 增强函数级精度
```

---

# Q12: 深度分析没有 LLM 的结果可信吗？

### 质疑

> 没配置 LLM，深度分析的结果是不是就没用了？

### 回应

```
所有 Agent 的确定性模式都经过精心设计:

  VulnAnalysis (无 LLM):
    ✔ 关键词规则匹配漏洞类型 (kfree→UAF, array_index→OOB)
    ✔ 从 CVE 描述和 diff 提取受影响函数/子系统
    ✔ 基于漏洞类型生成模板化但准确的根因/触发分析
    → 覆盖 80%+ 的常见内核漏洞类型

  PatchReview (无 LLM):
    ✔ 正则解析 diff 提取修改函数列表
    ✔ 代码模式检测 (kfree 后未置 NULL、缺少 NULL 检查等)
    ✔ 数据结构识别 (spinlock/mutex/rcu/refcount)
    → 完整的安全检视清单

  RiskBenefit (无 LLM):
    ✔ 纯规则计算: 文件数/hunk 数/前置补丁数 → 复杂度
    ✔ CVSS 严重度映射 → 安全收益
    ✔ 全文字描述 (等级标签 + 理由)，不输出裸数字
    → 结果明确可解释

有 LLM 时: 在确定性基础上增强 (更深入的根因、代码走读)
无 LLM 时: 输出完整、结构化、可操作的分析结果
```

---

<!-- _class: lead -->
<!-- _backgroundColor: #1a1a2e -->
<!-- _color: white -->

# 13 总结与展望

---

# 项目价值总结

### 五大核心价值

1. **效率跃升** — 单 CVE 分析从 2-4 小时降至 15-30 秒
2. **精度可量化** — 闭环验证框架 + P/R/F1 指标
3. **自动适配** — 多级 DryRun 自动生成适配补丁
4. **过程透明** — Analysis Narrative + 关联补丁完整分析，每个结论都有理由
5. **深度洞察** — v2.0 五大分析 Agent，从"能不能合"到"该怎么合"

### 技术创新

| 创新点 | 解决的问题 |
|--------|-----------|
| Diff 包含度算法 | Squash commit 匹配失效 |
| 锚点行定位 + 七策略搜索 | Context 序列断裂 |
| L5 Verified-Direct 内存直改 | 宏重命名/空白差异导致 git apply 失败 |
| 跨 hunk 偏移传播 | 多 hunk 文件精度递增 |
| Analysis Narrative | 分析过程不透明，开发者看不懂 |
| **v2.0 关联补丁完整分析** | 只给结论不给理由，无法追溯 |
| **v2.0 风险收益文字描述** | 裸数字无法理解 |
| **v2.0 合入建议引擎** | 缺少最终决策建议 |
| AI 辅助补丁生成 | 规则引擎的能力边界 |
| 闭环验证框架 | 工具可信度证明 |

---

# 后续规划

### 短期 (1-2 月)

- 🎯 扩大基准测试集，覆盖 50+ CVE 场景
- 🎯 集成 CI/CD 自动巡检流程
- 🎯 优化 Level 3 定位成功率

### 中期 (3-6 月)

- 🚀 对接内部安全运营平台，实现 CVE 自动分发
- 🚀 支持更多内核版本分支的并行分析
- 🚀 增强 AI 辅助能力（语义冲突检测、智能补丁建议）

### 长期

- 🌟 向 C/C++ 通用补丁回溯引擎演进
- 🌟 构建企业级 CVE 知识图谱
- 🌟 开源社区贡献

---

<!-- _class: lead -->
<!-- _backgroundColor: #0f3460 -->
<!-- _color: white -->

# 谢谢！

### CVE Backporting Engine
**确定性算法为核心 · 深度分析为洞察 · AI 增强为手段 · 闭环验证为保障**

<br>

Q & A
