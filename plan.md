# 优化计划

基于对全部代码的逐行审阅，提出以下优化方向和具体建议。

---

## 一、Dependency Agent — 前置补丁数量过多（核心问题）  ✅ 已完成

### 改造前的问题

```
1. 取 fix_patch 修改的文件 (top 3)
2. git log -- <files> 搜索最近 20 条 commit (无时间约束)
3. 排除已知的 fix/introduced commit
4. 剩余全部视为 "前置依赖" (无分级)
5. 对每个候选做函数级重叠检测 (is_strong 二元标记)
```

**问题根因：** "修改了同文件" ≠ "前置依赖"。频繁修改的文件会产生大量不相关的候选。

### 已实施的优化

#### ✅ 1.1 时间窗口限制

`search_by_files` 增加 `after_ts` 参数，从引入 commit 的 timestamp 开始搜索，排除远古无关历史。同时增加 `no_merges=True` 过滤 merge commit。

#### ✅ 1.2 Hunk 级别重叠

新增 `extract_hunks_from_diff()` 和 `compute_hunk_overlap()` 函数（`core/matcher.py`），从 diff 中提取每个 hunk 的 (文件, 起始行, 结束行)，计算直接重叠和相邻重叠（±50行 margin）。

#### ✅ 1.3 依赖分级

三级评分系统：

| 级别 | 判定条件 | 含义 |
|------|----------|------|
| **强依赖** | hunk 直接重叠 + 函数重叠，或 score ≥ 0.5 | 必须先合入 |
| **中依赖** | hunk 相邻 (±50行) 或 score ≥ 0.2 | 大概率需要先合入 |
| **弱依赖** | 仅同文件 | 参考 |

评分公式：`score = min(direct_overlaps × 0.3, 0.6) + min(adjacent × 0.1, 0.2) + min(funcs × 0.15, 0.3)`

#### ✅ 1.5 过滤策略

- merge commit → `--no-merges` 排除
- 修改文件数 > 20 的大重构 commit → 排除
- score < 0.05 且无函数/hunk 重叠 → 排除
- Fixes: 标签引用的 commit → 排除（避免与 fix 本身混淆）

### 验证效果

CVE-2024-26633 (ip6_tunnel.c) 改造前后对比：

| 指标 | 改造前 | 改造后 |
|------|--------|--------|
| 前置依赖数量 | ~10 个 | **3 个** |
| 分级信息 | 无 | 3 个中依赖 |
| hunk 分析 | 无 | 显示直接/相邻重叠数 |

#### 未实施: 1.4 Fixes 标签链递归追踪

当前只提取第一层 Fixes: 标签。递归追踪（链式查找多层 Fixes:）留待 Phase 3。

---

## 二、Rich 终端展示信息不足  ✅ 已完成

### 已实施的优化

#### ✅ 2.1 前置依赖详情表

`_render_prereq_table()` — 完整的 Rich Table，展示每个依赖的：
- 序号、强度标记（强/中/弱，彩色）
- Commit ID、Subject
- 评分、Hunk 重叠（N直接 + M相邻）、重叠函数列表
- 最多展示 15 条

#### ✅ 2.2 DryRun 冲突详情

`_render_dryrun_detail()` — 独立面板展示：
- `git apply --stat` 修改统计
- 冲突文件列表（红色 ✘ 标记）
- git 错误输出（含具体冲突行号）

#### ✅ 2.3 版本映射展示

`_render_version_map()` — CVE 影响的版本-commit 映射表，区分 Mainline 和 Stable backport。

#### ✅ 2.4 搜索过程可视化

- `SearchResult` 增加 `steps: List[SearchStep]` 字段，记录 L1/L2/L3 每级的 status/detail/elapsed
- `AnalysisAgent.search()` 在短路模式下也记录每级步骤
- `_render_search_steps()` 在分析报告中展示引入搜索和修复搜索的完整 L1→L2→L3 过程

#### ✅ 2.5 建议面板优化

`render_recommendations()` — 关键字高亮：强依赖/未合入/冲突等关键行用红色/黄色标记。

---

## 三、Analysis Agent 搜索质量

### 现状分析

- L2 搜索使用 `git log --grep` + `--fixed-strings`，是精确字符串匹配。当 backport commit 的 subject 被重写（如加了 `[PATCH]`、`[hulk]` 前缀），精确匹配可能 miss
- L2 回退到关键词搜索（`search_by_keywords`）时用的是 FTS5 的 AND 连接，过于严格
- L3 对每个候选都要 `git show` 获取完整 diff，当候选数多时非常慢（50 个候选 = 50 次 git show）
- `_search_subject` 中 `normalize_subject` 只处理了几个固定前缀（[backport]、[stable] 等），不够灵活

### 优化方案

#### 3.1 L2 模糊搜索增强

- `normalize_subject` 应该用正则去除所有 `[xxx]` 形式的前缀标签
- 关键词搜索改为 OR 连接（至少命中 N 个关键词），而非 AND
- FTS5 查询支持 NEAR 操作符，对关键词邻近性给更高权重

#### 3.2 L3 延迟 diff 获取

- 先做 subject 预过滤（sim > 0.5 的优先获取 diff）
- 分批获取：先取 top 10，如果最高已超阈值则不再继续
- 对 `git show` 使用 `--stat` 先获取修改统计，跳过明显无关的

#### 3.3 缓存 diff

频繁的 `git show <commit>` 对同一个 commit 可能重复执行（dependency 和 analysis 都会调用）。增加 LRU 内存缓存避免重复获取。

---

## 四、Pipeline 流程优化

### 现状分析

- `_try_stable_backport` 在 version_commit_mapping 中硬编码匹配 `"5.10"` 前缀，不够通用
- 当 CVE 没有引入 commit 信息时，`is_vulnerable` 被默认设为 True，应该更谨慎

### 优化方案

#### 4.1 Stable backport 匹配通用化

从 `config.yaml` 的 branch 配置中提取版本号前缀，而非硬编码 `"5.10"`。

#### 4.2 引入 commit 缺失时的处理

当 CVE 没有引入 commit 信息时，标记为"待确认"而非"受影响"。

#### 4.3 on_stage 回调完善

增加更细粒度的进度回调：
- Crawler: "正在获取 MITRE API..." / "正在获取 diff..."
- Analysis L2: "搜索到 15 个候选，正在比对..."
- Dependency: "分析第 3/7 个候选 commit..."

---

## 五、代码质量与健壮性

### 5.1 SQLite 连接管理

当前每次查询都 `sqlite3.connect()` + `conn.close()`。建议使用持久连接或连接池。

### 5.2 错误处理

- `verify=False` 改为从 config 读取
- `DryRunAgent` 中 `import subprocess` 移到文件顶部
- `except Exception: pass` 改为至少 `logger.debug`

### 5.3 类型标注

- `check_commit_existence` 返回值改为 NamedTuple
- ~~`DependencyAgent.analyze` 返回裸 Dict~~ → 已部分改善（使用 PrerequisitePatch dataclass）

### 5.4 配置一致性

- 代码中硬编码的阈值（0.85、0.70）应从 config.yaml 读取
- `performance.search_timeout` 等配置项未被使用

---

## 六、优先级排序（更新后）

| 优先级 | 项目 | 状态 |
|--------|------|------|
| **P0** | 1.1 + 1.2 依赖分析加时间窗口和 hunk 级重叠 | ✅ 已完成 |
| **P0** | 2.1 前置依赖详情表 | ✅ 已完成 |
| **P1** | 1.3 依赖分级 (强/中/弱) | ✅ 已完成 |
| **P1** | 2.2 + 2.3 DryRun 详情 + 版本映射展示 | ✅ 已完成 |
| **P1** | 2.4 搜索过程可视化 | ✅ 已完成 |
| **P2** | 3.1 L2 模糊搜索增强 | 待开发 |
| **P2** | 3.2 + 3.3 L3 优化 + diff 缓存 | 待开发 |
| **P2** | 4.1 + 4.2 Pipeline 通用化 | 待开发 |
| **P3** | 5.x 代码质量 | 待开发 |

---

## 七、变更文件清单 (P0 + P1)

| 文件 | 变更类型 | 说明 |
|------|----------|------|
| `core/models.py` | 新增 | `PrerequisitePatch` dataclass（含 grade/score/overlap_hunks/overlap_funcs）、`SearchStep` dataclass、`SearchResult.steps` 字段 |
| `core/matcher.py` | 新增 | `extract_hunks_from_diff()`、`compute_hunk_overlap()` 函数 |
| `core/git_manager.py` | 修改 | `search_by_files` 增加 `after_ts`/`no_merges` 参数 |
| `agents/dependency.py` | 重写 | 时间窗口 + hunk 分析 + 三级分级 + merge/大重构过滤 |
| `agents/analysis.py` | 修改 | `search()` 方法增加 SearchStep 记录 |
| `core/ui.py` | 大量新增 | `_render_prereq_table`、`_render_dryrun_detail`、`_render_version_map`、`_render_search_steps`；`render_report` 重写集成所有子面板 |
| `pipeline.py` | 修改 | dependency 回调展示分级统计 |
| `cli.py` | 修改 | JSON 序列化适配 PrerequisitePatch dataclass |
| `core/__init__.py` | 修改 | 导出新模型 |

---

## 八、下一阶段建议路径

```
Phase 2 (增强搜索 + Pipeline):
  ├─ normalize_subject 正则化（去除所有 [xxx] 前缀）
  ├─ FTS5 关键词搜索改 OR 连接
  ├─ L3 延迟 diff 获取 + LRU 缓存
  ├─ Pipeline stable backport 版本匹配通用化
  └─ 引入 commit 缺失时版本范围判断

Phase 3 (打磨):
  ├─ Fixes: 标签链递归追踪
  ├─ SQLite 持久连接
  ├─ 配置项统一读取（消除硬编码阈值）
  └─ 异常处理和日志规范化
```
