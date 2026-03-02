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
近期 (P2, 1-2 周):
  ├─ 2.1 normalize_subject 正则化 (半天)
  ├─ 2.4 diff LRU 缓存 (半天)
  ├─ 3.1 Stable backport 版本自动匹配 (半天)
  └─ 4.1 + 4.2 verify 可配置 + 阈值配置化 (半天)

中期 (P2-P3, 2-4 周):
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
