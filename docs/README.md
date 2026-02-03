# 文档目录

本目录包含CVE Backporting项目的所有技术文档。

## 📚 快速导航

### 新手必读

1. **[配置使用说明](CONFIG_USAGE.md)** - 配置文件使用指南
2. **[测试和缓存指南](TESTING_CACHE_GUIDE.md)** - 测试流程和缓存管理
3. **[基于分支的搜索指南](BRANCH_SEARCH_GUIDE.md)** - ⚠️ 重要：分支搜索配置

### 核心功能

4. **[CVE Mainline分析](CVE_MAINLINE_ANALYSIS.md)** - Mainline commit识别原理
5. **[测试重构总结](TEST_REFACTOR_SUMMARY.md)** - 测试代码重构说明

## 📖 详细文档列表

### 配置相关

| 文档 | 说明 | 适用人群 |
|------|------|---------|
| [CONFIG_USAGE.md](CONFIG_USAGE.md) | 配置文件完整说明 | 所有用户 |
| [BRANCH_SEARCH_GUIDE.md](BRANCH_SEARCH_GUIDE.md) | 基于分支搜索的配置 | ⚠️ 必读 |

**重点**: `BRANCH_SEARCH_GUIDE.md` 包含了最新的分支配置要求，所有用户必须阅读！

### 测试相关

| 文档 | 说明 | 适用人群 |
|------|------|---------|
| [TESTING_CACHE_GUIDE.md](TESTING_CACHE_GUIDE.md) | 测试流程和缓存管理 | 开发和测试人员 |
| [TEST_REFACTOR_SUMMARY.md](TEST_REFACTOR_SUMMARY.md) | 测试重构说明 | 开发人员 |

### 技术原理

| 文档 | 说明 | 适用人群 |
|------|------|---------|
| [CVE_MAINLINE_ANALYSIS.md](CVE_MAINLINE_ANALYSIS.md) | Mainline识别原理 | 深度用户 |

## 🚀 快速开始

### 第一次使用

1. 阅读 [CONFIG_USAGE.md](CONFIG_USAGE.md) 了解配置
2. **必读** [BRANCH_SEARCH_GUIDE.md](BRANCH_SEARCH_GUIDE.md) 配置分支
3. 阅读 [TESTING_CACHE_GUIDE.md](TESTING_CACHE_GUIDE.md) 学习使用

### 配置步骤

```bash
# 1. 复制配置文件
cp config.example.yaml config.yaml

# 2. 编辑配置（重要：必须配置branch字段）
vim config.yaml

# 3. 验证配置
python verify_branch_config.py

# 4. 构建缓存
python tests/test_crawl_cve.py build-cache <repo_version> 10000

# 5. 运行测试
python tests/test_crawl_cve.py CVE-2024-26633
```

## ⚠️ 重要变更

### 最新更新（必读）

**基于分支的搜索和缓存** - 详见 [BRANCH_SEARCH_GUIDE.md](BRANCH_SEARCH_GUIDE.md)

- ❗ 现在所有搜索和缓存只在配置的分支上进行
- ❗ 必须在 `config.yaml` 中为每个仓库配置 `branch` 字段
- ❗ 必须删除旧的 `commit_cache.db` 并重新构建

**迁移步骤**:
```bash
# 1. 更新 config.yaml，添加 branch 字段
# 2. 删除旧缓存
rm commit_cache.db
# 3. 重新构建
python tests/test_crawl_cve.py build-cache <repo_version> 10000
```

## 📋 文档更新日志

### 2026-02 最新版

- ✅ 新增 `BRANCH_SEARCH_GUIDE.md` - 基于分支搜索的完整指南
- ✅ 更新 `CONFIG_USAGE.md` - 添加 branch 配置说明
- ✅ 更新 `TESTING_CACHE_GUIDE.md` - 添加分支缓存说明
- ✅ 新增 `TEST_REFACTOR_SUMMARY.md` - 测试重构总结
- ❌ 删除旧的验证文档（已过时）

### 清理的文档

以下文档已删除（内容过时或重复）：
- ~~TESTING_GUIDE.md~~ - 已被 TESTING_CACHE_GUIDE.md 取代
- ~~VERIFICATION_REPORT.md~~ - 内容过时
- ~~功能验证总结.md~~ - 与 VERIFICATION_REPORT.md 重复
- ~~BRANCH_BASED_SEARCH.md~~ - 已合并到 BRANCH_SEARCH_GUIDE.md
- ~~BRANCH_SEARCH_SUMMARY.md~~ - 已合并到 BRANCH_SEARCH_GUIDE.md
- ~~BRANCH_MIGRATION_QUICK_GUIDE.md~~ - 已合并到 BRANCH_SEARCH_GUIDE.md

## 💡 使用建议

### 按角色推荐

**第一次使用者**:
1. CONFIG_USAGE.md
2. BRANCH_SEARCH_GUIDE.md（必读）
3. TESTING_CACHE_GUIDE.md

**开发人员**:
1. BRANCH_SEARCH_GUIDE.md（必读）
2. TEST_REFACTOR_SUMMARY.md
3. CVE_MAINLINE_ANALYSIS.md

**系统管理员**:
1. CONFIG_USAGE.md
2. BRANCH_SEARCH_GUIDE.md（必读）
3. TESTING_CACHE_GUIDE.md

### 按任务推荐

**配置系统**:
→ CONFIG_USAGE.md → BRANCH_SEARCH_GUIDE.md

**运行测试**:
→ TESTING_CACHE_GUIDE.md

**理解原理**:
→ CVE_MAINLINE_ANALYSIS.md

**迁移升级**:
→ BRANCH_SEARCH_GUIDE.md（必读）

## 🔗 外部资源

- [项目主README](../README.md)
- [项目结构](../PROJECT_STRUCTURE.md)
- [变更日志](../CHANGELOG.md)

## 📮 反馈

如果发现文档问题或有改进建议，请提交issue或pull request。

---

**最后更新**: 2026-02  
**文档版本**: 2.0
