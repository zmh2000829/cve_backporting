# 文档目录

本目录包含项目的所有详细文档。

## 📚 文档列表

### 中文文档

- **[功能验证总结.md](./功能验证总结.md)** - 项目功能验证总结（快速了解）
  - 需求对照表
  - 测试功能说明
  - 快速开始指南

### 英文文档

- **[TESTING_GUIDE.md](./TESTING_GUIDE.md)** - 完整测试指南
  - 所有测试命令详解
  - 使用示例
  - GitRepoManager配置

- **[CVE_MAINLINE_ANALYSIS.md](./CVE_MAINLINE_ANALYSIS.md)** - Mainline识别原理
  - CVE-2025-40198详细分析
  - 版本映射关系说明
  - 为什么mainline是8ecb790

- **[VERIFICATION_REPORT.md](./VERIFICATION_REPORT.md)** - 详细验证报告
  - 功能实现清单
  - 测试结果
  - 完整工作流示例

## 📖 阅读顺序建议

### 新用户
1. 先读 `../README.md`（项目根目录）了解项目概况
2. 再读 `功能验证总结.md` 快速了解功能
3. 然后读 `TESTING_GUIDE.md` 学习如何使用

### 深入了解
1. `CVE_MAINLINE_ANALYSIS.md` - 理解核心算法
2. `VERIFICATION_REPORT.md` - 了解实现细节

## 🔗 相关资源

- **测试代码**: `../tests/test_crawl_cve.py`
- **示例代码**: `../examples/`
- **项目结构**: `../PROJECT_STRUCTURE.md`

## 📝 文档维护

所有文档都应该：
- 保持最新
- 包含实际例子
- 中英文分别维护
- 定期更新日期
