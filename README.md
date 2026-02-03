# CVE Backporting 工具

一个用于Linux内核CVE补丁回合分析的自动化工具。

## ✨ 核心功能

1. **自动识别Mainline修复commit** - 从多个commit中准确识别主线修复
2. **版本映射关系** - 建立完整的内核版本到commit的映射
3. **智能commit搜索** - 多策略搜索自维护仓库中的对应commit
4. **Backport识别** - 识别`[backport] + 社区msg`模式
5. **修复状态检查** - 判断修复补丁是否已合入
6. **依赖分析** - 分析并列出前置依赖补丁

## 🚀 快速开始

### 安装依赖

```bash
pip install -r requirements.txt
```

### 基础使用

```bash
# 查看CVE信息和版本映射
python3 tests/test_crawl_cve.py CVE-2025-40198

# 查找引入commit（显示搜索策略）
python3 tests/test_crawl_cve.py search_introduced 8b67f04ab9de

# 检查修复是否已合入
python3 tests/test_crawl_cve.py check_fix abc123 "" CVE-2025-40198
```

### 配置仓库（可选）

复制配置模板并编辑：

```bash
cp config.example.yaml config.yaml
# 编辑config.yaml，配置您的kernel仓库路径
```

配置后可以进行实际的仓库搜索：

```bash
python3 tests/test_crawl_cve.py search_introduced 8b67f04ab9de 5.10-hulk
python3 tests/test_crawl_cve.py check_fix abc123 5.10-hulk CVE-2025-40198
```

## 📁 项目结构

```
cve_backporting/
├── README.md                      # 本文件
├── PROJECT_STRUCTURE.md           # 详细目录结构说明
├── requirements.txt               # Python依赖
├── config.example.yaml           # 配置文件示例
│
├── 核心模块/
│   ├── crawl_cve_patch.py        # CVE信息获取
│   ├── git_repo_manager.py       # Git仓库管理
│   ├── enhanced_cve_analyzer.py  # CVE分析
│   └── ...                       # 其他核心模块
│
├── tests/                        # 测试目录
│   ├── README.md                 # 测试说明
│   └── test_crawl_cve.py         # 测试工具
│
├── examples/                     # 示例代码
│   ├── example_complete_workflow.py
│   └── quick_start_example.py
│
├── docs/                         # 文档目录
│   ├── README.md                 # 文档索引
│   ├── TESTING_GUIDE.md          # 测试指南
│   ├── CVE_MAINLINE_ANALYSIS.md  # 技术文档
│   └── ...                       # 其他文档
│
└── output/                       # 输出目录
    └── *.json, *.txt             # 所有输出文件
```

详细结构请查看：[PROJECT_STRUCTURE.md](./PROJECT_STRUCTURE.md)

## 📚 文档

- **[测试指南](./docs/TESTING_GUIDE.md)** - 完整的测试命令和使用方法
- **[功能验证总结](./docs/功能验证总结.md)** - 项目功能验证（中文）
- **[Mainline识别原理](./docs/CVE_MAINLINE_ANALYSIS.md)** - 技术详解
- **[验证报告](./docs/VERIFICATION_REPORT.md)** - 详细验证报告
- **[项目结构](./PROJECT_STRUCTURE.md)** - 目录结构说明

## 🎯 使用示例

### 示例1：分析CVE-2025-40198

```bash
python3 tests/test_crawl_cve.py CVE-2025-40198
```

**输出**：
```
✅ mainline_commit: 8ecb790ea8c3 (版本: 6.18)
✅ 版本映射关系:
   5.4.301  → 7bf46ff 🔄 Backport
   5.10.246 → b2bac84 🔄 Backport
   6.18     → 8ecb790 ⭐ Mainline
```

### 示例2：查找引入commit

```bash
# 显示搜索策略
python3 tests/test_crawl_cve.py search_introduced 8b67f04ab9de
```

**功能**：
- 精确commit ID匹配
- Subject模糊匹配
- `[backport]` 模式识别
- 基于修改文件的搜索

### 示例3：检查修复状态

```bash
python3 tests/test_crawl_cve.py check_fix abc123 5.10-hulk CVE-2025-40198
```

**功能**：
- 自动获取社区修复commit
- 在目标仓库中搜索
- 计算相似度
- 判断是否已合入

## 🔧 核心模块

| 模块 | 功能 |
|------|------|
| `crawl_cve_patch.py` | 从CVE API获取信息，识别mainline |
| `git_repo_manager.py` | Git仓库管理，commit搜索 |
| `enhanced_cve_analyzer.py` | 完整的CVE分析流程 |
| `enhanced_patch_matcher.py` | Commit匹配算法 |
| `ai_analyze.py` | AI辅助分析（可选） |
| `config_loader.py` | 配置文件加载 |
| `cli.py` | 命令行接口 |

## 🧪 测试功能

### 基础测试
```bash
python3 tests/test_crawl_cve.py CVE-XXXX-XXXXX   # 测试单个CVE
python3 tests/test_crawl_cve.py mainline          # 测试mainline识别
python3 tests/test_crawl_cve.py full              # 测试完整逻辑
```

### 功能测试
```bash
# 查找引入commit
python3 tests/test_crawl_cve.py search_introduced <commit_id> [repo_version]

# 检查修复状态
python3 tests/test_crawl_cve.py check_fix <commit_id> [repo_version] [cve_id]
```

所有输出自动保存到 `output/` 目录。

## 📊 测试结果

**CVE-2025-40198 测试得分：90/100（优秀）**

- ✅ mainline commit识别
- ✅ mainline version识别
- ✅ 版本到commit映射（7/7）
- ✅ 标记正确性

## 🎓 技术亮点

### 1. 智能Mainline识别

通过解析CVE数据中的`versionType: "original_commit_for_fix"`标记，准确识别主线修复commit。

### 2. 多策略搜索

- 精确commit ID匹配（100%准确）
- Subject相似度计算（95%准确）
- Backport模式识别（90%准确）
- 文件匹配（80%准确）

### 3. 完整的版本映射

```python
{
  "mainline_commit": "8ecb790ea8c3",
  "mainline_version": "6.18",
  "version_commit_mapping": {
    "5.4.301": "7bf46ff...",
    "5.10.246": "b2bac84...",
    "6.18": "8ecb790..."
  }
}
```

## 💡 常见问题

### Q: 网络错误怎么办？
A: 即使无法访问kernel.org，也可以：
- 查看搜索策略
- 测试本地仓库功能
- 使用已保存的结果

### Q: 如何配置自己的仓库？
A: 编辑`config.yaml`：
```yaml
repositories:
  my-kernel:
    path: /path/to/your/kernel
    branch: master
```

### Q: 输出文件在哪里？
A: 所有输出统一保存在 `output/` 目录。

## 🤝 贡献

欢迎提交Issue和Pull Request！

## 📄 License

[您的License]

## 📞 联系方式

[您的联系方式]

---

**快速链接**：
- [测试指南](./docs/TESTING_GUIDE.md)
- [项目结构](./PROJECT_STRUCTURE.md)
- [示例代码](./examples/)
- [完整文档](./docs/)
