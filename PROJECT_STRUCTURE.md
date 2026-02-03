# 项目目录结构

```
cve_backporting/
│
├── README.md                      # 项目主文档
├── requirements.txt               # Python依赖
├── config.example.yaml           # 配置文件示例
│
├── 核心模块/
│   ├── crawl_cve_patch.py        # CVE信息获取和mainline识别
│   ├── git_repo_manager.py       # Git仓库管理和搜索
│   ├── enhanced_cve_analyzer.py  # 完整的CVE分析
│   ├── enhanced_patch_matcher.py # Commit匹配算法
│   ├── ai_analyze.py             # AI辅助分析
│   ├── config_loader.py          # 配置加载器
│   └── cli.py                    # 命令行接口
│
├── tests/                        # 测试目录
│   ├── README.md                 # 测试说明
│   └── test_crawl_cve.py         # 综合测试工具
│
├── examples/                     # 示例代码
│   ├── example_complete_workflow.py  # 完整工作流示例
│   └── quick_start_example.py        # 快速开始示例
│
├── docs/                         # 文档目录
│   ├── README.md                 # 文档索引
│   ├── TESTING_GUIDE.md          # 测试指南
│   ├── CVE_MAINLINE_ANALYSIS.md  # Mainline识别原理
│   ├── VERIFICATION_REPORT.md    # 验证报告
│   └── 功能验证总结.md            # 中文总结
│
└── output/                       # 输出目录
    ├── .gitkeep                  # Git保留空目录
    ├── *.json                    # 测试和分析结果
    └── *.txt                     # 补丁文件

```

## 目录说明

### 核心模块（根目录）
所有核心Python模块都在项目根目录，便于互相导入和使用。

### tests/ - 测试目录
- 所有测试文件统一放在这里
- 测试输出自动保存到 `output/` 目录
- 运行测试：`python3 tests/test_crawl_cve.py <参数>`

### examples/ - 示例代码
- 完整的使用示例
- 演示各种功能的代码
- 可以直接运行学习

### docs/ - 文档目录
- 所有文档统一放在这里
- 包含详细的使用指南和技术文档
- 中英文文档分类清晰

### output/ - 输出目录
- 所有程序生成的文件都保存在这里
- 包括测试结果、分析报告、补丁文件等
- 该目录已加入 `.gitignore`（除了.gitkeep）

## 使用方式

### 1. 测试功能

```bash
# 从项目根目录运行
python3 tests/test_crawl_cve.py CVE-2025-40198
python3 tests/test_crawl_cve.py search_introduced <commit_id>
python3 tests/test_crawl_cve.py check_fix <commit_id>
```

所有输出自动保存到 `output/` 目录。

### 2. 运行示例

```bash
# 从项目根目录运行
python3 examples/example_complete_workflow.py
python3 examples/quick_start_example.py
```

### 3. 查看文档

```bash
# 主文档
cat README.md

# 详细文档
cat docs/TESTING_GUIDE.md
cat docs/CVE_MAINLINE_ANALYSIS.md
cat docs/VERIFICATION_REPORT.md
```

## 文件组织原则

1. **核心代码在根目录** - 便于互相导入
2. **测试独立目录** - 清晰分离
3. **示例独立目录** - 学习参考
4. **文档统一管理** - docs/
5. **输出统一位置** - output/

## 更新记录

- 2026-02-03: 重新组织项目结构
  - 移动文档到 docs/
  - 移动测试到 tests/
  - 移动示例到 examples/
  - 统一输出到 output/
  - 删除重复文件
