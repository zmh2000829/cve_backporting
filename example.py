import json
from crawl_cve_patch import Crawl_Cve_Patch


def main():
    """完整演示CVE分析流程"""
    
    cve_id = "CVE-2025-40198"
    
    print("="*80)
    print(f"CVE分析示例: {cve_id}")
    print("="*80)
    
    # ===== 步骤1: 获取CVE信息 =====
    print("\n[步骤1] 从MITRE CVE API获取信息...")
    print("-"*80)
    
    crawler = Crawl_Cve_Patch()
    result = crawler.get_introduced_fixed_commit(cve_id)
    
    if not result:
        print("❌ 获取CVE信息失败")
        return
    
    # ===== 步骤2: 显示分析结果 =====
    print("\n[步骤2] CVE基本信息")
    print("-"*80)
    print(f"CVE ID: {cve_id}")
    print(f"描述: {result['cve_description'][:200]}...")
    print(f"严重程度: {result.get('severity', 'N/A')}")
    
    # ===== 步骤3: Mainline修复信息 =====
    print("\n[步骤3] Mainline修复信息")
    print("-"*80)
    
    mainline_commit = result.get('mainline_commit', '')
    mainline_version = result.get('mainline_version', '')
    introduced_commit = result.get('introduced_commit_id', '')
    
    print(f"⭐ Mainline修复commit: {mainline_commit}")
    print(f"   对应内核版本: {mainline_version}")
    print(f"   问题引入commit: {introduced_commit or '未知'}")
    
    # ===== 步骤4: 版本映射关系 =====
    print("\n[步骤4] 版本到commit的完整映射")
    print("-"*80)
    
    version_mapping = result.get('version_commit_mapping', {})
    
    if version_mapping:
        print(f"找到 {len(version_mapping)} 个版本的修复commits:")
        print()
        print(f"{'版本':<20} {'Commit ID':<15} {'类型'}")
        print("-"*60)
        
        for version in sorted(version_mapping.keys()):
            commit = version_mapping[version]
            is_mainline = (version == mainline_version)
            commit_type = "⭐ Mainline" if is_mainline else "🔄 Backport"
            print(f"{version:<20} {commit[:12]:<15} {commit_type}")
    
    # ===== 步骤5: 使用建议 =====
    print("\n[步骤5] 使用建议")
    print("-"*80)
    print()
    print("接下来您需要：")
    print()
    print("1️⃣  确定您的内核版本")
    print("   例如：5.10.x、6.1.x 等")
    print()
    print("2️⃣  在自维护仓库中查找对应的backport commit")
    print("   使用以下策略：")
    print("   a) 精确匹配commit ID")
    print(f"      git log --all --grep='{mainline_commit[:12]}'")
    print()
    print("   b) 匹配commit subject")
    print("      git log --all --grep='ext4.*buffer.*over-read'")
    print()
    print("   c) 匹配backport格式")
    print("      git log --all --grep='\\[backport\\].*ext4'")
    print()
    print("3️⃣  如果未找到，需要合入对应版本的backport commit")
    print()
    
    # 根据主流版本给出建议
    common_versions = ["5.4.301", "5.10.246", "6.1.158", "6.6.114"]
    for ver in common_versions:
        if ver in version_mapping:
            commit = version_mapping[ver]
            print(f"   如果您的内核基于 {ver}，应合入: {commit[:12]}")
    
    print()
    print("4️⃣  检查并合入前置依赖补丁")
    print("   使用 enhanced_cve_analyzer.py 的完整分析功能")
    print()
    
    # ===== 步骤6: 保存结果 =====
    output_file = f"analysis_{cve_id.replace('-', '_')}.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=4, ensure_ascii=False)
    
    print(f"✅ 完整分析结果已保存到: {output_file}")
    print()
    
    # ===== 步骤7: 高级功能提示 =====
    print("\n[高级功能] 使用enhanced_cve_analyzer进行完整分析")
    print("-"*80)
    print()
    print("如果您有配置好的GitRepoManager，可以运行完整分析：")
    print()
    print("```python")
    print("from enhanced_cve_analyzer import EnhancedCVEAnalyzer")
    print("from config_loader import ConfigLoader")
    print()
    print("# 加载配置")
    print("config = ConfigLoader.load('config.yaml')")
    print()
    print("# 创建分析器")
    print("analyzer = EnhancedCVEAnalyzer(...)")
    print()
    print("# 完整分析")
    print("result = analyzer.analyze_cve_patch_enhanced(")
    print(f"    cve_id='{cve_id}',")
    print("    target_kernel_version='your-kernel-version'")
    print(")")
    print()
    print("# 查看结果")
    print("print(result['recommendations'])")
    print("```")
    print()
    
    print("="*80)
    print("分析完成！")
    print("="*80)


if __name__ == "__main__":
    main()