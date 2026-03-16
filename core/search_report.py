"""
详细搜索过程报告 — 为分析人员提供逐策略的搜索结果和 context 对比
"""

from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class StrategyResult:
    """单个搜索策略的结果"""
    strategy_name: str  # "精确序列", "锚点行", "函数作用域", etc.
    success: bool
    position: Optional[int] = None  # 匹配位置
    confidence: float = 0.0  # 置信度 [0, 1]
    details: str = ""  # 额外信息


@dataclass
class HunkSearchReport:
    """单个 hunk 的完整搜索报告"""
    hunk_index: int
    file_path: str
    hunk_header: str  # "@@ -162,6 +162,9 @@"
    
    # Hunk 内容
    removed_lines: List[str] = field(default_factory=list)
    added_lines: List[str] = field(default_factory=list)
    before_context: List[str] = field(default_factory=list)
    after_context: List[str] = field(default_factory=list)
    
    # 搜索过程
    strategy_results: List[StrategyResult] = field(default_factory=list)
    
    # 最终结果
    final_position: Optional[int] = None
    final_strategy: Optional[str] = None
    final_confidence: float = 0.0
    
    # Context 对比
    mainline_context: List[str] = field(default_factory=list)  # mainline patch 的 context
    target_context: List[str] = field(default_factory=list)    # 目标文件的实际 context
    context_match_rate: float = 0.0  # context 匹配率
    
    def add_strategy_result(self, result: StrategyResult):
        """添加策略结果"""
        self.strategy_results.append(result)
        if result.success and self.final_position is None:
            self.final_position = result.position
            self.final_strategy = result.strategy_name
            self.final_confidence = result.confidence
    
    def set_context_comparison(self, mainline: List[str], target: List[str]):
        """设置 context 对比"""
        self.mainline_context = mainline
        self.target_context = target
        
        # 计算匹配率
        if mainline and target:
            matches = sum(1 for m, t in zip(mainline, target) if m.strip() == t.strip())
            self.context_match_rate = matches / max(len(mainline), len(target))
        else:
            self.context_match_rate = 0.0


@dataclass
class DetailedSearchReport:
    """完整的补丁搜索报告"""
    patch_commit_id: str
    target_file: str
    
    hunk_reports: List[HunkSearchReport] = field(default_factory=list)
    
    # 统计
    total_hunks: int = 0
    successful_hunks: int = 0
    failed_hunks: int = 0
    
    def add_hunk_report(self, report: HunkSearchReport):
        """添加 hunk 报告"""
        self.hunk_reports.append(report)
        self.total_hunks += 1
        if report.final_position is not None:
            self.successful_hunks += 1
        else:
            self.failed_hunks += 1
    
    def get_summary(self) -> Dict:
        """获取摘要"""
        return {
            "patch_commit_id": self.patch_commit_id,
            "target_file": self.target_file,
            "total_hunks": self.total_hunks,
            "successful_hunks": self.successful_hunks,
            "failed_hunks": self.failed_hunks,
            "success_rate": (self.successful_hunks / self.total_hunks * 100
                           if self.total_hunks > 0 else 0),
        }
