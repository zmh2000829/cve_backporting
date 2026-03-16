"""
代码语义匹配 — 用代码内容而非 context 序列做跨版本定位

核心思想：
  mainline patch 的 context 在企业仓库中被打断（中间插入额外代码）。
  不再依赖 context 序列的连续性，而是提取 patch 的实际代码片段（removed/added），
  用多维度代码相似度在目标文件中搜索。

多维度相似度：
  1. 变量名/函数名匹配（关键字提取）
  2. 代码结构相似度（编辑距离）
  3. 关键字序列匹配（去空格/注释后的序列）
"""

import re
import logging
from typing import List, Optional, Tuple, Dict
from difflib import SequenceMatcher

logger = logging.getLogger(__name__)


class PatchContextExtractor:
    """从 mainline patch 提取代码片段和元数据"""

    @staticmethod
    def extract_hunk_metadata(hunk_header: str) -> Dict:
        """
        从 @@ 行提取元数据：行号、函数名等
        格式: @@ -162,6 +162,9 @@ func_name
        """
        match = re.match(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\s*(.*)', hunk_header)
        if not match:
            return {}
        
        old_start = int(match.group(1))
        old_count = int(match.group(2)) if match.group(2) else 1
        new_start = int(match.group(3))
        new_count = int(match.group(4)) if match.group(4) else 1
        func_name = match.group(5).strip() if match.group(5) else ""
        
        return {
            "old_start": old_start,
            "old_count": old_count,
            "new_start": new_start,
            "new_count": new_count,
            "func_name": func_name,
        }

    @staticmethod
    def extract_identifiers(code_lines: List[str]) -> set:
        """
        从代码行提取标识符（变量名、函数名、宏等）
        """
        identifiers = set()
        for line in code_lines:
            # 移除注释
            line = re.sub(r'//.*$', '', line)
            line = re.sub(r'/\*.*?\*/', '', line)
            # 提取标识符（字母、数字、下划线）
            tokens = re.findall(r'\b[a-zA-Z_]\w*\b', line)
            identifiers.update(tokens)
        return identifiers

    @staticmethod
    def extract_keywords(code_lines: List[str]) -> List[str]:
        """
        提取代码的关键字序列（去空格、注释、字符串）
        用于结构相似度比较
        """
        keywords = []
        for line in code_lines:
            # 移除注释
            line = re.sub(r'//.*$', '', line)
            line = re.sub(r'/\*.*?\*/', '', line)
            # 移除字符串
            line = re.sub(r'"[^"]*"', '""', line)
            line = re.sub(r"'[^']*'", "''", line)
            # 提取关键字和符号
            tokens = re.findall(r'\b[a-zA-Z_]\w*\b|[{}()\[\];,=+\-*/<>!&|]', line)
            keywords.extend(tokens)
        return keywords


class CodeMatcher:
    """多维度代码相似度匹配"""

    def __init__(self, threshold_structure: float = 0.65,
                 threshold_identifier: float = 0.5):
        """
        threshold_structure: 代码结构相似度阈值
        threshold_identifier: 标识符匹配率阈值
        """
        self.threshold_structure = threshold_structure
        self.threshold_identifier = threshold_identifier

    def find_code_in_file(self, target_code: List[str],
                          file_lines: List[str],
                          hint_line: Optional[int] = None,
                          window: int = 300) -> List[Tuple[int, float]]:
        """
        在文件中搜索目标代码片段。
        返回候选位置列表 [(line_number, confidence_score), ...]
        
        搜索策略：
          1. 如果有 hint_line，先在 ±window 范围内搜索
          2. 然后全局搜索
          3. 返回所有候选位置，按置信度排序
        """
        candidates = []
        
        # 提取目标代码的特征
        target_ids = PatchContextExtractor.extract_identifiers(target_code)
        target_keywords = PatchContextExtractor.extract_keywords(target_code)
        
        if not target_keywords:
            logger.warning("目标代码无关键字，无法进行语义匹配")
            return []
        
        # 搜索范围
        search_ranges = []
        if hint_line is not None:
            start = max(0, hint_line - window)
            end = min(len(file_lines), hint_line + window)
            search_ranges.append((start, end, "hint_window"))
        search_ranges.append((0, len(file_lines), "global"))
        
        for start, end, range_type in search_ranges:
            for i in range(start, end - len(target_code) + 1):
                candidate_lines = file_lines[i:i + len(target_code)]
                
                # 计算多维度相似度
                score = self._compute_similarity(
                    target_code, candidate_lines,
                    target_ids, target_keywords
                )
                
                if score > 0.5:  # 基础阈值
                    candidates.append((i, score, range_type))
        
        # 去重并按置信度排序
        seen = set()
        unique_candidates = []
        for line_num, score, range_type in sorted(candidates, key=lambda x: -x[1]):
            if line_num not in seen:
                seen.add(line_num)
                unique_candidates.append((line_num, score))
        
        return unique_candidates[:10]  # 返回前 10 个候选

    def _compute_similarity(self, target_code: List[str],
                            candidate_lines: List[str],
                            target_ids: set,
                            target_keywords: List[str]) -> float:
        """
        计算多维度相似度：
          1. 结构相似度（编辑距离）— 权重 0.5
          2. 标识符匹配率 — 权重 0.3
          3. 关键字序列相似度 — 权重 0.2
        """
        # 1. 结构相似度
        target_str = "\n".join(target_code)
        candidate_str = "\n".join(candidate_lines)
        structure_sim = SequenceMatcher(None, target_str, candidate_str).ratio()
        
        # 2. 标识符匹配率
        candidate_ids = PatchContextExtractor.extract_identifiers(candidate_lines)
        if target_ids:
            id_match_rate = len(target_ids & candidate_ids) / len(target_ids)
        else:
            id_match_rate = 0.0
        
        # 3. 关键字序列相似度
        candidate_keywords = PatchContextExtractor.extract_keywords(candidate_lines)
        if target_keywords and candidate_keywords:
            kw_sim = SequenceMatcher(None, target_keywords, candidate_keywords).ratio()
        else:
            kw_sim = 0.0
        
        # 加权平均
        score = (0.5 * structure_sim +
                 0.3 * id_match_rate +
                 0.2 * kw_sim)
        
        return score

    def find_removed_lines(self, removed_code: List[str],
                           file_lines: List[str],
                           hint_line: Optional[int] = None) -> Optional[int]:
        """
        在文件中搜索被删除的代码行。
        返回第一个匹配行的行号，或 None。
        """
        candidates = self.find_code_in_file(
            removed_code, file_lines, hint_line, window=300
        )
        
        if candidates:
            best_line, best_score = candidates[0]
            logger.debug(f"代码语义匹配: 行 {best_line}, 置信度 {best_score:.2f}")
            return best_line
        
        return None

    def find_insertion_point(self, before_context: List[str],
                             after_context: List[str],
                             file_lines: List[str],
                             hint_line: Optional[int] = None) -> Optional[int]:
        """
        对于纯添加 hunk，用 before-context 或 after-context 找插入点。
        返回插入点行号，或 None。
        """
        # 优先用 before-context 最后一行做锚点
        if before_context:
            anchor_line = before_context[-1]
            candidates = self.find_code_in_file(
                [anchor_line], file_lines, hint_line, window=300
            )
            if candidates:
                anchor_pos, score = candidates[0]
                logger.debug(f"before-context 锚点匹配: 行 {anchor_pos}, 置信度 {score:.2f}")
                return anchor_pos + 1
        
        # 次选：after-context 第一行
        if after_context:
            anchor_line = after_context[0]
            candidates = self.find_code_in_file(
                [anchor_line], file_lines, hint_line, window=300
            )
            if candidates:
                anchor_pos, score = candidates[0]
                logger.debug(f"after-context 锚点匹配: 行 {anchor_pos}, 置信度 {score:.2f}")
                return anchor_pos
        
        return None
