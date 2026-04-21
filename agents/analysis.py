"""
Analysis Agent
在目标仓库中定位CVE相关commit，实现三级搜索策略：
  Level 1: Commit ID 精确匹配
  Level 2: Subject 语义匹配（含 [backport] 变体）
  Level 3: Code Diff 匹配
"""

import time
import logging
from typing import Dict, List

from core.models import (
    CommitInfo,
    SearchFailure,
    SearchResult,
    SearchStep,
    StrategyResult,
    MultiStrategyResult,
)
from core.git_manager import GitRepoManager
from core.config import SearchConfig
from core.matcher import (
    CommitMatcher, PathMapper, normalize_subject, extract_keywords,
    extract_files_from_diff, subject_similarity, diff_containment,
)

logger = logging.getLogger(__name__)


class AnalysisAgent:
    """目标仓库commit定位Agent"""

    def __init__(self, git_mgr: GitRepoManager, path_mapper: PathMapper = None,
                 search_config=None):
        self.git_mgr = git_mgr
        self.path_mapper = path_mapper or PathMapper()
        self.matcher = CommitMatcher(path_mapper=self.path_mapper)
        self.search_profile = self._coerce_search_profile(search_config)

    @staticmethod
    def _coerce_search_profile(search_config=None) -> Dict:
        cfg = search_config or SearchConfig()
        return {
            "profile": getattr(cfg, "profile", "balanced"),
            "subject_threshold": float(getattr(cfg, "subject_threshold", 0.85)),
            "diff_threshold": float(getattr(cfg, "diff_threshold", 0.70)),
            "subject_candidate_limit": int(getattr(cfg, "subject_candidate_limit", 10)),
            "keyword_candidate_limit": int(getattr(cfg, "keyword_candidate_limit", 30)),
            "diff_candidate_limit": int(getattr(cfg, "diff_candidate_limit", 50)),
            "file_search_limit": int(getattr(cfg, "file_search_limit", 6)),
            "near_miss_limit": int(getattr(cfg, "near_miss_limit", 5)),
        }

    def _new_result(self) -> SearchResult:
        return SearchResult(search_profile=dict(self.search_profile))

    @staticmethod
    def _set_failure(sr: SearchResult, reason: str, detail: str,
                     retryable: bool = False, level: str = "") -> SearchResult:
        sr.failure = SearchFailure(
            reason=reason,
            detail=detail,
            retryable=retryable,
            level=level,
        )
        return sr

    def _failure_from_git(self, sr: SearchResult, *, level: str,
                          fallback_reason: str,
                          fallback_detail: str) -> SearchResult:
        err = getattr(self.git_mgr, "last_error", {}) or {}
        reason = err.get("reason")
        if reason == "git_timeout":
            return self._set_failure(
                sr, "git_timeout", err.get("detail", fallback_detail),
                retryable=True, level=level,
            )
        if reason in {"git_command_failed", "git_exception", "repo_not_configured", "repo_path_missing"}:
            mapped = "diff_fetch_failed" if level == "L3" else "git_command_failed"
            return self._set_failure(
                sr, mapped, err.get("detail", fallback_detail),
                retryable=reason in {"git_timeout", "git_exception"},
                level=level,
            )
        return self._set_failure(sr, fallback_reason, fallback_detail, False, level)

    def _candidate_limit(self) -> int:
        return max(1, int(self.search_profile.get("near_miss_limit", 5)))

    @staticmethod
    def _threshold_delta(score: float, threshold: float) -> float:
        return round(max(0.0, threshold - score), 4)

    # ─── 快速搜索 (短路模式，用于Pipeline) ────────────────────────────

    def search(self, commit_id: str, subject: str, diff_code: str,
               target_version: str,
               use_containment: bool = False) -> SearchResult:
        """
        三级搜索（短路）：首个命中即返回，同时记录每级步骤。
        use_containment=True:  引入commit搜索，L3启用包含度检测(适配squash场景)
        use_containment=False: 修复commit搜索，L3仅用双向相似度
        """
        sr = self._new_result()

        # Level 1
        t0 = time.time()
        logger.info("  [L1] 精确ID匹配: %s", commit_id[:12])
        try:
            status, exact = self.git_mgr.check_commit_existence(commit_id, target_version)
        except Exception as exc:
            self._set_failure(sr, "git_command_failed", str(exc), retryable=True, level="L1")
            sr.steps.append(SearchStep("L1", "miss", sr.failure.detail, time.time() - t0))
            return sr
        if status == "on_branch" and exact:
            sr.found = True
            sr.strategy = "exact_id"
            sr.confidence = 1.0
            sr.target_commit = exact["commit_id"]
            sr.target_subject = exact["subject"]
            sr.steps.append(SearchStep("L1", "hit", exact["commit_id"][:12], time.time() - t0))
            logger.info("  [L1] 命中: %s", exact["commit_id"][:12])
            return sr
        l1_detail = "目标分支中不存在"
        if status == "not_on_branch":
            l1_detail = "commit 存在于对象库但不在目标分支历史中"
        l1_miss_step = SearchStep("L1", "miss", l1_detail, time.time() - t0)
        sr.steps.append(l1_miss_step)

        if not subject:
            self._set_failure(sr, "no_candidates", "无 subject 信息，无法执行 L2 subject 搜索", False, "L2")
            return sr

        # Level 2
        t0 = time.time()
        logger.info("  [L2] Subject匹配: %s", subject[:60])
        sr = self._search_subject(commit_id, subject, target_version)
        if sr.found:
            sr.steps.insert(0, l1_miss_step)
            sr.steps.append(SearchStep("L2", "hit",
                f"{sr.target_commit[:12]} ({sr.confidence:.0%})", time.time() - t0))
            return sr
        step2_detail = (
            f"{len(sr.candidates)} 个候选, 最高 {sr.candidates[0]['similarity']:.0%}, "
            f"距阈值 {sr.candidates[0].get('threshold_delta', 0):.0%}"
            if sr.candidates else (sr.failure.detail if sr.failure else "无匹配")
        )
        l2_step = SearchStep("L2", "miss", step2_detail, time.time() - t0)

        # Level 3
        if diff_code:
            files = extract_files_from_diff(diff_code)
            if files:
                search_files = self.path_mapper.expand_files(files) if self.path_mapper.has_rules else files
                if len(search_files) > len(files):
                    logger.info("  [L3] 路径映射: %s → +%d 等价路径",
                                ", ".join(files[:2]), len(search_files) - len(files))
                t0 = time.time()
                mode_label = "Diff包含匹配" if use_containment else "Diff匹配"
                logger.info("  [L3] %s (%s)", mode_label, ", ".join(files[:3]))
                sr = self._search_diff(commit_id, subject, diff_code, files,
                                       target_version, use_containment=use_containment)
                if sr.found:
                    sr.steps.insert(0, l1_miss_step)
                    sr.steps.insert(1, l2_step)
                    sr.steps.append(SearchStep("L3", "hit",
                        f"{sr.target_commit[:12]} ({sr.confidence:.0%})", time.time() - t0))
                    return sr
                sr.steps.insert(0, l1_miss_step)
                sr.steps.insert(1, l2_step)
                l3_detail = (
                    f"{len(sr.candidates)} 个候选, 最高 {sr.candidates[0].get('confidence', 0):.0%}, "
                    f"距阈值 {sr.candidates[0].get('threshold_delta', 0):.0%}"
                    if sr.candidates else (sr.failure.detail if sr.failure else "无匹配")
                )
                sr.steps.append(SearchStep("L3", "miss", l3_detail, time.time() - t0))
                return sr

        sr.steps.insert(0, l1_miss_step)
        sr.steps.append(l2_step)
        if not sr.failure:
            self._set_failure(sr, "no_candidates", "无 diff 信息，无法执行 L3 diff 搜索", False, "L3")
        return sr

    # ─── 详细搜索 (全策略，用于check-intro) ──────────────────────────

    def search_detailed(self, commit_id: str, subject: str, diff_code: str,
                        modified_files: List[str], author: str,
                        target_version: str,
                        use_containment: bool = True) -> MultiStrategyResult:
        """
        运行全部三级策略，不短路，返回每个策略的独立结果。
        use_containment=True:  引入commit检测 (check-intro)
        use_containment=False: 修复commit检测 (check-fix)
        """
        msr = MultiStrategyResult(
            commit_id=commit_id,
            subject=subject,
            author=author,
            modified_files=modified_files,
        )

        # ── L1: ID 精确匹配 ─────────────────────────────────────────
        t0 = time.time()
        s1 = StrategyResult(level="L1", name="ID 精确匹配")
        status, info = self.git_mgr.check_commit_existence(commit_id, target_version)
        branch = self.git_mgr._get_repo_branch(target_version) or "目标分支"
        if status == "on_branch":
            s1.found = True
            s1.confidence = 1.0
            s1.target_commit = info["commit_id"]
            s1.target_subject = info["subject"]
            s1.detail = f"commit 存在于 {branch}"
        elif status == "not_on_branch":
            s1.found = False
            s1.detail = (f"commit 存在于仓库但不在 {branch} 分支上"
                         f" (可能有对应backport, 见L2/L3)")
            if info:
                s1.target_commit = info["commit_id"]
                s1.target_subject = info.get("subject", "")
        else:
            s1.detail = "commit 在仓库中不存在"
        s1.elapsed = time.time() - t0
        msr.strategies.append(s1)

        # ── L2: Subject 语义匹配 ────────────────────────────────────
        t0 = time.time()
        s2 = StrategyResult(level="L2", name="Subject 语义匹配")
        if subject:
            sr2 = self._search_subject(commit_id, subject, target_version)
            s2.candidates = sr2.candidates
            if sr2.found:
                s2.found = True
                s2.confidence = sr2.confidence
                s2.target_commit = sr2.target_commit
                s2.target_subject = sr2.target_subject
                s2.detail = f"相似度 {sr2.confidence:.0%}: {sr2.target_subject[:50]}"
            elif sr2.candidates:
                best = sr2.candidates[0]
                s2.detail = (f"最高相似度 {best['similarity']:.0%} "
                             f"(阈值{best.get('threshold', self.search_profile['subject_threshold']):.0%}, "
                             f"差{best.get('threshold_delta', 0):.0%}): "
                             f"{best['commit_id'][:12]}")
            else:
                s2.detail = "未找到相似subject"
        else:
            s2.detail = "无subject信息, 跳过"
        s2.elapsed = time.time() - t0
        msr.strategies.append(s2)

        # ── L3: Diff 代码匹配 ────────────────────────────────────────
        t0 = time.time()
        l3_label = "Diff 代码匹配 (含包含度)" if use_containment else "Diff 代码匹配"
        s3 = StrategyResult(level="L3", name=l3_label)
        files = modified_files or (extract_files_from_diff(diff_code) if diff_code else [])
        if diff_code and files:
            if self.path_mapper.has_rules:
                expanded = self.path_mapper.expand_files(files)
                if len(expanded) > len(files):
                    s3.detail = f"路径映射: +{len(expanded) - len(files)} 等价路径"
            sr3 = self._search_diff(commit_id, subject or "", diff_code, files,
                                    target_version, use_containment=use_containment)
            s3.candidates = sr3.candidates
            if sr3.found:
                s3.found = True
                s3.confidence = sr3.confidence
                s3.target_commit = sr3.target_commit
                s3.target_subject = sr3.target_subject
                ctype = sr3.strategy.split("(")[-1].rstrip(")") if "(" in sr3.strategy else ""
                label = "包含度" if "containment" in ctype else "相似度"
                s3.detail = f"{label} {sr3.confidence:.0%}: {sr3.target_commit[:12]}"
            elif sr3.candidates:
                best = sr3.candidates[0]
                conf = best.get("confidence", 0)
                ct = best.get("containment")
                extra = f", 包含度 {ct:.0%}" if ct and ct > 0 else ""
                s3.detail = (f"最高置信度 {conf:.0%}{extra} "
                             f"(阈值{best.get('threshold', self.search_profile['diff_threshold']):.0%}, "
                             f"差{best.get('threshold_delta', 0):.0%}): "
                             f"{best.get('commit_id', '')[:12]}")
            else:
                s3.detail = sr3.failure.detail if sr3.failure else "修改同文件的commit中无匹配"
        else:
            s3.detail = "无diff信息, 跳过"
        s3.elapsed = time.time() - t0
        msr.strategies.append(s3)

        return msr

    # ─── Level 2 ─────────────────────────────────────────────────────

    def _search_subject(self, commit_id: str, subject: str,
                        tv: str) -> SearchResult:
        sr = self._new_result()
        norm = normalize_subject(subject)
        threshold = self.search_profile["subject_threshold"]
        subject_limit = self.search_profile["subject_candidate_limit"]
        keyword_limit = self.search_profile["keyword_candidate_limit"]

        try:
            candidates = self.git_mgr.search_by_subject(norm, tv, limit=subject_limit)
            if not candidates:
                kws = extract_keywords(subject)
                if kws:
                    candidates = self.git_mgr.search_by_keywords(kws, tv, limit=keyword_limit)
        except Exception as exc:
            return self._set_failure(sr, "git_command_failed", str(exc), True, "L2")
        if not candidates:
            return self._failure_from_git(
                sr,
                level="L2",
                fallback_reason="no_candidates",
                fallback_detail="subject/keyword 搜索没有返回候选",
            )

        best, best_sim = None, 0.0
        all_cands = []
        for c in candidates:
            sim = subject_similarity(subject, c.subject)
            all_cands.append({
                "commit_id": c.commit_id,
                "subject": c.subject,
                "similarity": sim,
                "confidence": sim,
                "threshold": threshold,
                "threshold_delta": self._threshold_delta(sim, threshold),
                "passed": sim >= threshold,
                "failure_reason": "" if sim >= threshold else "below_threshold",
            })
            if sim > best_sim:
                best_sim = sim
                best = c

        sr.candidates = sorted(all_cands, key=lambda x: x["similarity"], reverse=True)[:self._candidate_limit()]
        sr.near_misses = [c for c in sr.candidates if not c.get("passed")]

        if best and best_sim >= threshold:
            sr.found = True
            sr.strategy = "subject_match"
            sr.confidence = best_sim
            sr.target_commit = best.commit_id
            sr.target_subject = best.subject
            logger.info("  [L2] 命中: %s (%.0f%%)", best.commit_id[:12], best_sim * 100)
        elif best:
            self._set_failure(
                sr,
                "below_threshold",
                f"最高 subject 相似度 {best_sim:.0%} 低于阈值 {threshold:.0%}",
                retryable=False,
                level="L2",
            )
        return sr

    # ─── Level 3 ─────────────────────────────────────────────────────

    def _search_diff(self, commit_id: str, subject: str, diff_code: str,
                     files: List[str], tv: str,
                     use_containment: bool = False) -> SearchResult:
        sr = self._new_result()
        search_files = self.path_mapper.expand_files(files) if self.path_mapper.has_rules else files
        file_limit = max(1, int(self.search_profile["file_search_limit"]))
        diff_limit = max(1, int(self.search_profile["diff_candidate_limit"]))
        threshold = self.search_profile["diff_threshold"]
        try:
            fc = self.git_mgr.search_by_files(search_files[:file_limit], tv, limit=diff_limit)
        except Exception as exc:
            return self._set_failure(sr, "git_command_failed", str(exc), True, "L3")
        if not fc:
            return self._failure_from_git(
                sr,
                level="L3",
                fallback_reason="no_candidates",
                fallback_detail=f"同文件搜索没有返回候选 (files={len(search_files[:file_limit])})",
            )

        source = CommitInfo(commit_id=commit_id, subject=subject,
                            diff_code=diff_code, modified_files=files)
        targets = []
        diff_failures = 0
        for gc in fc:
            d = self.git_mgr.get_commit_diff(gc.commit_id, tv)
            if d is None:
                diff_failures += 1
                continue
            targets.append(CommitInfo(
                commit_id=gc.commit_id, subject=gc.subject,
                diff_code=d,
                modified_files=extract_files_from_diff(d),
            ))
        if not targets:
            return self._failure_from_git(
                sr,
                level="L3",
                fallback_reason="diff_fetch_failed",
                fallback_detail=f"找到 {len(fc)} 个同文件候选，但 diff 拉取全部失败",
            )

        matches = self.matcher.match_comprehensive(source, targets,
                                                    use_containment=use_containment,
                                                    subject_threshold=self.search_profile["subject_threshold"],
                                                    diff_threshold=threshold,
                                                    include_below_threshold=True)
        if not matches:
            return self._set_failure(
                sr,
                "below_threshold",
                f"同文件候选 {len(targets)} 个，但未形成可排序的 diff near-miss",
                retryable=False,
                level="L3",
            )

        sr.candidates = self._build_l3_candidates(matches[:self._candidate_limit()], self.search_profile)
        sr.near_misses = [c for c in sr.candidates if not c.get("passed")]
        best_candidate = sr.candidates[0] if sr.candidates else {}

        if matches and best_candidate.get("passed"):
            b = matches[0]
            sr.found = True
            sr.strategy = f"diff_match ({b.match_type})"
            sr.confidence = b.confidence
            sr.target_commit = b.target_commit
            sr.target_subject = b.details.get("target_subject", "")
            logger.info("  [L3] 命中: %s (%.0f%% via %s)",
                        b.target_commit[:12], b.confidence * 100, b.match_type)
        else:
            self._set_failure(
                sr,
                "below_threshold",
                (
                    f"最高 diff 置信度 {best_candidate.get('confidence', 0):.0%} "
                    f"低于阈值 {best_candidate.get('threshold', threshold):.0%}"
                ),
                retryable=False,
                level="L3",
            )
        if diff_failures:
            sr.search_profile["diff_fetch_failures"] = diff_failures
        return sr

    @staticmethod
    def _threshold_for_match(match_type: str, profile: Dict) -> float:
        if match_type == "exact_id":
            return 1.0
        if match_type == "subject_similarity":
            return float(profile.get("subject_threshold", 0.85))
        return float(profile.get("diff_threshold", 0.70))

    @classmethod
    def _build_l3_candidates(cls, matches, profile: Dict) -> List[dict]:
        out = []
        for m in matches:
            threshold = cls._threshold_for_match(m.match_type, profile)
            entry = {
                "commit_id": m.target_commit,
                "confidence": m.confidence,
                "type": m.match_type,
                "target_subject": m.details.get("target_subject", ""),
                "threshold": threshold,
                "threshold_delta": cls._threshold_delta(m.confidence, threshold),
                "passed": m.confidence >= threshold,
                "failure_reason": "" if m.confidence >= threshold else "below_threshold",
            }
            if "file_sim" in m.details:
                entry["file_similarity"] = m.details["file_sim"]
            if "diff_containment" in m.details:
                entry["containment"] = m.details["diff_containment"]
            if "diff_sim" in m.details:
                entry["similarity"] = m.details["diff_sim"]
            out.append(entry)
        return out
