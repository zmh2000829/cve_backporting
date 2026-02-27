"""
Crawler Agent
负责从外部数据源获取CVE漏洞信息和补丁内容：
  - MITRE CVE API (cveawg.mitre.org)
  - Google Kernel Mirror (kernel.googlesource.com)
"""

import re
import json
import base64
import logging
import requests
from typing import Dict, List, Optional

from core.models import CveInfo, PatchInfo

logger = logging.getLogger(__name__)

try:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pass


class CrawlerAgent:
    """CVE情报采集Agent"""

    MITRE_API = "https://cveawg.mitre.org/api/cve/"
    KERNEL_GIT = "https://kernel.googlesource.com/pub/scm/linux/kernel/git/stable/linux"

    def __init__(self, api_timeout: int = 30):
        self.api_timeout = api_timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "CVE-Backporting-Tool/3.0",
            "Accept": "application/json",
        })

    # ─── public ──────────────────────────────────────────────────────

    def fetch_cve(self, cve_id: str) -> Optional[CveInfo]:
        """获取CVE完整信息"""
        logger.info("[Crawler] 获取 %s ...", cve_id)
        raw = self._fetch_mitre(cve_id)
        if not raw:
            return None
        info = self._parse_cve(raw, cve_id)
        logger.info("[Crawler] %s: mainline=%s (%s), %d fix, %d intro",
                     cve_id,
                     info.mainline_fix_commit[:12] if info.mainline_fix_commit else "N/A",
                     info.mainline_version or "N/A",
                     len(info.fix_commits), len(info.introduced_commits))
        return info

    def fetch_patch(self, commit_id: str) -> Optional[PatchInfo]:
        """从 kernel.googlesource.com 获取补丁元数据+diff"""
        logger.info("[Crawler] 获取 patch %s ...", commit_id[:12])
        patch = PatchInfo(commit_id=commit_id)

        # JSON元数据
        try:
            url = f"{self.KERNEL_GIT}/+/{commit_id}?format=JSON"
            resp = self.session.get(url, timeout=self.api_timeout, verify=False)
            if resp.status_code == 200:
                text = resp.text
                if text.startswith(")]}'"):
                    text = text[text.index("\n") + 1:]
                data = json.loads(text)
                msg = data.get("message", "")
                patch.subject = msg.split("\n")[0] if msg else ""
                patch.commit_msg = msg
                author = data.get("author", {})
                patch.author = f"{author.get('name', '')} <{author.get('email', '')}>"
                patch.date = author.get("time", "")
                for td in data.get("tree_diff", []):
                    p = td.get("new_path") or td.get("old_path", "")
                    if p and p != "/dev/null":
                        patch.modified_files.append(p)
        except Exception as e:
            logger.debug("[Crawler] JSON元数据异常: %s", e)

        # TEXT diff (base64)
        try:
            url = f"{self.KERNEL_GIT}/+/{commit_id}%5E%21?format=TEXT"
            resp = self.session.get(url, timeout=self.api_timeout, verify=False)
            if resp.status_code == 200:
                patch.diff_code = base64.b64decode(resp.text).decode("utf-8", errors="replace")
                if not patch.modified_files:
                    patch.modified_files = self._files_from_diff(patch.diff_code)
        except Exception as e:
            logger.debug("[Crawler] diff异常: %s", e)

        if patch.subject or patch.diff_code:
            return patch
        logger.warning("[Crawler] patch获取失败: %s", commit_id[:12])
        return None

    # ─── MITRE ───────────────────────────────────────────────────────

    def _fetch_mitre(self, cve_id: str) -> Optional[Dict]:
        try:
            resp = self.session.get(f"{self.MITRE_API}{cve_id}",
                                    timeout=self.api_timeout, verify=False)
            if resp.status_code == 404:
                logger.warning("[Crawler] CVE不存在: %s", cve_id)
                return None
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            logger.error("[Crawler] MITRE请求失败: %s", e)
            return None

    # ─── parse ───────────────────────────────────────────────────────

    def _parse_cve(self, raw: Dict, cve_id: str) -> CveInfo:
        info = CveInfo(cve_id=cve_id)
        cna = raw.get("containers", {}).get("cna", {})

        descs = cna.get("descriptions", [])
        if descs:
            info.description = descs[0].get("value", "")

        for m in cna.get("metrics", []):
            if "cvssV3_1" in m:
                info.severity = m["cvssV3_1"].get("baseSeverity", "unknown")
                break

        for ref in cna.get("references", []):
            url = ref.get("url", "")
            tags = ref.get("tags", [])
            cid = self._commit_from_url(url)
            if not cid:
                continue
            entry = {"commit_id": cid, "url": url, "tags": tags,
                     "source": self._source(url)}
            if any(t in ("patch", "fix", "vendor-advisory") for t in tags):
                info.fix_commits.append(entry)
            if any(t in ("introduced", "regression") for t in tags):
                info.introduced_commits.append(entry)

        self._parse_affected(cna.get("affected", []), info)
        info.fix_commits = self._dedup(info.fix_commits)
        info.introduced_commits = self._dedup(info.introduced_commits)

        if not info.fix_commits and info.version_commit_mapping:
            for ver, cid in info.version_commit_mapping.items():
                info.fix_commits.append({
                    "commit_id": cid,
                    "url": f"https://git.kernel.org/stable/c/{cid}",
                    "tags": ["patch"],
                    "source": "mainline" if ver == info.mainline_version else "stable",
                })
        return info

    def _parse_affected(self, affected: List[Dict], info: CveInfo):
        git_commits: List[str] = []
        intro_commit: Optional[str] = None
        semvers: List[str] = []
        ml_ver = None

        for prod in affected:
            name = prod.get("product", "")
            if "linux" not in name.lower() and "kernel" not in name.lower():
                continue
            versions = prod.get("versions", [])
            has_git = any(v.get("versionType") == "git" for v in versions)
            has_sv = any(v.get("versionType") in ("semver", "original_commit_for_fix") for v in versions)

            if has_git and not git_commits:
                for v in versions:
                    if v.get("versionType") == "git":
                        ver = v.get("version", "")
                        if ver and not intro_commit:
                            intro_commit = ver
                        lt = v.get("lessThan", "")
                        if lt and lt not in git_commits:
                            git_commits.append(lt)

            if has_sv and not semvers:
                for v in versions:
                    vt = v.get("versionType", "")
                    if vt == "original_commit_for_fix":
                        ml_ver = v.get("version", "")
                        semvers.append(ml_ver)
                    elif vt == "semver" and v.get("status") == "unaffected":
                        val = v.get("version", "")
                        if val and not val.startswith("0"):
                            semvers.append(val)

        if intro_commit and not info.introduced_commits:
            info.introduced_commits.append({
                "commit_id": intro_commit,
                "url": f"https://git.kernel.org/stable/c/{intro_commit}",
                "tags": ["introduced"], "source": "affected",
            })

        info.mainline_version = ml_ver or ""

        if git_commits and semvers and len(git_commits) == len(semvers):
            for c, v in zip(git_commits, semvers):
                info.version_commit_mapping[v] = c
                if v == ml_ver:
                    info.mainline_fix_commit = c
                    self._mark_ml(info, c, v)
        elif git_commits:
            info.mainline_fix_commit = git_commits[-1]
            if ml_ver:
                info.version_commit_mapping[ml_ver] = git_commits[-1]

    def _mark_ml(self, info: CveInfo, commit: str, version: str):
        for e in info.fix_commits:
            if e["commit_id"][:12] == commit[:12]:
                e["is_mainline"] = True
                e["kernel_version"] = version
                return
        info.fix_commits.append({
            "commit_id": commit,
            "url": f"https://git.kernel.org/stable/c/{commit}",
            "tags": ["patch"], "source": "mainline",
            "is_mainline": True, "kernel_version": version,
        })

    # ─── util ────────────────────────────────────────────────────────

    _COMMIT_RE = [
        re.compile(r"/\+/([0-9a-f]{12,40})"),
        re.compile(r"/commit/\?id=([0-9a-f]{7,40})"),
        re.compile(r"/commit/([0-9a-f]{7,40})"),
        re.compile(r"[?&]id=([0-9a-f]{7,40})"),
    ]

    def _commit_from_url(self, url: str) -> Optional[str]:
        for p in self._COMMIT_RE:
            m = p.search(url)
            if m:
                return m.group(1)
        m = re.search(r"([0-9a-f]{12,40})", url)
        return m.group(1) if m else None

    @staticmethod
    def _source(url: str) -> str:
        u = url.lower()
        if "torvalds/linux" in u:
            return "mainline"
        if "/stable/" in u:
            return "stable"
        return "unknown"

    @staticmethod
    def _dedup(lst: List[Dict]) -> List[Dict]:
        seen, out = set(), []
        for c in lst:
            k = c["commit_id"][:12]
            if k not in seen:
                seen.add(k)
                out.append(c)
        return out

    @staticmethod
    def _files_from_diff(diff: str) -> List[str]:
        files = set()
        for line in diff.split("\n"):
            if line.startswith("diff --git"):
                m = re.search(r"a/(.*?)\s+b/", line)
                if m:
                    files.add(m.group(1))
            elif line.startswith("+++"):
                m = re.search(r"\+\+\+\s+b/(.+)", line)
                if m and m.group(1) != "/dev/null":
                    files.add(m.group(1))
        return sorted(files)
