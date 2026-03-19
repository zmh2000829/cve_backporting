"""
Crawler Agent
负责从外部数据源获取CVE漏洞信息和补丁内容：
  - MITRE CVE API (cveawg.mitre.org)
  - git.kernel.org (主要补丁源，format-patch 格式)
  - kernel.googlesource.com (备选)
"""

import re
import json
import time
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
    KERNEL_ORG_STABLE = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
    KERNEL_ORG_TORVALDS = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
    GOOGLESOURCE = "https://kernel.googlesource.com/pub/scm/linux/kernel/git/stable/linux"

    _PATCH_RETRIES = 3
    _REMOTE_TIMEOUT = 30

    def __init__(self, api_timeout: int = 30, git_mgr=None):
        self.api_timeout = api_timeout
        self.git_mgr = git_mgr
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

    def fetch_patch(self, commit_id: str, target_version: str = None,
                    local_first: bool = False) -> Optional[PatchInfo]:
        """
        获取补丁元数据+diff。
        local_first=False (默认): kernel.org > googlesource > 本地
        local_first=True:  本地 > kernel.org > googlesource
            适用于 batch-validate 等场景，commit 大概率已在本地对象库中，
            跳过网络请求可节省数十秒/个。
        """
        logger.info("[Crawler] 获取 patch %s (local_first=%s) ...",
                    commit_id[:12], local_first)

        if local_first and self.git_mgr and target_version:
            patch_local = self._fetch_patch_local(commit_id, target_version)
            if patch_local and patch_local.subject and patch_local.diff_code:
                logger.info("[Crawler] 本地仓库命中: %s", commit_id[:12])
                return patch_local

        patch = self._fetch_from_kernel_org(commit_id)
        if patch and patch.subject and patch.diff_code:
            return patch

        patch_gs = self._fetch_from_googlesource(commit_id)
        if patch_gs and patch_gs.subject and patch_gs.diff_code:
            return patch_gs
        if patch_gs:
            patch = self._merge_patch(patch, patch_gs)
        if patch and patch.subject and patch.diff_code:
            return patch

        if self.git_mgr and target_version and not local_first:
            logger.info("[Crawler] 远程不可用, 回退到本地仓库")
            patch_local = self._fetch_patch_local(commit_id, target_version)
            if patch_local:
                return self._merge_patch(patch, patch_local) if patch else patch_local

        if patch and (patch.subject or patch.diff_code):
            return patch
        logger.warning("[Crawler] patch获取失败: %s", commit_id[:12])
        return None

    @staticmethod
    def _merge_patch(base: Optional[PatchInfo], extra: Optional[PatchInfo]) -> Optional[PatchInfo]:
        """合并两个不完整的 PatchInfo，取各自非空字段"""
        if not base:
            return extra
        if not extra:
            return base
        if not base.subject and extra.subject:
            base.subject = extra.subject
        if not base.author and extra.author:
            base.author = extra.author
        if not base.commit_msg and extra.commit_msg:
            base.commit_msg = extra.commit_msg
        if not base.diff_code and extra.diff_code:
            base.diff_code = extra.diff_code
        if not base.modified_files and extra.modified_files:
            base.modified_files = extra.modified_files
        if not base.date and extra.date:
            base.date = extra.date
        return base

    # ─── git.kernel.org (format-patch, 单请求获取全部信息) ────────────

    def _fetch_from_kernel_org(self, commit_id: str) -> Optional[PatchInfo]:
        """
        从 git.kernel.org 获取 format-patch 输出。
        单次请求同时包含 subject / author / date / commit message / diff。
        """
        trees = [
            ("stable", self.KERNEL_ORG_STABLE),
            ("torvalds", self.KERNEL_ORG_TORVALDS),
        ]
        for tree_name, tree_url in trees:
            url = f"{tree_url}/patch/?id={commit_id}"
            for attempt in range(1, self._PATCH_RETRIES + 1):
                try:
                    resp = self.session.get(url, timeout=self._REMOTE_TIMEOUT, verify=True)
                    if resp.status_code == 200 and len(resp.text) > 50:
                        patch = self._parse_format_patch(commit_id, resp.text)
                        if patch:
                            logger.info("[Crawler] git.kernel.org/%s 获取成功: %s",
                                        tree_name, commit_id[:12])
                            return patch
                    elif resp.status_code >= 500:
                        logger.debug("[Crawler] kernel.org/%s %d/%d: HTTP %d",
                                     tree_name, attempt, self._PATCH_RETRIES, resp.status_code)
                    else:
                        break
                except requests.Timeout:
                    logger.debug("[Crawler] kernel.org/%s %d/%d: timeout",
                                 tree_name, attempt, self._PATCH_RETRIES)
                except Exception as e:
                    logger.debug("[Crawler] kernel.org/%s 异常: %s", tree_name, e)
                    break
                if attempt < self._PATCH_RETRIES:
                    time.sleep(attempt)
        return None

    def _parse_format_patch(self, commit_id: str, text: str) -> Optional[PatchInfo]:
        """解析 git format-patch 输出"""
        patch = PatchInfo(commit_id=commit_id)
        lines = text.split("\n")
        idx = 0
        total = len(lines)

        while idx < total:
            line = lines[idx]
            if line.startswith("From:"):
                patch.author = line[5:].strip()
            elif line.startswith("Date:"):
                patch.date = line[5:].strip()
            elif line.startswith("Subject:"):
                subj_parts = [line[8:].strip()]
                idx += 1
                while idx < total and lines[idx].startswith(" "):
                    subj_parts.append(lines[idx].strip())
                    idx += 1
                patch.subject = " ".join(subj_parts)
                if patch.subject.startswith("[PATCH]"):
                    patch.subject = patch.subject[7:].strip()
                continue
            elif line == "---":
                diff_start = idx + 1
                while diff_start < total and not lines[diff_start].startswith("diff --git"):
                    diff_start += 1
                patch.diff_code = "\n".join(lines[diff_start:]).rstrip()
                msg_start = 0
                for j in range(total):
                    if lines[j] == "" and j > 0:
                        msg_start = j + 1
                        break
                if msg_start and msg_start < idx:
                    patch.commit_msg = "\n".join(lines[msg_start:idx]).strip()
                break
            idx += 1

        if patch.diff_code:
            patch.modified_files = self._files_from_diff(patch.diff_code)

        from_line = lines[0] if lines else ""
        m = re.match(r"From\s+([0-9a-f]{40})", from_line)
        if m:
            patch.commit_id = m.group(1)

        return patch if (patch.subject or patch.diff_code) else None

    # ─── googlesource.com (JSON + TEXT, 备选) ────────────────────────

    def _fetch_from_googlesource(self, commit_id: str) -> Optional[PatchInfo]:
        """从 kernel.googlesource.com 获取 (含重试)"""
        patch = PatchInfo(commit_id=commit_id)

        json_url = f"{self.GOOGLESOURCE}/+/{commit_id}?format=JSON"
        diff_url = f"{self.GOOGLESOURCE}/+/{commit_id}%5E%21?format=TEXT"

        for attempt in range(1, self._PATCH_RETRIES + 1):
            if not patch.subject:
                try:
                    resp = self.session.get(json_url, timeout=self._REMOTE_TIMEOUT, verify=False)
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
                    elif resp.status_code < 500:
                        break
                except requests.Timeout:
                    pass
                except Exception:
                    pass

            if not patch.diff_code:
                try:
                    resp = self.session.get(diff_url, timeout=self._REMOTE_TIMEOUT, verify=False)
                    if resp.status_code == 200:
                        patch.diff_code = base64.b64decode(resp.text).decode("utf-8", errors="replace")
                        if not patch.modified_files:
                            patch.modified_files = self._files_from_diff(patch.diff_code)
                    elif resp.status_code < 500:
                        break
                except requests.Timeout:
                    pass
                except Exception:
                    pass

            if patch.subject and patch.diff_code:
                break
            if attempt < self._PATCH_RETRIES:
                time.sleep(attempt)

        return patch if (patch.subject or patch.diff_code) else None

    def _fetch_patch_local(self, commit_id: str, target_version: str) -> Optional[PatchInfo]:
        """从本地 git 仓库获取 commit 信息 (commit 可能在对象库中但不在目标分支上)"""
        import subprocess
        rp = self.git_mgr._get_repo_path(target_version)
        if not rp:
            return None

        patch = PatchInfo(commit_id=commit_id)
        try:
            # 检查 commit 是否在对象库中
            chk = subprocess.run(["git", "cat-file", "-t", commit_id],
                                 cwd=rp, capture_output=True, text=True, timeout=10)
            if chk.returncode != 0:
                return None

            # 获取 commit 元信息
            fmt = "%H%n%s%n%an <%ae>%n%B"
            meta = subprocess.run(["git", "log", "-1", f"--format={fmt}", commit_id],
                                  cwd=rp, capture_output=True, text=True, timeout=30)
            if meta.returncode == 0 and meta.stdout.strip():
                lines = meta.stdout.strip().split("\n")
                if len(lines) >= 3:
                    patch.commit_id = lines[0]
                    patch.subject = lines[1]
                    patch.author = lines[2]
                    patch.commit_msg = "\n".join(lines[3:]) if len(lines) > 3 else ""

            # 获取 diff
            diff = subprocess.run(["git", "show", "--format=", commit_id],
                                  cwd=rp, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=30)
            if diff.returncode == 0 and diff.stdout.strip():
                patch.diff_code = diff.stdout
                patch.modified_files = self._files_from_diff(patch.diff_code)

            # 获取修改文件列表 (如果 diff 提取失败)
            if not patch.modified_files:
                files_out = subprocess.run(["git", "show", "--name-only", "--format=", commit_id],
                                           cwd=rp, capture_output=True, text=True, timeout=10)
                if files_out.returncode == 0:
                    patch.modified_files = [f.strip() for f in files_out.stdout.strip().split("\n") if f.strip()]

        except Exception as e:
            logger.debug("[Crawler] 本地git获取异常: %s", e)
            return None

        if patch.subject or patch.diff_code:
            logger.info("[Crawler] 本地获取成功: %s (%s)", commit_id[:12], patch.subject[:40])
            return patch
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
