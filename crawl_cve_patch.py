#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE补丁信息获取模块
从MITRE CVE API和kernel.googlesource.com获取CVE相关的commit信息
"""

import requests
import re
import json
import base64
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# 安全地禁用 HTTPS 证书验证警告（内网环境常见）
try:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pass


@dataclass
class CveInfo:
    """CVE漏洞信息"""
    cve_id: str
    description: str = ""
    severity: str = "unknown"
    introduced_commits: List[Dict] = field(default_factory=list)
    fix_commits: List[Dict] = field(default_factory=list)
    mainline_fix_commit: str = ""
    mainline_version: str = ""
    version_commit_mapping: Dict[str, str] = field(default_factory=dict)

    @property
    def introduced_commit_id(self) -> Optional[str]:
        return self.introduced_commits[0]["commit_id"] if self.introduced_commits else None

    @property
    def fix_commit_id(self) -> Optional[str]:
        return self.mainline_fix_commit or (
            self.fix_commits[0]["commit_id"] if self.fix_commits else None
        )


@dataclass
class PatchInfo:
    """补丁内容"""
    commit_id: str
    subject: str = ""
    commit_msg: str = ""
    author: str = ""
    date: str = ""
    diff_code: str = ""
    modified_files: List[str] = field(default_factory=list)


class CveFetcher:
    """
    CVE补丁信息获取器
    从MITRE CVE API获取漏洞元数据，从kernel.googlesource.com获取patch内容
    """

    MITRE_API = "https://cveawg.mitre.org/api/cve/"
    KERNEL_GIT = "https://kernel.googlesource.com/pub/scm/linux/kernel/git/stable/linux"

    def __init__(self, api_timeout: int = 30):
        self.api_timeout = api_timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "CVE-Backporting-Tool/2.0",
            "Accept": "application/json",
        })

    # ─── 公开 API ────────────────────────────────────────────────────

    def fetch_cve(self, cve_id: str) -> Optional[CveInfo]:
        """获取CVE的完整信息：引入commit、修复commit、版本映射"""
        logger.info("获取 %s 的信息...", cve_id)

        raw = self._fetch_mitre_json(cve_id)
        if not raw:
            return None

        info = self._parse_cve_data(raw, cve_id)
        logger.info(
            "%s: mainline=%s (%s), %d个fix commits, %d个introduced commits",
            cve_id,
            info.mainline_fix_commit[:12] if info.mainline_fix_commit else "N/A",
            info.mainline_version or "N/A",
            len(info.fix_commits),
            len(info.introduced_commits),
        )
        return info

    def fetch_patch(self, commit_id: str) -> Optional[PatchInfo]:
        """
        从kernel.googlesource.com获取patch内容
        使用JSON格式获取commit元数据，TEXT格式获取diff
        """
        logger.info("获取 patch %s ...", commit_id[:12])
        patch = PatchInfo(commit_id=commit_id)

        # 1. 获取commit元数据（JSON格式）
        try:
            meta_url = f"{self.KERNEL_GIT}/+/{commit_id}?format=JSON"
            resp = self.session.get(meta_url, timeout=self.api_timeout, verify=False)
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

                # tree_diff 中有文件列表
                for td in data.get("tree_diff", []):
                    old_path = td.get("old_path", "")
                    new_path = td.get("new_path", "")
                    if new_path and new_path != "/dev/null":
                        patch.modified_files.append(new_path)
                    elif old_path and old_path != "/dev/null":
                        patch.modified_files.append(old_path)
        except Exception as e:
            logger.debug("获取commit元数据异常: %s", e)

        # 2. 获取diff（TEXT格式，base64编码）
        try:
            diff_url = f"{self.KERNEL_GIT}/+/{commit_id}%5E%21?format=TEXT"
            resp = self.session.get(diff_url, timeout=self.api_timeout, verify=False)
            if resp.status_code == 200:
                patch.diff_code = base64.b64decode(resp.text).decode("utf-8", errors="replace")
                if not patch.modified_files:
                    patch.modified_files = self._extract_files_from_diff(patch.diff_code)
        except Exception as e:
            logger.debug("获取diff异常: %s", e)

        if patch.subject or patch.diff_code:
            logger.info(
                "Patch %s: subject=%s, %d files",
                commit_id[:12],
                patch.subject[:60] if patch.subject else "N/A",
                len(patch.modified_files),
            )
            return patch

        logger.warning("获取patch失败: %s", commit_id[:12])
        return None

    # ─── MITRE API ───────────────────────────────────────────────────

    def _fetch_mitre_json(self, cve_id: str) -> Optional[Dict]:
        url = f"{self.MITRE_API}{cve_id}"
        try:
            resp = self.session.get(url, timeout=self.api_timeout, verify=False)
            if resp.status_code == 404:
                logger.warning("CVE不存在: %s", cve_id)
                return None
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            logger.error("MITRE API请求失败: %s", e)
            return None

    # ─── CVE 数据解析 ────────────────────────────────────────────────

    def _parse_cve_data(self, raw: Dict, cve_id: str) -> CveInfo:
        info = CveInfo(cve_id=cve_id)
        cna = raw.get("containers", {}).get("cna", {})

        # 描述
        descs = cna.get("descriptions", [])
        if descs:
            info.description = descs[0].get("value", "")

        # 严重程度
        for metric in cna.get("metrics", []):
            if "cvssV3_1" in metric:
                info.severity = metric["cvssV3_1"].get("baseSeverity", "unknown")
                break

        # references 提取 commit
        for ref in cna.get("references", []):
            url = ref.get("url", "")
            tags = ref.get("tags", [])
            commit_id = self._extract_commit_from_url(url)
            if not commit_id:
                continue

            entry = {
                "commit_id": commit_id,
                "url": url,
                "tags": tags,
                "source": self._identify_source(url),
            }

            if any(t in ("patch", "fix", "vendor-advisory") for t in tags):
                info.fix_commits.append(entry)
            if any(t in ("introduced", "regression") for t in tags):
                info.introduced_commits.append(entry)

        # affected 字段：提取 git commit <-> semver version 映射
        self._parse_affected(cna.get("affected", []), info)

        # 去重
        info.fix_commits = self._dedup(info.fix_commits)
        info.introduced_commits = self._dedup(info.introduced_commits)

        # 如果 references 里没拿到 fix，从 affected 的 git commit 补充
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
        """从 affected 数组中提取 git commit 与 semver 版本的映射"""
        git_commits: List[str] = []
        introduced_commit: Optional[str] = None
        semver_versions: List[str] = []
        mainline_version = None

        for product in affected:
            name = product.get("product", "")
            if "linux" not in name.lower() and "kernel" not in name.lower():
                continue

            versions = product.get("versions", [])
            has_git = any(v.get("versionType") == "git" for v in versions)
            has_semver = any(
                v.get("versionType") in ("semver", "original_commit_for_fix")
                for v in versions
            )

            if has_git and not git_commits:
                for v in versions:
                    if v.get("versionType") == "git":
                        # version字段是引入commit，lessThan是修复commit
                        intro = v.get("version", "")
                        if intro and not introduced_commit:
                            introduced_commit = intro
                        lt = v.get("lessThan", "")
                        if lt and lt not in git_commits:
                            git_commits.append(lt)

            if has_semver and not semver_versions:
                for v in versions:
                    vtype = v.get("versionType", "")
                    if vtype == "original_commit_for_fix":
                        mainline_version = v.get("version", "")
                        semver_versions.append(mainline_version)
                    elif vtype == "semver" and v.get("status") == "unaffected":
                        val = v.get("version", "")
                        if val and not val.startswith("0"):
                            semver_versions.append(val)

        # 设置引入commit
        if introduced_commit and not info.introduced_commits:
            info.introduced_commits.append({
                "commit_id": introduced_commit,
                "url": f"https://git.kernel.org/stable/c/{introduced_commit}",
                "tags": ["introduced"],
                "source": "affected",
            })

        info.mainline_version = mainline_version or ""

        # 建立映射
        if git_commits and semver_versions and len(git_commits) == len(semver_versions):
            for commit, version in zip(git_commits, semver_versions):
                info.version_commit_mapping[version] = commit
                if version == mainline_version:
                    info.mainline_fix_commit = commit
                    self._mark_mainline(info, commit, version)
        elif git_commits:
            # 数量不匹配时，最后一个通常是 mainline
            info.mainline_fix_commit = git_commits[-1]
            if mainline_version:
                info.version_commit_mapping[mainline_version] = git_commits[-1]

    def _mark_mainline(self, info: CveInfo, commit: str, version: str):
        """在 fix_commits 列表中标记 mainline commit"""
        for entry in info.fix_commits:
            if entry["commit_id"][:12] == commit[:12]:
                entry["is_mainline"] = True
                entry["kernel_version"] = version
                return
        info.fix_commits.append({
            "commit_id": commit,
            "url": f"https://git.kernel.org/stable/c/{commit}",
            "tags": ["patch"],
            "source": "mainline",
            "is_mainline": True,
            "kernel_version": version,
        })

    # ─── URL / commit 工具方法 ──────────────────────────────────────

    _COMMIT_PATTERNS = [
        re.compile(r"/\+/([0-9a-f]{12,40})"),           # googlesource
        re.compile(r"/commit/\?id=([0-9a-f]{7,40})"),   # cgit ?id=
        re.compile(r"/commit/([0-9a-f]{7,40})"),         # cgit /commit/
        re.compile(r"[?&]id=([0-9a-f]{7,40})"),          # query param
    ]

    def _extract_commit_from_url(self, url: str) -> Optional[str]:
        if not url:
            return None
        for pat in self._COMMIT_PATTERNS:
            m = pat.search(url)
            if m:
                return m.group(1)
        # 兜底: 提取长hex串
        m = re.search(r"([0-9a-f]{12,40})", url)
        return m.group(1) if m else None

    @staticmethod
    def _identify_source(url: str) -> str:
        u = url.lower()
        if "torvalds/linux" in u:
            return "mainline"
        if "/stable/" in u:
            return "stable"
        if "github.com" in u:
            return "github"
        if "googlesource.com" in u:
            return "googlesource"
        return "unknown"

    @staticmethod
    def _dedup(commits: List[Dict]) -> List[Dict]:
        seen, result = set(), []
        for c in commits:
            key = c["commit_id"][:12]
            if key not in seen:
                seen.add(key)
                result.append(c)
        return result

    # ─── Patch 文本解析 ──────────────────────────────────────────────

    def _parse_patch_text(self, text: str, commit_id: str) -> PatchInfo:
        """解析 git format-patch 风格的文本"""
        patch = PatchInfo(commit_id=commit_id)
        lines = text.split("\n")
        diff_start = -1

        msg_lines = []
        in_header = True
        header_done = False

        for i, line in enumerate(lines):
            if line.startswith("diff --git"):
                diff_start = i
                break

            if in_header:
                if line.startswith("From:"):
                    patch.author = line[5:].strip()
                elif line.startswith("Date:"):
                    patch.date = line[5:].strip()
                elif line.startswith("Subject:"):
                    subj = line[8:].strip()
                    subj = re.sub(r"^\[PATCH[^\]]*\]\s*", "", subj)
                    patch.subject = subj
                    header_done = True
                elif header_done and line.strip() == "":
                    in_header = False
            else:
                if line.startswith("---") and not line.startswith("---\n"):
                    # "---" 分隔 commit msg 和 diffstat
                    break
                msg_lines.append(line)

        patch.commit_msg = "\n".join(msg_lines).strip()

        if diff_start >= 0:
            patch.diff_code = "\n".join(lines[diff_start:])
            patch.modified_files = self._extract_files_from_diff(patch.diff_code)

        if not patch.subject and patch.commit_msg:
            patch.subject = patch.commit_msg.split("\n")[0]

        logger.info(
            "Patch %s: subject=%s, %d files",
            commit_id[:12],
            patch.subject[:60] if patch.subject else "N/A",
            len(patch.modified_files),
        )
        return patch

    @staticmethod
    def _extract_files_from_diff(diff: str) -> List[str]:
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


# ─── 向后兼容别名 ────────────────────────────────────────────────────
Crawl_Cve_Patch = CveFetcher


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    fetcher = CveFetcher()
    cve = fetcher.fetch_cve("CVE-2024-26633")
    if cve:
        print(f"CVE: {cve.cve_id}")
        print(f"Mainline fix: {cve.mainline_fix_commit[:12]}")
        print(f"Version map: {cve.version_commit_mapping}")
        if cve.fix_commit_id:
            patch = fetcher.fetch_patch(cve.fix_commit_id)
            if patch:
                print(f"Subject: {patch.subject}")
                print(f"Files: {patch.modified_files}")
