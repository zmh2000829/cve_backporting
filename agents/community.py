"""
Community Agent — 社区演进分析

数据源:
  1. lore.kernel.org  (邮件列表搜索)
  2. bugzilla.kernel.org (Bug 搜索)
  3. CVE 引用链接 (从 MITRE 数据中提取)

策略: 确定性爬取 + LLM 摘要增强
"""

import logging
import re
import urllib.parse
import urllib.request
import ssl
import json
from typing import List, Optional
from html.parser import HTMLParser

from core.models import CommunityDiscussion, CveInfo
from core.llm_client import LLMClient

logger = logging.getLogger(__name__)

_TIMEOUT = 20
_SSL_CTX = ssl.create_default_context()


class _TextExtractor(HTMLParser):
    """从 HTML 中提取纯文本的简易解析器"""

    def __init__(self):
        super().__init__()
        self._pieces: List[str] = []
        self._skip = False

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip = True

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip = False

    def handle_data(self, data):
        if not self._skip:
            self._pieces.append(data)

    def get_text(self) -> str:
        return " ".join(self._pieces)


def _fetch_text(url: str) -> Optional[str]:
    """GET 请求并返回文本 (限 100KB)"""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "CVE-Backporting/2.0",
        })
        with urllib.request.urlopen(req, timeout=_TIMEOUT,
                                    context=_SSL_CTX) as resp:
            return resp.read(100_000).decode("utf-8", errors="replace")
    except Exception as e:
        logger.debug("fetch %s 失败: %s", url, e)
        return None


class CommunityAgent:
    """社区讨论收集与分析"""

    def __init__(self, llm: Optional[LLMClient] = None):
        self.llm = llm

    def analyze(self, cve_info: CveInfo) -> List[CommunityDiscussion]:
        """收集社区讨论，返回讨论列表"""
        results: List[CommunityDiscussion] = []

        results.extend(self._search_lore(cve_info))
        results.extend(self._search_bugzilla(cve_info))
        results.extend(self._extract_cve_refs(cve_info))

        if self.llm and self.llm.enabled and results:
            self._enrich_with_llm(cve_info.cve_id, results)

        logger.info("[Community] %s: 收集到 %d 条社区讨论",
                    cve_info.cve_id, len(results))
        return results

    # ── lore.kernel.org ───────────────────────────────────────────────

    def _search_lore(self, cve_info: CveInfo) -> List[CommunityDiscussion]:
        """搜索 lore.kernel.org 邮件列表"""
        results: List[CommunityDiscussion] = []

        queries = [cve_info.cve_id]
        if cve_info.mainline_fix_commit:
            queries.append(cve_info.mainline_fix_commit[:12])

        for q in queries:
            items = self._lore_query(q)
            for item in items[:5]:
                if not any(r.url == item.url for r in results):
                    results.append(item)

        return results

    def _lore_query(self, query: str) -> List[CommunityDiscussion]:
        """查询 lore.kernel.org 的 Atom feed"""
        encoded = urllib.parse.quote(query)
        url = f"https://lore.kernel.org/all/?q={encoded}&x=A"
        raw = _fetch_text(url)
        if not raw:
            return []
        return self._parse_lore_atom(raw)

    def _parse_lore_atom(self, xml_text: str) -> List[CommunityDiscussion]:
        """从 Atom XML 中提取条目 (简易正则解析，避免依赖 xml.etree)"""
        results: List[CommunityDiscussion] = []

        entries = re.findall(
            r'<entry>(.*?)</entry>', xml_text, re.DOTALL
        )
        for entry in entries[:10]:
            title_m = re.search(r'<title>(.*?)</title>', entry, re.DOTALL)
            link_m = re.search(r'<link\s+href=["\']([^"\']+)', entry)
            updated_m = re.search(r'<updated>(.*?)</updated>', entry)
            author_m = re.search(
                r'<author>\s*<name>(.*?)</name>', entry, re.DOTALL
            )
            summary_m = re.search(
                r'<content[^>]*>(.*?)</content>', entry, re.DOTALL
            )

            title = title_m.group(1).strip() if title_m else ""
            link = link_m.group(1).strip() if link_m else ""
            date = updated_m.group(1).strip()[:10] if updated_m else ""
            author = author_m.group(1).strip() if author_m else ""
            snippet = ""
            if summary_m:
                ext = _TextExtractor()
                ext.feed(summary_m.group(1))
                snippet = ext.get_text()[:500]

            if title or link:
                results.append(CommunityDiscussion(
                    source="lore",
                    url=link,
                    title=self._clean_html(title),
                    date=date,
                    author=self._clean_html(author),
                    snippet=snippet,
                    relevance="discussion",
                ))
        return results

    # ── bugzilla.kernel.org ───────────────────────────────────────────

    def _search_bugzilla(self, cve_info: CveInfo) -> List[CommunityDiscussion]:
        """搜索 bugzilla.kernel.org"""
        results: List[CommunityDiscussion] = []
        q = urllib.parse.quote(cve_info.cve_id)
        url = (f"https://bugzilla.kernel.org/buglist.cgi?"
               f"quicksearch={q}&ctype=csv&human=1")
        raw = _fetch_text(url)
        if not raw:
            return results

        lines = raw.strip().split("\n")
        if len(lines) <= 1:
            return results

        for line in lines[1:6]:
            fields = self._parse_csv_line(line)
            if len(fields) < 7:
                continue
            bug_id = fields[0].strip('"')
            summary = fields[6].strip('"') if len(fields) > 6 else ""
            bug_url = f"https://bugzilla.kernel.org/show_bug.cgi?id={bug_id}"
            results.append(CommunityDiscussion(
                source="bugzilla",
                url=bug_url,
                title=summary,
                date="",
                author="",
                snippet="",
                relevance="discussion",
            ))

        return results

    # ── CVE 引用链接 ──────────────────────────────────────────────────

    def _extract_cve_refs(self, cve_info: CveInfo) -> List[CommunityDiscussion]:
        """从 CVE 数据中提取非 git commit 的引用链接"""
        results: List[CommunityDiscussion] = []
        seen_urls = set()

        all_refs = []
        for fc in cve_info.fix_commits:
            url = fc.get("url", "")
            if url:
                all_refs.append(url)
        for ic in cve_info.introduced_commits:
            url = ic.get("url", "")
            if url:
                all_refs.append(url)

        for url in all_refs:
            if url in seen_urls:
                continue
            seen_urls.add(url)

            if "git.kernel.org" in url and "/commit/" in url:
                relevance = "direct_fix"
            elif "lore.kernel.org" in url:
                relevance = "discussion"
            else:
                relevance = "related"

            results.append(CommunityDiscussion(
                source="cve_ref",
                url=url,
                title="",
                relevance=relevance,
            ))

        return results

    # ── LLM 增强 ─────────────────────────────────────────────────────

    def _enrich_with_llm(self, cve_id: str,
                         discussions: List[CommunityDiscussion]):
        """用 LLM 为社区讨论生成摘要"""
        snippets = []
        for d in discussions[:8]:
            s = f"[{d.source}] {d.title}"
            if d.snippet:
                s += f": {d.snippet[:200]}"
            snippets.append(s)

        prompt = (
            f"以下是 {cve_id} 相关的社区讨论条目，请用中文为每条生成一句话摘要，"
            f"并判断其与该 CVE 的关联程度 (direct_fix/discussion/related)。\n\n"
            + "\n".join(f"{i+1}. {s}" for i, s in enumerate(snippets))
            + "\n\n请用 JSON 数组格式回复: "
            '[{"index": 1, "summary": "...", "relevance": "..."}, ...]'
        )

        resp = self.llm.chat_json(prompt, system="你是 Linux 内核安全专家。")
        if resp and isinstance(resp, list):
            for item in resp:
                idx = item.get("index", 0) - 1
                if 0 <= idx < len(discussions):
                    if item.get("summary"):
                        discussions[idx].snippet = item["summary"]
                    if item.get("relevance"):
                        discussions[idx].relevance = item["relevance"]

    # ── 工具方法 ──────────────────────────────────────────────────────

    @staticmethod
    def _clean_html(text: str) -> str:
        return re.sub(r'<[^>]+>', '', text).strip()

    @staticmethod
    def _parse_csv_line(line: str) -> List[str]:
        """简易 CSV 行解析 (处理引号内逗号)"""
        fields: List[str] = []
        current = ""
        in_quote = False
        for ch in line:
            if ch == '"':
                in_quote = not in_quote
                current += ch
            elif ch == ',' and not in_quote:
                fields.append(current)
                current = ""
            else:
                current += ch
        fields.append(current)
        return fields
