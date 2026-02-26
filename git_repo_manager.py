#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Git仓库管理器
高效操作目标kernel仓库：commit搜索、缓存构建、分支感知查询
针对千万级commit仓库做了专门优化
"""

import subprocess
import re
import os
import logging
import sqlite3
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

FIELD_SEP = "\x1e"   # ASCII Record Separator - 字段分隔
RECORD_SEP = "\x1f"  # ASCII Unit Separator - 记录分隔


@dataclass
class GitCommit:
    """Git commit数据结构"""
    commit_id: str
    subject: str
    commit_msg: str = ""
    author: str = ""
    timestamp: int = 0
    diff_code: str = ""
    modified_files: List[str] = field(default_factory=list)


class GitRepoManager:
    """
    Git仓库管理器
    支持多仓库配置，SQLite缓存加速，千万级commit高效搜索
    """

    def __init__(self, repo_configs: Dict[str, Dict[str, str]], use_cache: bool = True,
                 cache_db_path: str = "commit_cache.db"):
        """
        Args:
            repo_configs: {"5.10-hulk": {"path": "/path/to/repo", "branch": "linux-5.10.y"}}
            use_cache: 是否使用SQLite缓存
            cache_db_path: 缓存数据库路径
        """
        self.repo_configs = repo_configs
        self.use_cache = use_cache
        self.cache_db_path = cache_db_path

        if use_cache:
            self._init_cache_db()

    # ─── 仓库配置 ────────────────────────────────────────────────────

    def _get_repo_path(self, repo_version: str) -> Optional[str]:
        cfg = self.repo_configs.get(repo_version)
        if isinstance(cfg, dict):
            return cfg.get("path")
        return cfg if isinstance(cfg, str) else None

    def _get_repo_branch(self, repo_version: str) -> Optional[str]:
        cfg = self.repo_configs.get(repo_version)
        return cfg.get("branch") if isinstance(cfg, dict) else None

    # ─── Git命令执行 ─────────────────────────────────────────────────

    def run_git(self, cmd: List[str], repo_version: str,
                timeout: int = 600) -> Optional[str]:
        """在指定仓库执行git命令，返回stdout"""
        repo_path = self._get_repo_path(repo_version)
        if not repo_path:
            raise ValueError(f"未配置仓库: {repo_version}")
        if not os.path.exists(repo_path):
            raise FileNotFoundError(f"仓库路径不存在: {repo_path}")

        try:
            result = subprocess.run(
                cmd, cwd=repo_path,
                capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=timeout,
            )
            if result.returncode != 0:
                logger.debug("Git命令失败: %s\nstderr: %s", " ".join(cmd), result.stderr.strip())
                return None
            return result.stdout
        except subprocess.TimeoutExpired:
            logger.error("Git命令超时(%ds): %s", timeout, " ".join(cmd[:5]))
            return None
        except Exception as e:
            logger.error("Git命令异常: %s", e)
            return None

    # ─── Commit 查找 (Level 1: ID Match) ────────────────────────────

    def find_commit_by_id(self, commit_id: str, repo_version: str) -> Optional[Dict]:
        """
        通过commit ID查找（先查缓存，再查git）
        使用 git merge-base --is-ancestor 代替 git branch --contains（快几个数量级）
        """
        short_id = commit_id[:12]

        # 1. 查缓存
        if self.use_cache:
            cached = self._cache_lookup_by_id(short_id, repo_version)
            if cached:
                return cached

        # 2. 检查commit是否存在
        check = self.run_git(["git", "cat-file", "-t", commit_id], repo_version, timeout=10)
        if not check or check.strip() != "commit":
            return None

        # 3. 检查commit是否在目标分支上
        branch = self._get_repo_branch(repo_version)
        if branch:
            if not self._is_ancestor(commit_id, branch, repo_version):
                return None

        # 4. 获取详细信息
        fmt = f"%H{FIELD_SEP}%s{FIELD_SEP}%an{FIELD_SEP}%at"
        output = self.run_git(
            ["git", "log", "-1", f"--format={fmt}", commit_id],
            repo_version, timeout=30,
        )
        if not output:
            return None

        parts = output.strip().split(FIELD_SEP)
        if len(parts) < 4:
            return None

        result = {
            "commit_id": parts[0],
            "subject": parts[1],
            "author": parts[2],
            "timestamp": int(parts[3]) if parts[3].isdigit() else 0,
        }

        if self.use_cache:
            self._cache_commit(repo_version, result)

        return result

    def _is_ancestor(self, commit_id: str, branch: str, repo_version: str) -> bool:
        """检查commit是否是branch的祖先（即commit在branch上）"""
        repo_path = self._get_repo_path(repo_version)
        if not repo_path:
            return False
        try:
            result = subprocess.run(
                ["git", "merge-base", "--is-ancestor", commit_id, branch],
                cwd=repo_path, capture_output=True, timeout=30,
            )
            return result.returncode == 0
        except Exception:
            return False

    # ─── Commit 搜索 (Level 2: Subject / Keyword) ───────────────────

    def search_by_subject(self, subject: str, repo_version: str,
                          limit: int = 20) -> List[GitCommit]:
        """精确搜索commit subject（使用--fixed-strings）"""
        # 先查缓存
        if self.use_cache:
            cached = self._cache_search_subject(subject, repo_version, limit)
            if cached:
                return cached

        branch = self._get_repo_branch(repo_version)
        cmd = ["git", "log"]
        if branch:
            cmd.append(branch)
        cmd.extend([
            f"--grep={subject}", "--fixed-strings", "-i",
            f"--max-count={limit}",
            f"--format=%H{FIELD_SEP}%s{FIELD_SEP}%an{FIELD_SEP}%at{RECORD_SEP}",
        ])

        return self._parse_log_output(self.run_git(cmd, repo_version))

    def search_by_keywords(self, keywords: List[str], repo_version: str,
                           limit: int = 50) -> List[GitCommit]:
        """通过关键词搜索commits（OR模式，使用--extended-regexp）"""
        # 先查缓存 FTS
        if self.use_cache:
            cached = self._cache_fts_search(keywords, repo_version, limit)
            if cached:
                return cached

        branch = self._get_repo_branch(repo_version)
        pattern = "|".join(re.escape(k) for k in keywords)
        cmd = ["git", "log"]
        if branch:
            cmd.append(branch)
        cmd.extend([
            f"--grep={pattern}", "--extended-regexp", "-i",
            f"--max-count={limit}",
            f"--format=%H{FIELD_SEP}%s{FIELD_SEP}%an{FIELD_SEP}%at{RECORD_SEP}",
        ])

        return self._parse_log_output(self.run_git(cmd, repo_version))

    def search_by_files(self, file_paths: List[str], repo_version: str,
                        limit: int = 100) -> List[GitCommit]:
        """搜索修改了指定文件的commits"""
        branch = self._get_repo_branch(repo_version)
        cmd = ["git", "log"]
        if branch:
            cmd.append(branch)
        cmd.extend([
            f"--max-count={limit}",
            f"--format=%H{FIELD_SEP}%s{FIELD_SEP}%an{FIELD_SEP}%at{RECORD_SEP}",
            "--",
        ])
        cmd.extend(file_paths)

        return self._parse_log_output(self.run_git(cmd, repo_version))

    # ─── Commit Diff 获取 ───────────────────────────────────────────

    def get_commit_diff(self, commit_id: str, repo_version: str) -> Optional[str]:
        return self.run_git(["git", "show", "--format=", commit_id], repo_version)

    def get_commit_files(self, commit_id: str, repo_version: str) -> List[str]:
        output = self.run_git(
            ["git", "show", "--name-only", "--format=", commit_id], repo_version
        )
        if not output:
            return []
        return [l.strip() for l in output.strip().split("\n") if l.strip()]

    def get_file_log(self, file_paths: List[str], repo_version: str,
                     since_commit: str = None, limit: int = 50) -> List[GitCommit]:
        """获取指定文件在某个commit之后的修改历史（用于依赖分析）"""
        branch = self._get_repo_branch(repo_version)
        cmd = ["git", "log"]
        if branch:
            cmd.append(branch)
        if since_commit:
            cmd.append(f"{since_commit}..HEAD")
        cmd.extend([
            f"--max-count={limit}",
            f"--format=%H{FIELD_SEP}%s{FIELD_SEP}%an{FIELD_SEP}%at{RECORD_SEP}",
            "--",
        ])
        cmd.extend(file_paths)

        return self._parse_log_output(self.run_git(cmd, repo_version))

    # ─── 日志解析 ────────────────────────────────────────────────────

    def _parse_log_output(self, output: Optional[str]) -> List[GitCommit]:
        if not output:
            return []
        results = []
        for record in output.strip().split(RECORD_SEP):
            record = record.strip()
            if not record:
                continue
            parts = record.split(FIELD_SEP)
            if len(parts) >= 4:
                results.append(GitCommit(
                    commit_id=parts[0].strip(),
                    subject=parts[1].strip(),
                    author=parts[2].strip(),
                    timestamp=int(parts[3].strip()) if parts[3].strip().isdigit() else 0,
                ))
        return results

    # ─── SQLite 缓存 ────────────────────────────────────────────────

    def _init_cache_db(self):
        conn = sqlite3.connect(self.cache_db_path)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS commits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_version TEXT NOT NULL,
                commit_id TEXT NOT NULL,
                short_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                author TEXT,
                timestamp INTEGER,
                UNIQUE(repo_version, commit_id)
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_short_id ON commits(repo_version, short_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_subject ON commits(repo_version, subject)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON commits(repo_version, timestamp)")

        try:
            c.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS commits_fts
                USING fts5(commit_id, subject, content='commits', content_rowid='id')
            """)
            c.execute("""
                CREATE TRIGGER IF NOT EXISTS commits_ai AFTER INSERT ON commits BEGIN
                    INSERT INTO commits_fts(rowid, commit_id, subject)
                    VALUES (new.id, new.commit_id, new.subject);
                END
            """)
        except sqlite3.OperationalError:
            logger.warning("SQLite不支持FTS5，全文搜索功能受限")

        conn.commit()
        conn.close()

    def _cache_lookup_by_id(self, short_id: str, repo_version: str) -> Optional[Dict]:
        try:
            conn = sqlite3.connect(self.cache_db_path)
            c = conn.cursor()
            c.execute(
                "SELECT commit_id, subject, author, timestamp FROM commits "
                "WHERE repo_version = ? AND short_id = ? LIMIT 1",
                (repo_version, short_id),
            )
            row = c.fetchone()
            conn.close()
            if row:
                return {"commit_id": row[0], "subject": row[1], "author": row[2], "timestamp": row[3]}
        except Exception:
            pass
        return None

    def _cache_search_subject(self, subject: str, repo_version: str,
                              limit: int) -> List[GitCommit]:
        try:
            conn = sqlite3.connect(self.cache_db_path)
            c = conn.cursor()
            c.execute(
                "SELECT commit_id, subject, author, timestamp FROM commits "
                "WHERE repo_version = ? AND subject = ? LIMIT ?",
                (repo_version, subject, limit),
            )
            rows = c.fetchall()
            conn.close()
            return [GitCommit(commit_id=r[0], subject=r[1], author=r[2], timestamp=r[3]) for r in rows]
        except Exception:
            return []

    def _cache_fts_search(self, keywords: List[str], repo_version: str,
                          limit: int) -> List[GitCommit]:
        try:
            conn = sqlite3.connect(self.cache_db_path)
            c = conn.cursor()
            query = " AND ".join(keywords)
            c.execute(
                "SELECT c.commit_id, c.subject, c.author, c.timestamp "
                "FROM commits c JOIN commits_fts f ON c.id = f.rowid "
                "WHERE f MATCH ? AND c.repo_version = ? LIMIT ?",
                (query, repo_version, limit),
            )
            rows = c.fetchall()
            conn.close()
            if rows:
                return [GitCommit(commit_id=r[0], subject=r[1], author=r[2], timestamp=r[3]) for r in rows]
        except sqlite3.OperationalError:
            pass
        return []

    def _cache_commit(self, repo_version: str, info: Dict):
        if not self.use_cache:
            return
        try:
            conn = sqlite3.connect(self.cache_db_path)
            conn.execute(
                "INSERT OR IGNORE INTO commits (repo_version, commit_id, short_id, subject, author, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (repo_version, info["commit_id"], info["commit_id"][:12],
                 info.get("subject", ""), info.get("author", ""), info.get("timestamp", 0)),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.debug("缓存commit失败: %s", e)

    def get_cache_count(self, repo_version: str = None) -> int:
        """获取缓存的commit数量"""
        try:
            conn = sqlite3.connect(self.cache_db_path)
            c = conn.cursor()
            if repo_version:
                c.execute("SELECT COUNT(*) FROM commits WHERE repo_version = ?", (repo_version,))
            else:
                c.execute("SELECT COUNT(*) FROM commits")
            count = c.fetchone()[0]
            conn.close()
            return count
        except Exception:
            return 0

    # ─── 缓存构建（支持千万级commit） ──────────────────────────────

    def build_commit_cache(self, repo_version: str, max_commits: int = None):
        """
        批量构建commit缓存
        Args:
            repo_version: 仓库版本名称
            max_commits: 最大数量，None表示全部
        """
        branch = self._get_repo_branch(repo_version)
        desc = f"(分支: {branch})" if branch else "(当前分支)"
        count_desc = str(max_commits) if max_commits else "全部"
        logger.info("开始构建 %s 的commit缓存 %s, 数量: %s", repo_version, desc, count_desc)

        cmd = ["git", "log"]
        if branch:
            cmd.append(branch)
        if max_commits and max_commits > 0:
            cmd.append(f"--max-count={max_commits}")

        fmt = f"%H{FIELD_SEP}%s{FIELD_SEP}%an{FIELD_SEP}%at{RECORD_SEP}"
        cmd.append(f"--format={fmt}")

        timeout = 1800 if not max_commits else 600
        if not max_commits:
            logger.info("正在获取所有commits，可能需要几分钟...")

        output = self.run_git(cmd, repo_version, timeout=timeout)
        if not output:
            logger.error("获取commits失败")
            return

        records = output.strip().split(RECORD_SEP)
        logger.info("解析 %d 个commit记录...", len(records))

        commits_data = []
        for i, record in enumerate(records):
            record = record.strip()
            if not record:
                continue
            parts = record.split(FIELD_SEP)
            if len(parts) >= 4:
                commits_data.append((
                    repo_version,
                    parts[0].strip(),
                    parts[0].strip()[:12],
                    parts[1].strip(),
                    parts[2].strip(),
                    int(parts[3].strip()) if parts[3].strip().isdigit() else 0,
                ))
            if (i + 1) % 100000 == 0:
                logger.info("已解析 %d/%d", i + 1, len(records))

        # 批量写入
        conn = sqlite3.connect(self.cache_db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")

        batch_size = 5000
        for i in range(0, len(commits_data), batch_size):
            batch = commits_data[i:i + batch_size]
            conn.executemany(
                "INSERT OR IGNORE INTO commits "
                "(repo_version, commit_id, short_id, subject, author, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                batch,
            )
            conn.commit()
            if (i + batch_size) % 50000 == 0:
                logger.info("已保存 %d/%d", min(i + batch_size, len(commits_data)), len(commits_data))

        conn.commit()
        conn.close()
        logger.info("缓存构建完成: %d 条记录 %s", len(commits_data), desc)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    configs = {
        "5.10-hulk": {
            "path": "/Users/junxiaoqiong/Workplace/linux",
            "branch": "linux-5.10.y",
        }
    }
    mgr = GitRepoManager(configs)
    commits = mgr.search_by_keywords(["memory", "leak"], "5.10-hulk", limit=5)
    for c in commits:
        print(f"{c.commit_id[:12]} {c.subject}")
