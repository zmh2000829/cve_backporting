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
from typing import List, Dict, Optional, Callable
from core.models import GitCommit

logger = logging.getLogger(__name__)

FIELD_SEP = "\x1e"
RECORD_SEP = "\x1f"

ProgressCB = Optional[Callable[[int, int], None]]  # (current, total)


class GitRepoManager:

    def __init__(self, repo_configs: Dict[str, Dict[str, str]],
                 use_cache: bool = True, cache_db_path: str = "commit_cache.db"):
        self.repo_configs = repo_configs
        self.use_cache = use_cache
        self.cache_db_path = cache_db_path
        if use_cache:
            self._init_cache_db()

    # ─── repo config helpers ─────────────────────────────────────────

    def _get_repo_path(self, rv: str) -> Optional[str]:
        c = self.repo_configs.get(rv)
        return c.get("path") if isinstance(c, dict) else (c if isinstance(c, str) else None)

    def _get_repo_branch(self, rv: str) -> Optional[str]:
        c = self.repo_configs.get(rv)
        return c.get("branch") if isinstance(c, dict) else None

    # ─── git execution ───────────────────────────────────────────────

    def run_git(self, cmd: List[str], rv: str, timeout: int = 600) -> Optional[str]:
        rp = self._get_repo_path(rv)
        if not rp:
            raise ValueError(f"未配置仓库: {rv}")
        if not os.path.exists(rp):
            raise FileNotFoundError(f"仓库路径不存在: {rp}")
        try:
            r = subprocess.run(cmd, cwd=rp, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=timeout)
            if r.returncode != 0:
                logger.debug("Git失败: %s\n%s", " ".join(cmd[:6]), r.stderr.strip()[:200])
                return None
            return r.stdout
        except subprocess.TimeoutExpired:
            logger.error("Git超时(%ds): %s", timeout, " ".join(cmd[:5]))
            return None
        except Exception as e:
            logger.error("Git异常: %s", e)
            return None

    def run_git_rc(self, cmd: List[str], rv: str, timeout: int = 30) -> int:
        """执行git命令并返回returncode"""
        rp = self._get_repo_path(rv)
        if not rp:
            return -1
        try:
            r = subprocess.run(cmd, cwd=rp, capture_output=True, timeout=timeout)
            return r.returncode
        except Exception:
            return -1

    # ─── commit lookup ───────────────────────────────────────────────

    def check_commit_existence(self, commit_id: str, rv: str) -> tuple:
        """
        分步检查commit状态，返回 (status, info_dict)
        status:
          "on_branch"     — 存在且在目标分支上
          "not_on_branch" — 存在于对象库但不在目标分支上
          "not_found"     — 对象库中不存在
        """
        sid = commit_id[:12]
        # 缓存命中 → 一定在分支上（缓存只存目标分支的commit）
        if self.use_cache:
            c = self._cache_lookup_id(sid, rv)
            if c:
                return "on_branch", c

        # 检查对象是否存在
        chk = self.run_git(["git", "cat-file", "-t", commit_id], rv, timeout=10)
        if not chk or chk.strip() != "commit":
            return "not_found", None

        # 获取commit信息
        fmt = f"%H{FIELD_SEP}%s{FIELD_SEP}%an{FIELD_SEP}%at"
        out = self.run_git(["git", "log", "-1", f"--format={fmt}", commit_id], rv, timeout=30)
        info = None
        if out:
            p = out.strip().split(FIELD_SEP)
            if len(p) >= 4:
                info = {"commit_id": p[0], "subject": p[1], "author": p[2],
                        "timestamp": int(p[3]) if p[3].isdigit() else 0}

        # 检查是否在目标分支上
        br = self._get_repo_branch(rv)
        if br and self.run_git_rc(["git", "merge-base", "--is-ancestor", commit_id, br], rv) != 0:
            return "not_on_branch", info

        # 在分支上 → 写入缓存
        if info and self.use_cache:
            self._cache_commit(rv, info)
        return "on_branch", info

    def find_commit_by_id(self, commit_id: str, rv: str) -> Optional[Dict]:
        status, info = self.check_commit_existence(commit_id, rv)
        return info if status == "on_branch" else None

    # ─── search ──────────────────────────────────────────────────────

    def search_by_subject(self, subject: str, rv: str, limit: int = 20) -> List[GitCommit]:
        if self.use_cache:
            c = self._cache_search_subject(subject, rv, limit)
            if c:
                return c
        br = self._get_repo_branch(rv)
        cmd = ["git", "log"] + ([br] if br else []) + [
            f"--grep={subject}", "--fixed-strings", "-i",
            f"--max-count={limit}",
            f"--format=%H{FIELD_SEP}%s{FIELD_SEP}%an{FIELD_SEP}%at{RECORD_SEP}",
        ]
        return self._parse_log(self.run_git(cmd, rv))

    def search_by_keywords(self, keywords: List[str], rv: str, limit: int = 50) -> List[GitCommit]:
        if self.use_cache:
            c = self._cache_fts(keywords, rv, limit)
            if c:
                return c
        br = self._get_repo_branch(rv)
        pat = "|".join(re.escape(k) for k in keywords)
        cmd = ["git", "log"] + ([br] if br else []) + [
            f"--grep={pat}", "--extended-regexp", "-i",
            f"--max-count={limit}",
            f"--format=%H{FIELD_SEP}%s{FIELD_SEP}%an{FIELD_SEP}%at{RECORD_SEP}",
        ]
        return self._parse_log(self.run_git(cmd, rv))

    def search_by_files(self, files: List[str], rv: str, limit: int = 100) -> List[GitCommit]:
        br = self._get_repo_branch(rv)
        cmd = ["git", "log"] + ([br] if br else []) + [
            f"--max-count={limit}",
            f"--format=%H{FIELD_SEP}%s{FIELD_SEP}%an{FIELD_SEP}%at{RECORD_SEP}",
            "--",
        ] + files
        return self._parse_log(self.run_git(cmd, rv))

    def get_commit_diff(self, cid: str, rv: str) -> Optional[str]:
        return self.run_git(["git", "show", "--format=", cid], rv)

    def get_commit_files(self, cid: str, rv: str) -> List[str]:
        out = self.run_git(["git", "show", "--name-only", "--format=", cid], rv)
        return [l.strip() for l in (out or "").strip().split("\n") if l.strip()]

    def get_cache_count(self, rv: str = None) -> int:
        try:
            conn = sqlite3.connect(self.cache_db_path)
            if rv:
                r = conn.execute("SELECT COUNT(*) FROM commits WHERE repo_version=?", (rv,)).fetchone()
            else:
                r = conn.execute("SELECT COUNT(*) FROM commits").fetchone()
            conn.close()
            return r[0]
        except Exception:
            return 0

    # ─── cache build (optimized for 10M+ commits) ─────────────────────

    def count_commits(self, rv: str) -> int:
        """快速统计分支commit总数"""
        br = self._get_repo_branch(rv)
        cmd = ["git", "rev-list", "--count"] + ([br] if br else ["HEAD"])
        out = self.run_git(cmd, rv, timeout=120)
        return int(out.strip()) if out and out.strip().isdigit() else 0

    def build_commit_cache(self, rv: str, max_commits: int = None,
                           progress_cb: ProgressCB = None):
        """
        构建commit缓存 (流式优化版)

        优化要点 vs 旧版:
        1. 流式读取 git stdout (Popen) → 不将GB级输出加载到内存
        2. 每行一条记录 → 去掉 RECORD_SEP，直接按行解析
        3. 批量50000条写入 (旧版5000)
        4. 批量导入期间禁用FTS触发器，导入完成后重建FTS索引
        5. PRAGMA page_size/cache_size/temp_store 全面调优
        """
        br = self._get_repo_branch(rv)
        rp = self._get_repo_path(rv)
        if not rp or not os.path.exists(rp):
            logger.error("仓库路径不可用: %s", rv)
            return

        total = max_commits or self.count_commits(rv)
        logger.info("构建缓存: %s (分支: %s, 预计: %s)", rv, br or "当前",
                     f"{total:,}" if total else "未知")

        # git log 流式输出，每行一条记录
        fmt = f"%H{FIELD_SEP}%s{FIELD_SEP}%an{FIELD_SEP}%at"
        cmd = ["git", "log"] + ([br] if br else [])
        if max_commits and max_commits > 0:
            cmd.append(f"--max-count={max_commits}")
        cmd.append(f"--format={fmt}")

        proc = subprocess.Popen(
            cmd, cwd=rp, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True,
            encoding="utf-8", errors="replace",
            bufsize=1 << 20,  # 1MB buffer
        )

        conn = sqlite3.connect(self.cache_db_path)
        # SQLite批量导入优化
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=OFF")
        conn.execute("PRAGMA cache_size=-512000")  # 512MB cache
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA mmap_size=1073741824")  # 1GB mmap

        # 禁用FTS触发器（批量导入后重建）
        try:
            conn.execute("DROP TRIGGER IF EXISTS commits_ai")
        except Exception:
            pass

        batch = []
        count = 0
        batch_size = 50000
        sql = ("INSERT OR IGNORE INTO commits "
               "(repo_version,commit_id,short_id,subject,author,timestamp) "
               "VALUES (?,?,?,?,?,?)")

        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            p = line.split(FIELD_SEP)
            if len(p) < 4:
                continue
            cid = p[0].strip()
            batch.append((rv, cid, cid[:12], p[1].strip(), p[2].strip(),
                          int(p[3].strip()) if p[3].strip().isdigit() else 0))
            count += 1

            if len(batch) >= batch_size:
                conn.executemany(sql, batch)
                conn.commit()
                batch.clear()
                if progress_cb:
                    progress_cb(count, total)

        # flush remaining
        if batch:
            conn.executemany(sql, batch)
            conn.commit()
            if progress_cb:
                progress_cb(count, total)

        proc.wait()

        # 重建FTS索引
        logger.info("重建FTS索引...")
        if progress_cb:
            progress_cb(count, total)
        try:
            # 安全重建：先删除再重建整个FTS表
            conn.execute("DROP TABLE IF EXISTS commits_fts")
            conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS commits_fts "
                         "USING fts5(commit_id,subject,content='commits',content_rowid='id')")
            conn.execute("INSERT INTO commits_fts(rowid, commit_id, subject) "
                         "SELECT id, commit_id, subject FROM commits WHERE repo_version=?", (rv,))
            conn.execute("DROP TRIGGER IF EXISTS commits_ai")
            conn.execute(
                "CREATE TRIGGER IF NOT EXISTS commits_ai AFTER INSERT ON commits BEGIN "
                "INSERT INTO commits_fts(rowid,commit_id,subject) "
                "VALUES(new.id,new.commit_id,new.subject); END")
            conn.commit()
        except sqlite3.OperationalError as e:
            logger.warning("FTS重建失败(不影响核心功能): %s", e)

        conn.execute("PRAGMA synchronous=NORMAL")
        conn.close()
        logger.info("缓存完成: %d 条", count)

    # ─── internals ───────────────────────────────────────────────────

    def _parse_log(self, out: Optional[str]) -> List[GitCommit]:
        if not out:
            return []
        res = []
        for rec in out.strip().split(RECORD_SEP):
            rec = rec.strip()
            if not rec:
                continue
            p = rec.split(FIELD_SEP)
            if len(p) >= 4:
                res.append(GitCommit(commit_id=p[0].strip(), subject=p[1].strip(),
                                     author=p[2].strip(),
                                     timestamp=int(p[3].strip()) if p[3].strip().isdigit() else 0))
        return res

    def _init_cache_db(self):
        conn = sqlite3.connect(self.cache_db_path)
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS commits (
            id INTEGER PRIMARY KEY AUTOINCREMENT, repo_version TEXT NOT NULL,
            commit_id TEXT NOT NULL, short_id TEXT NOT NULL, subject TEXT NOT NULL,
            author TEXT, timestamp INTEGER, UNIQUE(repo_version, commit_id))""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_sid ON commits(repo_version,short_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_subj ON commits(repo_version,subject)")
        try:
            c.execute("CREATE VIRTUAL TABLE IF NOT EXISTS commits_fts "
                      "USING fts5(commit_id,subject,content='commits',content_rowid='id')")
            c.execute("CREATE TRIGGER IF NOT EXISTS commits_ai AFTER INSERT ON commits BEGIN "
                      "INSERT INTO commits_fts(rowid,commit_id,subject) VALUES(new.id,new.commit_id,new.subject); END")
        except sqlite3.OperationalError:
            pass
        conn.commit()
        conn.close()

    def _cache_lookup_id(self, sid: str, rv: str) -> Optional[Dict]:
        try:
            conn = sqlite3.connect(self.cache_db_path)
            r = conn.execute("SELECT commit_id,subject,author,timestamp FROM commits "
                             "WHERE repo_version=? AND short_id=? LIMIT 1", (rv, sid)).fetchone()
            conn.close()
            if r:
                return {"commit_id": r[0], "subject": r[1], "author": r[2], "timestamp": r[3]}
        except Exception:
            pass
        return None

    def _cache_search_subject(self, subj: str, rv: str, limit: int) -> List[GitCommit]:
        try:
            conn = sqlite3.connect(self.cache_db_path)
            rows = conn.execute("SELECT commit_id,subject,author,timestamp FROM commits "
                                "WHERE repo_version=? AND subject=? LIMIT ?", (rv, subj, limit)).fetchall()
            conn.close()
            return [GitCommit(commit_id=r[0], subject=r[1], author=r[2], timestamp=r[3]) for r in rows]
        except Exception:
            return []

    def _cache_fts(self, kws: List[str], rv: str, limit: int) -> List[GitCommit]:
        try:
            conn = sqlite3.connect(self.cache_db_path)
            q = " AND ".join(kws)
            rows = conn.execute(
                "SELECT c.commit_id,c.subject,c.author,c.timestamp FROM commits c "
                "JOIN commits_fts f ON c.id=f.rowid WHERE f MATCH ? AND c.repo_version=? LIMIT ?",
                (q, rv, limit)).fetchall()
            conn.close()
            if rows:
                return [GitCommit(commit_id=r[0], subject=r[1], author=r[2], timestamp=r[3]) for r in rows]
        except sqlite3.OperationalError:
            pass
        return []

    def _cache_commit(self, rv: str, info: Dict):
        try:
            conn = sqlite3.connect(self.cache_db_path)
            conn.execute("INSERT OR IGNORE INTO commits (repo_version,commit_id,short_id,subject,author,timestamp) "
                         "VALUES (?,?,?,?,?,?)",
                         (rv, info["commit_id"], info["commit_id"][:12],
                          info.get("subject", ""), info.get("author", ""), info.get("timestamp", 0)))
            conn.commit()
            conn.close()
        except Exception:
            pass
