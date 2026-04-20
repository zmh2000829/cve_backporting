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

    def search_by_files(self, files: List[str], rv: str, limit: int = 100,
                        after_ts: int = 0, no_merges: bool = False) -> List[GitCommit]:
        br = self._get_repo_branch(rv)
        cmd = ["git", "log"] + ([br] if br else [])
        if no_merges:
            cmd.append("--no-merges")
        if after_ts > 0:
            cmd.append(f"--after=@{after_ts}")
        cmd += [
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

    def get_file_content(self, filepath: str, rv: str, ref: str = None) -> Optional[str]:
        """读取目标分支中的文件内容。"""
        target_ref = ref or self._get_repo_branch(rv) or "HEAD"
        path = (filepath or "").strip()
        if not path:
            return None
        return self.run_git(["git", "show", f"{target_ref}:{path}"], rv, timeout=30)

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

    # ─── worktree management ────────────────────────────────────────────

    def create_worktree(self, rv: str, commit: str, worktree_path: str) -> bool:
        """在指定 commit 创建 git worktree，返回是否成功"""
        rp = self._get_repo_path(rv)
        if not rp:
            return False
        try:
            subprocess.run(
                ["git", "worktree", "add", "--detach", worktree_path, commit],
                cwd=rp, capture_output=True, text=True, timeout=60, check=True,
            )
            logger.info("创建 worktree: %s @ %s", worktree_path, commit[:12])
            return True
        except subprocess.CalledProcessError as e:
            logger.error("创建 worktree 失败: %s", e.stderr.strip()[:200])
            return False
        except Exception as e:
            logger.error("创建 worktree 异常: %s", e)
            return False

    def remove_worktree(self, rv: str, worktree_path: str):
        """清理 git worktree"""
        rp = self._get_repo_path(rv)
        if not rp:
            return
        try:
            subprocess.run(
                ["git", "worktree", "remove", "--force", worktree_path],
                cwd=rp, capture_output=True, text=True, timeout=30,
            )
            logger.info("清理 worktree: %s", worktree_path)
        except Exception as e:
            logger.warning("清理 worktree 失败: %s (可手动删除 %s)", e, worktree_path)

    # ─── cache build (optimized for 10M+ commits) ─────────────────────

    def get_latest_cached_commit(self, rv: str) -> Optional[str]:
        """获取缓存中时间戳最大的 commit ID（即最新的缓存 commit）"""
        try:
            conn = sqlite3.connect(self.cache_db_path)
            r = conn.execute(
                "SELECT commit_id FROM commits "
                "WHERE repo_version=? ORDER BY timestamp DESC LIMIT 1", (rv,)
            ).fetchone()
            conn.close()
            return r[0] if r else None
        except Exception:
            return None

    def count_commits(self, rv: str, timeout: int = 600) -> int:
        """
        统计分支commit总数。
        优先使用 rev-list --count (快但可能超时)，
        失败后回退到缓存表记录数。
        """
        br = self._get_repo_branch(rv)
        rp = self._get_repo_path(rv)
        if not rp or not os.path.exists(rp):
            return 0

        # 策略1: git rev-list --count (Popen + 长超时，避免内存问题)
        cmd = ["git", "rev-list", "--count"] + ([br] if br else ["HEAD"])
        try:
            proc = subprocess.Popen(
                cmd, cwd=rp, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True,
            )
            out, _ = proc.communicate(timeout=timeout)
            if proc.returncode == 0 and out and out.strip().isdigit():
                return int(out.strip())
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            logger.warning("rev-list --count 超时(%ds), 尝试回退方案", timeout)
        except Exception as e:
            logger.warning("rev-list --count 失败: %s", e)

        # 策略2: 使用已有缓存数量作为近似值
        if self.use_cache and os.path.exists(self.cache_db_path):
            cached = self.get_cache_count(rv)
            if cached > 0:
                logger.info("使用缓存记录数作为近似: %d", cached)
                return cached

        # 策略3: 快速采样估算 — 取最近10万条的速度推算
        try:
            cmd2 = ["git", "rev-list", "--count", "--max-count=100000"] + ([br] if br else ["HEAD"])
            r = subprocess.run(cmd2, cwd=rp, capture_output=True, text=True, timeout=60)
            if r.returncode == 0 and r.stdout.strip().isdigit():
                sample = int(r.stdout.strip())
                if sample < 100000:
                    return sample
                logger.info("rev-list采样到10万条, 总数未知, 返回0")
        except Exception:
            pass

        return 0

    def build_commit_cache(self, rv: str, max_commits: int = None,
                           progress_cb: ProgressCB = None,
                           incremental: bool = False):
        """
        构建commit缓存 (流式优化版)

        incremental=True 时：
          - 查找缓存中最新commit, 只拉取其之后的新增commit
          - 验证最新缓存commit仍在目标分支上（应对rebase）
          - 若缓存为空或最新commit不在分支上，自动降级为全量构建
        """
        br = self._get_repo_branch(rv)
        rp = self._get_repo_path(rv)
        if not rp or not os.path.exists(rp):
            logger.error("仓库路径不可用: %s", rv)
            return

        rev_range = None

        if incremental:
            latest = self.get_latest_cached_commit(rv)
            if latest:
                # 验证缓存中最新commit仍在分支上（防止rebase后脏数据）
                chk = self.run_git_rc(
                    ["git", "merge-base", "--is-ancestor", latest, br or "HEAD"],
                    rv, timeout=30)
                if chk == 0:
                    rev_range = f"{latest}..{br or 'HEAD'}"
                    logger.info("增量模式: %s (基于 %s)", rv, latest[:12])
                else:
                    logger.warning("缓存中最新commit %s 不在分支上，降级为全量构建", latest[:12])
            else:
                logger.info("缓存为空，执行全量构建")

        total = max_commits or 0
        mode_str = "增量" if rev_range else "全量"
        logger.info("构建缓存[%s]: %s (分支: %s, 预计: %s)", mode_str, rv, br or "当前",
                     f"{total:,}" if total else "未知")

        # git log 流式输出，每行一条记录
        fmt = f"%H{FIELD_SEP}%s{FIELD_SEP}%an{FIELD_SEP}%at"
        if rev_range:
            cmd = ["git", "log", rev_range]
        else:
            cmd = ["git", "log"] + ([br] if br else [])
        if max_commits and max_commits > 0 and not rev_range:
            cmd.append(f"--max-count={max_commits}")
        cmd.append(f"--format={fmt}")

        proc = subprocess.Popen(
            cmd, cwd=rp, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True,
            encoding="utf-8", errors="replace",
            bufsize=1 << 20,  # 1MB buffer
        )

        conn = sqlite3.connect(self.cache_db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=OFF")
        conn.execute("PRAGMA cache_size=-512000")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA mmap_size=1073741824")

        # 增量模式下保留FTS触发器（新增量少），全量重建时禁用
        if not rev_range:
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

        if batch:
            conn.executemany(sql, batch)
            conn.commit()
            if progress_cb:
                progress_cb(count, total)

        proc.wait()

        # FTS 处理：增量模式只插入新增部分，全量模式完整重建
        if rev_range:
            logger.info("增量更新FTS索引 (%d 条新commit)...", count)
            # FTS触发器在增量模式下已保留，刚写入的commit会自动进入FTS
            # 但 INSERT OR IGNORE 不触发 AFTER INSERT，需要手动补录
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO commits_fts(rowid, commit_id, subject) "
                    "SELECT id, commit_id, subject FROM commits "
                    "WHERE repo_version=? ORDER BY id DESC LIMIT ?",
                    (rv, count))
                conn.commit()
            except sqlite3.OperationalError as e:
                logger.warning("FTS增量更新失败: %s, 尝试全量重建", e)
                self._rebuild_fts(conn, rv)
        else:
            logger.info("全量重建FTS索引...")
            self._rebuild_fts(conn, rv)

        if progress_cb:
            progress_cb(count, total)

        conn.execute("PRAGMA synchronous=NORMAL")
        conn.close()
        logger.info("缓存完成[%s]: 新增 %d 条", mode_str, count)

    def _rebuild_fts(self, conn: sqlite3.Connection, rv: str):
        """完整重建 FTS 索引"""
        try:
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
