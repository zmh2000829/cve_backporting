#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Git仓库管理器
用于操作目标kernel仓库，搜索和匹配commits
"""

import subprocess
import re
import os
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
import sqlite3
from pathlib import Path


@dataclass
class GitCommit:
    """Git commit数据结构"""
    commit_id: str
    subject: str
    commit_msg: str
    author: str
    timestamp: int
    diff_code: str = ""
    modified_files: List[str] = None


class GitRepoManager:
    """
    Git仓库管理器
    提供高效的commit搜索和匹配功能
    """
    
    def __init__(self, repo_configs: Dict[str, Dict[str, str]], use_cache: bool = True):
        """
        Args:
            repo_configs: {version_name: {"path": repo_path, "branch": branch_name}} 
                         例如 {"5.10-hulk": {"path": "/path/to/repo", "branch": "master"}}
            use_cache: 是否使用本地缓存数据库加速搜索
        """
        self.repo_configs = repo_configs
        self.use_cache = use_cache
        self.cache_db_path = "commit_cache.db"
        
        if use_cache:
            self._init_cache_db()
    
    def _get_repo_path(self, repo_version: str) -> Optional[str]:
        """获取仓库路径"""
        config = self.repo_configs.get(repo_version)
        if isinstance(config, dict):
            return config.get('path')
        # 向后兼容：如果是字符串，直接返回
        return config if isinstance(config, str) else None
    
    def _get_repo_branch(self, repo_version: str) -> Optional[str]:
        """获取仓库分支名称"""
        config = self.repo_configs.get(repo_version)
        if isinstance(config, dict):
            return config.get('branch')
        # 如果没有配置分支，返回None（使用当前分支）
        return None
    
    def _init_cache_db(self):
        """
        初始化缓存数据库
        用于存储commits信息，加速搜索
        """
        conn = sqlite3.connect(self.cache_db_path)
        cursor = conn.cursor()
        
        # 创建commits表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS commits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_version TEXT NOT NULL,
                commit_id TEXT NOT NULL,
                short_id TEXT NOT NULL,
                subject TEXT NOT NULL,
                commit_msg TEXT,
                author TEXT,
                timestamp INTEGER,
                modified_files TEXT,
                diff_code TEXT,
                UNIQUE(repo_version, commit_id)
            )
        ''')
        
        # 创建索引加速搜索
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_short_id 
            ON commits(repo_version, short_id)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_subject 
            ON commits(repo_version, subject)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp 
            ON commits(repo_version, timestamp)
        ''')
        
        # 全文搜索索引（如果SQLite支持FTS5）
        try:
            cursor.execute('''
                CREATE VIRTUAL TABLE IF NOT EXISTS commits_fts 
                USING fts5(commit_id, subject, commit_msg, content='commits', content_rowid='id')
            ''')
            
            # 创建触发器保持FTS表同步
            cursor.execute('''
                CREATE TRIGGER IF NOT EXISTS commits_ai AFTER INSERT ON commits BEGIN
                    INSERT INTO commits_fts(rowid, commit_id, subject, commit_msg)
                    VALUES (new.id, new.commit_id, new.subject, new.commit_msg);
                END
            ''')
        except sqlite3.OperationalError:
            print("警告: SQLite不支持FTS5，全文搜索功能将受限")
        
        conn.commit()
        conn.close()
    
    def execute_git_command(self, 
                           cmd: List[str], 
                           repo_version: str,
                           capture_output: bool = True) -> Optional[str]:
        """
        在指定仓库中执行git命令
        """
        repo_path = self._get_repo_path(repo_version)
        if not repo_path:
            raise ValueError(f"未配置版本 {repo_version} 的仓库路径")
        
        if not os.path.exists(repo_path):
            raise FileNotFoundError(f"仓库路径不存在: {repo_path}")
        
        try:
            result = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=capture_output,
                text=True,
                timeout=300  # 5分钟超时
            )
            
            if result.returncode != 0:
                print(f"Git命令执行失败: {' '.join(cmd)}")
                print(f"错误信息: {result.stderr}")
                return None
            
            return result.stdout if capture_output else None
        
        except subprocess.TimeoutExpired:
            print(f"Git命令执行超时: {' '.join(cmd)}")
            return None
        except Exception as e:
            print(f"执行Git命令时出错: {e}")
            return None
    
    def find_commit_by_id(self, commit_id: str, repo_version: str) -> Optional[Dict]:
        """
        通过commit ID精确查找（只在配置的分支上查找）
        """
        # 先查缓存
        if self.use_cache:
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT commit_id, subject, commit_msg, author, timestamp
                FROM commits
                WHERE repo_version = ? AND (commit_id = ? OR short_id = ?)
                LIMIT 1
            ''', (repo_version, commit_id, commit_id[:12]))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    "commit_id": row[0],
                    "subject": row[1],
                    "commit_msg": row[2],
                    "author": row[3],
                    "timestamp": row[4]
                }
        
        # 缓存中没有，从git仓库查（只在指定分支上查找）
        branch = self._get_repo_branch(repo_version)
        
        if branch:
            # 先检查commit是否在指定分支上
            check_cmd = ["git", "branch", "--contains", commit_id]
            branch_output = self.execute_git_command(check_cmd, repo_version)
            
            if not branch_output or branch not in branch_output:
                # commit不在指定分支上
                return None
        
        # 获取commit详细信息
        cmd = ["git", "log", "-1", "--format=%H|%s|%b|%an|%at", commit_id]
        output = self.execute_git_command(cmd, repo_version)
        
        if not output:
            return None
        
        parts = output.strip().split('|', 4)
        if len(parts) < 5:
            return None
        
        result = {
            "commit_id": parts[0],
            "subject": parts[1],
            "commit_msg": parts[2],
            "author": parts[3],
            "timestamp": int(parts[4]) if parts[4] else 0
        }
        
        # 保存到缓存
        if self.use_cache:
            self._cache_commit(repo_version, result)
        
        return result
    
    def search_commits_by_keywords(self, 
                                   keywords: List[str], 
                                   repo_version: str,
                                   limit: int = 100) -> List[GitCommit]:
        """
        通过关键词搜索commits
        """
        results = []
        
        # 方法1: 使用FTS全文搜索（如果可用）
        if self.use_cache:
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()
            
            try:
                # 构建FTS查询
                query = ' AND '.join(keywords)
                cursor.execute(f'''
                    SELECT c.commit_id, c.subject, c.commit_msg, c.author, 
                           c.timestamp, c.modified_files, c.diff_code
                    FROM commits c
                    JOIN commits_fts fts ON c.id = fts.rowid
                    WHERE fts MATCH ? AND c.repo_version = ?
                    LIMIT ?
                ''', (query, repo_version, limit))
                
                rows = cursor.fetchall()
                for row in rows:
                    results.append(GitCommit(
                        commit_id=row[0],
                        subject=row[1],
                        commit_msg=row[2],
                        author=row[3],
                        timestamp=row[4],
                        modified_files=row[5].split(',') if row[5] else [],
                        diff_code=row[6] or ""
                    ))
                
                conn.close()
                
                if results:
                    return results
            except sqlite3.OperationalError:
                # FTS不可用，fallback到LIKE查询
                pass
            finally:
                conn.close()
        
        # 方法2: 使用git log --grep（只在指定分支上搜索）
        branch = self._get_repo_branch(repo_version)
        
        grep_pattern = '|'.join(keywords)  # 匹配任一关键词
        cmd = ["git", "log"]
        
        # 如果配置了分支，只搜索该分支
        if branch:
            cmd.append(branch)
        
        cmd.extend([
            f"--grep={grep_pattern}",
            "--extended-regexp",
            "-i",  # 忽略大小写
            f"--max-count={limit}",
            "--format=%H|%s|%b|%an|%at"
        ])
        
        output = self.execute_git_command(cmd, repo_version)
        if not output:
            return results
        
        for line in output.strip().split('\n\n'):  # commits由空行分隔
            if not line.strip():
                continue
            
            parts = line.split('|', 4)
            if len(parts) >= 5:
                commit = GitCommit(
                    commit_id=parts[0],
                    subject=parts[1],
                    commit_msg=parts[2],
                    author=parts[3],
                    timestamp=int(parts[4]) if parts[4].isdigit() else 0
                )
                results.append(commit)
                
                # 缓存
                if self.use_cache:
                    self._cache_commit(repo_version, {
                        "commit_id": commit.commit_id,
                        "subject": commit.subject,
                        "commit_msg": commit.commit_msg,
                        "author": commit.author,
                        "timestamp": commit.timestamp
                    })
        
        return results[:limit]
    
    def search_commits_by_files(self,
                               file_paths: List[str],
                               repo_version: str,
                               limit: int = 200) -> List[GitCommit]:
        """
        搜索修改了指定文件的commits（只在指定分支上搜索）
        """
        results = []
        
        branch = self._get_repo_branch(repo_version)
        
        # 使用git log -- <files>（只搜索指定分支）
        cmd = ["git", "log"]
        
        # 如果配置了分支，只搜索该分支
        if branch:
            cmd.append(branch)
        
        cmd.extend([
            f"--max-count={limit}",
            "--format=%H|%s|%b|%an|%at",
            "--"
        ])
        cmd.extend(file_paths)
        
        output = self.execute_git_command(cmd, repo_version)
        if not output:
            return results
        
        for line in output.strip().split('\n\n'):
            if not line.strip():
                continue
            
            parts = line.split('|', 4)
            if len(parts) >= 5:
                results.append(GitCommit(
                    commit_id=parts[0],
                    subject=parts[1],
                    commit_msg=parts[2],
                    author=parts[3],
                    timestamp=int(parts[4]) if parts[4].isdigit() else 0
                ))
        
        return results[:limit]
    
    def get_commit_diff(self, commit_id: str, repo_version: str) -> Optional[str]:
        """
        获取commit的完整diff
        """
        cmd = ["git", "show", "--format=", commit_id]
        return self.execute_git_command(cmd, repo_version)
    
    def get_commit_files(self, commit_id: str, repo_version: str) -> List[str]:
        """
        获取commit修改的文件列表
        """
        cmd = ["git", "show", "--name-only", "--format=", commit_id]
        output = self.execute_git_command(cmd, repo_version)
        
        if not output:
            return []
        
        return [line.strip() for line in output.strip().split('\n') if line.strip()]
    
    def _cache_commit(self, repo_version: str, commit_info: Dict):
        """
        将commit信息缓存到数据库
        """
        if not self.use_cache:
            return
        
        try:
            conn = sqlite3.connect(self.cache_db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR IGNORE INTO commits 
                (repo_version, commit_id, short_id, subject, commit_msg, author, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                repo_version,
                commit_info["commit_id"],
                commit_info["commit_id"][:12],
                commit_info.get("subject", ""),
                commit_info.get("commit_msg", ""),
                commit_info.get("author", ""),
                commit_info.get("timestamp", 0)
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"缓存commit时出错: {e}")
    
    def build_commit_cache(self, repo_version: str, max_commits: int = 10000):
        """
        预先构建commit缓存（只缓存配置的分支）
        适合在第一次使用前运行，加速后续搜索
        """
        branch = self._get_repo_branch(repo_version)
        
        if branch:
            print(f"开始构建 {repo_version} 的commit缓存（分支: {branch}）...")
        else:
            print(f"开始构建 {repo_version} 的commit缓存（当前分支）...")
        
        # 构建git log命令，只查询指定分支
        cmd = ["git", "log"]
        
        # 如果配置了分支，只查询该分支
        if branch:
            cmd.append(branch)
        
        cmd.extend([
            f"--max-count={max_commits}",
            "--format=%H|%s|%b|%an|%at"
        ])
        
        print(f"  执行命令: {' '.join(cmd)}")
        
        output = self.execute_git_command(cmd, repo_version)
        if not output:
            print("获取commits失败")
            return
        
        commits_data = []
        lines = output.strip().split('\n')
        
        print(f"  正在处理 {len(lines)} 个commits...")
        
        for i, line in enumerate(lines):
            if not line.strip():
                continue
            
            parts = line.split('|', 4)
            if len(parts) >= 5:
                commits_data.append({
                    "commit_id": parts[0],
                    "subject": parts[1],
                    "commit_msg": parts[2],
                    "author": parts[3],
                    "timestamp": int(parts[4]) if parts[4].isdigit() else 0
                })
            
            if (i + 1) % 1000 == 0:
                print(f"  已处理 {i + 1}/{len(lines)} commits")
        
        # 批量插入数据库
        conn = sqlite3.connect(self.cache_db_path)
        cursor = conn.cursor()
        
        print(f"  正在保存到数据库...")
        
        for commit in commits_data:
            cursor.execute('''
                INSERT OR IGNORE INTO commits 
                (repo_version, commit_id, short_id, subject, commit_msg, author, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                repo_version,
                commit["commit_id"],
                commit["commit_id"][:12],
                commit["subject"],
                commit["commit_msg"],
                commit["author"],
                commit["timestamp"]
            ))
        
        conn.commit()
        conn.close()
        
        print(f"✅ 缓存构建完成，共 {len(commits_data)} 条记录（分支: {branch if branch else '当前分支'}）")


# 使用示例
if __name__ == "__main__":
    # 配置仓库（包括path和branch）
    repo_configs = {
        "5.10-hulk": {
            "path": "/data/zhangmh/Associated_Patch_Analysis/5.10/kernel",
            "branch": "5.10.0-60.18.0.50.oe2203"
        },
        # "6.6-hulk": {
        #     "path": "/path/to/your/kernel-6.6",
        #     "branch": "master"
        # }
    }
    
    manager = GitRepoManager(repo_configs, use_cache=True)
    
    # 构建缓存（首次使用时，只缓存指定分支）
    # manager.build_commit_cache("5.10-hulk", max_commits=10000)
    
    # 搜索示例（只在配置的分支上搜索）
    commits = manager.search_commits_by_keywords(
        keywords=["memory", "leak", "tcp"],
        repo_version="5.10-hulk",
        limit=10
    )
    
    for commit in commits:
        print(f"{commit.commit_id[:12]} - {commit.subject}")
