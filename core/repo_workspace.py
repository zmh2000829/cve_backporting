"""Android repo workspace helpers.

Android source trees are usually managed by the `repo` tool: a workspace root
contains many independent Git projects described by a manifest. This module
keeps that topology explicit so higher layers can still ask for a single
target alias while the repository layer routes work to the right project.
"""

import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class RepoProject:
    name: str
    path: str
    revision: str = ""
    remote: str = ""

    @property
    def norm_path(self) -> str:
        return "" if self.path in ("", ".") else self.path.strip("/")


class RepoManifest:
    """Parsed view of a repo manifest."""

    def __init__(self, root: str, manifest_path: str = ".repo/manifest.xml",
                 include_dirs: List[str] = None):
        self.root = os.path.abspath(root)
        self.manifest_path = (
            manifest_path if os.path.isabs(manifest_path)
            else os.path.join(self.root, manifest_path)
        )
        self.include_dirs = self._normalize_include_dirs(include_dirs or [])
        self.projects: List[RepoProject] = []
        self._by_path: Dict[str, RepoProject] = {}
        self.include_errors: List[str] = []
        self._load()

    def _load(self):
        if not os.path.exists(self.manifest_path):
            return
        projects = self._load_file(
            self.manifest_path,
            default_revision="",
            default_remote="",
            visited=set(),
        )
        projects.sort(key=lambda p: len(p.norm_path), reverse=True)
        self.projects = projects
        self._by_path = {p.norm_path: p for p in projects}

    def _load_file(self, path: str, *, default_revision: str,
                   default_remote: str, visited: set) -> List[RepoProject]:
        real_path = os.path.realpath(path)
        if real_path in visited:
            return []
        visited.add(real_path)
        if not os.path.exists(real_path):
            self.include_errors.append(real_path)
            return []

        tree = ET.parse(real_path)
        root = tree.getroot()
        default = root.find("default")
        if default is not None:
            default_revision = default.attrib.get("revision", default_revision)
            default_remote = default.attrib.get("remote", default_remote)

        projects: List[RepoProject] = []
        for node in root.findall("project"):
            name = node.attrib.get("name", "").strip()
            path = node.attrib.get("path", name).strip()
            if not name or not path:
                continue
            project = RepoProject(
                name=name,
                path=path.strip("/"),
                revision=node.attrib.get("revision", default_revision),
                remote=node.attrib.get("remote", default_remote),
            )
            projects.append(project)

        for node in root.findall("include"):
            name = node.attrib.get("name", "").strip()
            if not name:
                continue
            include_path = self._resolve_include(real_path, name)
            if not include_path:
                self.include_errors.append(name)
                continue
            projects.extend(self._load_file(
                include_path,
                default_revision=default_revision,
                default_remote=default_remote,
                visited=visited,
            ))

        return projects

    def _normalize_include_dirs(self, include_dirs: List[str]) -> List[str]:
        roots: List[str] = []
        for item in include_dirs or []:
            if not item:
                continue
            roots.append(item if os.path.isabs(item) else os.path.join(self.root, item))
        # Generic repo defaults. They are appended after user config, so vendors
        # can override or add alternate include roots without code changes.
        roots.extend([
            os.path.join(self.root, ".repo", "manifests"),
            os.path.join(self.root, ".repo", "local_manifests"),
        ])
        seen = set()
        out = []
        for root in roots:
            root = os.path.normpath(root)
            if root not in seen:
                seen.add(root)
                out.append(root)
        return out

    def _resolve_include(self, current_manifest: str, include_name: str) -> Optional[str]:
        if os.path.isabs(include_name) and os.path.exists(include_name):
            return include_name
        candidates = [
            os.path.join(os.path.dirname(current_manifest), include_name),
            os.path.join(os.path.dirname(os.path.realpath(current_manifest)), include_name),
        ]
        candidates.extend(os.path.join(root, include_name) for root in self.include_dirs)
        for candidate in candidates:
            if os.path.exists(candidate):
                return candidate
        return None

    def project_for_file(self, file_path: str) -> Optional[RepoProject]:
        path = (file_path or "").strip().strip("/")
        if not path:
            return None
        for project in self.projects:
            prefix = project.norm_path
            if not prefix:
                continue
            if path == prefix or path.startswith(prefix + "/"):
                return project
        return None

    def relative_path(self, project: RepoProject, file_path: str) -> str:
        path = (file_path or "").strip().strip("/")
        prefix = project.norm_path
        if prefix and path.startswith(prefix + "/"):
            return path[len(prefix) + 1:]
        if path == prefix:
            return ""
        return path

    def abs_path(self, project: RepoProject) -> str:
        return os.path.join(self.root, project.norm_path)

    def common_project_for_files(self, files: List[str]) -> Tuple[Optional[RepoProject], List[str]]:
        projects: Dict[str, RepoProject] = {}
        unresolved: List[str] = []
        for file_path in files or []:
            project = self.project_for_file(file_path)
            if project:
                projects[project.norm_path] = project
            else:
                unresolved.append(file_path)
        if len(projects) == 1 and not unresolved:
            return next(iter(projects.values())), []
        problems = list(unresolved)
        if len(projects) > 1:
            problems.extend(sorted(projects.keys()))
        return None, problems
