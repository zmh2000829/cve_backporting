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

    def __init__(self, root: str, manifest_path: str = ".repo/manifest.xml"):
        self.root = os.path.abspath(root)
        self.manifest_path = (
            manifest_path if os.path.isabs(manifest_path)
            else os.path.join(self.root, manifest_path)
        )
        self.projects: List[RepoProject] = []
        self._by_path: Dict[str, RepoProject] = {}
        self._load()

    def _load(self):
        if not os.path.exists(self.manifest_path):
            return
        tree = ET.parse(self.manifest_path)
        root = tree.getroot()
        default_revision = ""
        default_remote = ""
        default = root.find("default")
        if default is not None:
            default_revision = default.attrib.get("revision", "")
            default_remote = default.attrib.get("remote", "")

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

        projects.sort(key=lambda p: len(p.norm_path), reverse=True)
        self.projects = projects
        self._by_path = {p.norm_path: p for p in projects}

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
