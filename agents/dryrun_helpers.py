"""DryRun hunk 解析与锚点辅助函数。"""

from typing import List


_NOISE_PREFIXES = ("\\",)


def clean_hunk_lines(lines: List[str]) -> List[str]:
    return [line for line in lines
            if not any(line.startswith(prefix) for prefix in _NOISE_PREFIXES)]


_TRIVIAL_ANCHORS = frozenset({
    "return 0;", "return ret;", "return;", "return -1;",
    "return err;", "return rc;", "return result;",
    "return NULL;", "return false;", "return true;",
    "return -EINVAL;", "return -ENOMEM;", "return -EIO;",
    "break;", "continue;", "default:",
    "{", "}", "} else {", "else {",
    "out:", "err:", "error:", "unlock:", "fail:",
})


def is_trivial_anchor(line: str) -> bool:
    text = line.strip()
    if not text or len(text) < 4:
        return True
    if text in _TRIVIAL_ANCHORS:
        return True
    if text.startswith("//") or text.startswith("/*") or text.startswith("*"):
        return True
    return False


def split_hunk_segments(hunk_lines: List[str]):
    """拆分 hunk → (ctx_before, removed, added, ctx_after)。"""
    clean = clean_hunk_lines(hunk_lines)
    ctx_before, removed, added, ctx_after = [], [], [], []
    first_change, last_change = len(clean), -1

    for idx, line in enumerate(clean):
        if line.startswith("-") or line.startswith("+"):
            first_change = min(first_change, idx)
            last_change = max(last_change, idx)

    for idx, line in enumerate(clean):
        if line.startswith("-"):
            removed.append(line[1:])
        elif line.startswith("+"):
            added.append(line[1:])
        else:
            text = line[1:] if line.startswith(" ") else line
            if idx < first_change:
                ctx_before.append(text)
            elif idx > last_change:
                ctx_after.append(text)

    return ctx_before, removed, added, ctx_after


def parse_hunk_regions(hunk_lines: List[str]):
    """将 hunk 解析为有序的 context/change 区域列表。"""
    clean = clean_hunk_lines(hunk_lines)
    regions = []
    current_ctx = []
    current_removed = []
    current_added = []
    in_change = False

    for line in clean:
        if line.startswith("-"):
            if not in_change and current_ctx:
                regions.append({"type": "context", "lines": current_ctx})
                current_ctx = []
            in_change = True
            current_removed.append(line[1:])
        elif line.startswith("+"):
            if not in_change and current_ctx:
                regions.append({"type": "context", "lines": current_ctx})
                current_ctx = []
            in_change = True
            current_added.append(line[1:])
        else:
            text = line[1:] if line.startswith(" ") else line
            if in_change:
                regions.append({
                    "type": "change",
                    "removed": current_removed,
                    "added": current_added,
                })
                current_removed = []
                current_added = []
                in_change = False
            current_ctx.append(text)

    if in_change:
        regions.append({
            "type": "change",
            "removed": current_removed,
            "added": current_added,
        })
    elif current_ctx:
        regions.append({"type": "context", "lines": current_ctx})

    return regions


def split_to_sub_hunks(hunk_header: str, hunk_lines: List[str]):
    """将多变更区域 hunk 拆成多个 sub-hunk。"""
    regions = parse_hunk_regions(hunk_lines)
    change_indices = [idx for idx, region in enumerate(regions)
                      if region["type"] == "change"]

    if len(change_indices) <= 1:
        return [(hunk_header, hunk_lines)]

    sub_hunks = []
    for idx in change_indices:
        change = regions[idx]

        ctx_before = []
        if idx > 0 and regions[idx - 1]["type"] == "context":
            ctx_before = regions[idx - 1]["lines"][-3:]

        ctx_after = []
        if idx + 1 < len(regions) and regions[idx + 1]["type"] == "context":
            ctx_after = regions[idx + 1]["lines"][:3]

        sub_lines = []
        for line in ctx_before:
            sub_lines.append(" " + line)
        for line in change["removed"]:
            sub_lines.append("-" + line)
        for line in change["added"]:
            sub_lines.append("+" + line)
        for line in ctx_after:
            sub_lines.append(" " + line)

        sub_hunks.append((hunk_header, sub_lines))

    return sub_hunks
