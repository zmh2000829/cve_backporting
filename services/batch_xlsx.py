"""XLSX export for batch-validate reports.

The writer intentionally uses only the Python standard library.  The generated
workbook is a small OOXML package with inline strings, filters, frozen headers,
and light row highlighting for the three questions batch validation usually
needs to answer: exact matches, level promotions, and failures.
"""

from collections import Counter
from datetime import datetime, timezone
import os
import re
from typing import Dict, Iterable, List, Optional, Tuple
from xml.sax.saxutils import escape
from zipfile import ZIP_DEFLATED, ZipFile

from core.output_serializers import PATCH_ACCEPTABLE_VERDICTS, build_l0_l5_view
from rules.level_policies import effective_level_floor, level_rank


DETAIL_HEADERS = [
    "CVE",
    "主补丁状态",
    "是否完全一致",
    "是否升级",
    "是否失败",
    "补丁判定",
    "核心相似度",
    "基线级别",
    "最终级别",
    "升级路径",
    "升级幅度",
    "升级规则",
    "DryRun方法",
    "Known Fix",
    "结果状态",
    "情报不足原因",
    "整套解集判定",
    "整套解集相似度",
    "前置补丁识别",
    "关键结构变更",
    "专项高风险",
    "关联补丁分桶",
    "直接回移状态",
    "关联补丁状态",
    "风险状态",
    "摘要/失败原因",
]

_ILLEGAL_XML_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _clean_text(value) -> str:
    if value is None:
        return ""
    text = str(value)
    return _ILLEGAL_XML_RE.sub("", text)


def _xml_text(value) -> str:
    return escape(_clean_text(value), {"\"": "&quot;"})


def _column_name(index: int) -> str:
    name = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        name = chr(65 + remainder) + name
    return name


def _cell_ref(row_index: int, column_index: int) -> str:
    return f"{_column_name(column_index)}{row_index}"


def _percent(value) -> str:
    try:
        return f"{float(value):.1%}"
    except (TypeError, ValueError):
        return ""


def _yes_no(value: bool) -> str:
    return "是" if value else "否"


def _short_commit(value: str) -> str:
    value = str(value or "")
    return value[:12] if len(value) > 12 else value


def _status_from_verdict(verdict: str, deterministic_exact: bool, result_state: str) -> str:
    if result_state == "error" or verdict == "error":
        return "执行异常"
    if deterministic_exact or verdict == "identical":
        return "完全一致"
    if verdict == "essentially_same":
        return "本质相同"
    if verdict == "partially_same":
        return "部分一致"
    if verdict == "no_data":
        return "无数据"
    return "失败"


def _promotion_rules(result: dict, base_level: str) -> str:
    base_rank = level_rank(base_level)
    level_decision = result.get("level_decision") or {}
    rules = []
    for hit in level_decision.get("rule_hits", []) or []:
        if not isinstance(hit, dict):
            continue
        floor = effective_level_floor(hit)
        if level_rank(floor) <= base_rank:
            continue
        rule_id = hit.get("rule_id") or hit.get("id") or "unknown"
        rules.append(f"{rule_id}->{floor}")
    return ", ".join(rules[:8])


def _prereq_cell(result: dict) -> str:
    prereq = result.get("prereq_cross_validation") or {}
    known = prereq.get("known_prereqs")
    matched = prereq.get("matched")
    if known is not None and matched is not None:
        recall = prereq.get("recall")
        suffix = f" ({_percent(recall)})" if recall is not None else ""
        return f"{matched}/{known}{suffix}"
    tool_prereqs = result.get("tool_prereqs") or []
    if tool_prereqs:
        return f"工具建议 {len(tool_prereqs)} 个"
    return ""


def _extract_special_risk(result: dict) -> Tuple[bool, str]:
    validation_details = result.get("validation_details") or {}
    special = (validation_details.get("special_risk_report") or {}).get("summary") or {}
    sections = special.get("triggered_sections") or []
    return bool(special.get("has_critical_structure_change")), ", ".join(str(item) for item in sections)


def _extract_conclusion_statuses(result: dict) -> Tuple[str, str, str]:
    conclusion = ((result.get("analysis_framework") or {}).get("conclusion") or {})
    return (
        (conclusion.get("direct_backport") or {}).get("status", ""),
        (conclusion.get("prerequisite") or {}).get("status", ""),
        (conclusion.get("risk") or {}).get("status", ""),
    )


def build_batch_validate_xlsx_rows(results: Iterable[dict]) -> List[Dict]:
    """Return normalized row dictionaries used by the XLSX exporter."""
    rows = []
    for result in results or []:
        if not isinstance(result, dict):
            continue
        generated = result.get("generated_vs_real") or {}
        solution_set = result.get("solution_set_vs_real") or {}
        dryrun = result.get("dryrun_detail") or {}
        result_status = result.get("result_status") or {}
        result_state = result_status.get("state") or ("error" if generated.get("verdict") == "error" else "complete")
        verdict = generated.get("verdict") or "no_data"
        deterministic_exact = bool(generated.get("deterministic_exact_match"))
        patch_status = _status_from_verdict(verdict, deterministic_exact, result_state)
        level_view = build_l0_l5_view(result)
        base_level = level_view.get("base_level", "")
        current_level = level_view.get("current_level", "")
        promoted = bool(base_level and current_level and level_rank(current_level) > level_rank(base_level))
        failed = verdict not in PATCH_ACCEPTABLE_VERDICTS or result_state == "error"
        critical_structure, special_sections = _extract_special_risk(result)
        direct_status, prereq_status, risk_status = _extract_conclusion_statuses(result)
        upgrade_path = f"{base_level}->{current_level}" if base_level and current_level and promoted else ""
        upgrade_delta = level_rank(current_level) - level_rank(base_level) if promoted else 0
        row = {
            "CVE": result.get("cve_id", ""),
            "主补丁状态": patch_status,
            "是否完全一致": _yes_no(patch_status == "完全一致"),
            "是否升级": _yes_no(promoted),
            "是否失败": _yes_no(failed),
            "补丁判定": verdict,
            "核心相似度": _percent(generated.get("core_similarity")) if verdict not in ("no_data", "error") else "",
            "基线级别": base_level,
            "最终级别": current_level,
            "升级路径": upgrade_path,
            "升级幅度": upgrade_delta if promoted else "",
            "升级规则": _promotion_rules(result, base_level) if promoted else "",
            "DryRun方法": dryrun.get("apply_method", ""),
            "Known Fix": _short_commit(result.get("known_fix", "")),
            "结果状态": result_state,
            "情报不足原因": result_status.get("incomplete_reason", ""),
            "整套解集判定": solution_set.get("verdict", ""),
            "整套解集相似度": _percent(solution_set.get("core_similarity")) if solution_set else "",
            "前置补丁识别": _prereq_cell(result),
            "关键结构变更": _yes_no(critical_structure),
            "专项高风险": special_sections,
            "关联补丁分桶": level_view.get("dependency_bucket", ""),
            "直接回移状态": direct_status,
            "关联补丁状态": prereq_status,
            "风险状态": risk_status,
            "摘要/失败原因": result.get("summary", "") or result_status.get("user_message", ""),
            "_is_exact": patch_status == "完全一致",
            "_is_promoted": promoted,
            "_is_failed": failed,
        }
        rows.append(row)
    return rows


def _row_values(row: dict) -> List:
    return [row.get(header, "") for header in DETAIL_HEADERS]


def _summary_rows(target: str, rows: List[Dict], batch_summary: Optional[dict], generated_at: str) -> List[List]:
    total = len(rows)
    exact = sum(1 for row in rows if row.get("_is_exact"))
    promoted = sum(1 for row in rows if row.get("_is_promoted"))
    failed = sum(1 for row in rows if row.get("_is_failed"))
    acceptable = sum(1 for row in rows if not row.get("_is_failed"))
    verdicts = Counter(row.get("补丁判定", "no_data") for row in rows)
    levels = Counter(row.get("最终级别", "") for row in rows if row.get("最终级别"))

    summary = [
        ["指标", "值", "说明"],
        ["目标分支", target, ""],
        ["生成时间", generated_at, ""],
        ["样本总数", total, "本次 batch-validate 产生的 CVE 结果数"],
        ["完全一致", exact, "主补丁状态为完全一致"],
        ["可接受补丁", acceptable, "补丁判定 in {identical, essentially_same}"],
        ["有升级", promoted, "最终级别高于 DryRun 基线级别"],
        ["失败", failed, "补丁判定不在可接受集合，或结果状态为 error"],
    ]
    if total:
        summary.extend([
            ["完全一致率", f"{exact / total:.1%}", ""],
            ["升级率", f"{promoted / total:.1%}", ""],
            ["失败率", f"{failed / total:.1%}", ""],
        ])

    summary.append([])
    summary.append(["补丁判定分布", "数量", ""])
    for verdict, count in sorted(verdicts.items()):
        summary.append([verdict, count, f"{count / total:.1%}" if total else ""])

    summary.append([])
    summary.append(["最终级别分布", "数量", ""])
    for level in [f"L{i}" for i in range(6)]:
        count = levels.get(level, 0)
        summary.append([level, count, f"{count / total:.1%}" if total else ""])

    promotion_summary = (batch_summary or {}).get("promotion_summary") or {}
    promotion_matrix = promotion_summary.get("promotion_matrix") or {}
    if promotion_matrix:
        summary.append([])
        summary.append(["升级路径分布", "数量", ""])
        for path, count in sorted(promotion_matrix.items()):
            summary.append([path, count, ""])

    return summary


def _detail_rows(rows: List[Dict]) -> List[List]:
    return [DETAIL_HEADERS] + [_row_values(row) for row in rows]


def _workbook_xml(sheet_names: List[str]) -> str:
    sheets = []
    for index, name in enumerate(sheet_names, 1):
        sheets.append(f'<sheet name="{_xml_text(name)}" sheetId="{index}" r:id="rId{index}"/>')
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        "<sheets>"
        + "".join(sheets)
        + "</sheets></workbook>"
    )


def _workbook_rels(sheet_count: int) -> str:
    rels = [
        f'<Relationship Id="rId{index}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        f'Target="worksheets/sheet{index}.xml"/>'
        for index in range(1, sheet_count + 1)
    ]
    rels.append(
        f'<Relationship Id="rId{sheet_count + 1}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(rels)
        + "</Relationships>"
    )


def _content_types(sheet_count: int) -> str:
    overrides = [
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
        '<Override PartName="/xl/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>',
        '<Override PartName="/docProps/core.xml" '
        'ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>',
        '<Override PartName="/docProps/app.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>',
    ]
    for index in range(1, sheet_count + 1):
        overrides.append(
            f'<Override PartName="/xl/worksheets/sheet{index}.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        + "".join(overrides)
        + "</Types>"
    )


def _root_rels() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>'
        '<Relationship Id="rId2" '
        'Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" '
        'Target="docProps/core.xml"/>'
        '<Relationship Id="rId3" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" '
        'Target="docProps/app.xml"/>'
        "</Relationships>"
    )


def _styles_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="2">'
        '<font><sz val="11"/><name val="Calibri"/></font>'
        '<font><b/><sz val="11"/><name val="Calibri"/><color rgb="FFFFFFFF"/></font>'
        '</fonts>'
        '<fills count="6">'
        '<fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FF4472C4"/><bgColor indexed="64"/></patternFill></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FFE2F0D9"/><bgColor indexed="64"/></patternFill></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FFFFF2CC"/><bgColor indexed="64"/></patternFill></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FFF4CCCC"/><bgColor indexed="64"/></patternFill></fill>'
        '</fills>'
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="5">'
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>'
        '<xf numFmtId="0" fontId="0" fillId="3" borderId="0" xfId="0" applyFill="1"/>'
        '<xf numFmtId="0" fontId="0" fillId="4" borderId="0" xfId="0" applyFill="1"/>'
        '<xf numFmtId="0" fontId="0" fillId="5" borderId="0" xfId="0" applyFill="1"/>'
        '</cellXfs>'
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        '<dxfs count="0"/><tableStyles count="0" defaultTableStyle="TableStyleMedium2" defaultPivotStyle="PivotStyleLight16"/>'
        '</styleSheet>'
    )


def _doc_props_core(created_at: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" '
        'xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:dcmitype="http://purl.org/dc/dcmitype/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        '<dc:creator>cve_backporting</dc:creator>'
        '<cp:lastModifiedBy>cve_backporting</cp:lastModifiedBy>'
        f'<dcterms:created xsi:type="dcterms:W3CDTF">{_xml_text(created_at)}</dcterms:created>'
        f'<dcterms:modified xsi:type="dcterms:W3CDTF">{_xml_text(created_at)}</dcterms:modified>'
        '</cp:coreProperties>'
    )


def _doc_props_app(sheet_names: List[str]) -> str:
    titles = "".join(f"<vt:lpstr>{_xml_text(name)}</vt:lpstr>" for name in sheet_names)
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" '
        'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
        '<Application>cve_backporting</Application>'
        f'<HeadingPairs><vt:vector size="2" baseType="variant"><vt:variant><vt:lpstr>Worksheets</vt:lpstr></vt:variant><vt:variant><vt:i4>{len(sheet_names)}</vt:i4></vt:variant></vt:vector></HeadingPairs>'
        f'<TitlesOfParts><vt:vector size="{len(sheet_names)}" baseType="lpstr">{titles}</vt:vector></TitlesOfParts>'
        '</Properties>'
    )


def _cell_xml(row_index: int, column_index: int, value, style: int = 0) -> str:
    ref = _cell_ref(row_index, column_index)
    style_attr = f' s="{style}"' if style else ""
    if value is None or value == "":
        return f'<c r="{ref}"{style_attr}/>'
    if isinstance(value, bool):
        return f'<c r="{ref}" t="b"{style_attr}><v>{1 if value else 0}</v></c>'
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f'<c r="{ref}"{style_attr}><v>{value}</v></c>'
    return f'<c r="{ref}" t="inlineStr"{style_attr}><is><t>{_xml_text(value)}</t></is></c>'


def _row_xml(row_index: int, values: list, style: int = 0) -> str:
    cells = "".join(_cell_xml(row_index, column_index, value, style) for column_index, value in enumerate(values, 1))
    return f'<row r="{row_index}">{cells}</row>'


def _column_widths(rows: List[List]) -> str:
    if not rows:
        return ""
    max_columns = max(len(row) for row in rows)
    cols = []
    for index in range(1, max_columns + 1):
        max_len = 8
        for row in rows[:200]:
            if index - 1 >= len(row):
                continue
            value = _clean_text(row[index - 1])
            max_len = max(max_len, min(len(value) + 2, 60))
        width = max(10, min(max_len, 60))
        cols.append(f'<col min="{index}" max="{index}" width="{width}" customWidth="1"/>')
    return "<cols>" + "".join(cols) + "</cols>"


def _sheet_xml(rows: List[List], row_styles: Optional[List[int]] = None, freeze_header: bool = True) -> str:
    row_styles = row_styles or []
    sheet_rows = []
    for row_index, values in enumerate(rows, 1):
        style = row_styles[row_index - 1] if row_index - 1 < len(row_styles) else 0
        if row_index == 1 and values:
            style = 1
        sheet_rows.append(_row_xml(row_index, values, style))

    max_columns = max((len(row) for row in rows), default=1)
    max_rows = max(len(rows), 1)
    dimension = f"A1:{_cell_ref(max_rows, max_columns)}"
    auto_filter = f'<autoFilter ref="A1:{_cell_ref(max_rows, max_columns)}"/>' if rows and len(rows) > 1 else ""
    freeze = (
        '<sheetViews><sheetView workbookViewId="0">'
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
        '</sheetView></sheetViews>'
        if freeze_header and rows
        else ""
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<dimension ref="{dimension}"/>'
        + freeze
        + _column_widths(rows)
        + "<sheetData>"
        + "".join(sheet_rows)
        + "</sheetData>"
        + auto_filter
        + "</worksheet>"
    )


def _detail_row_styles(rows: List[Dict]) -> List[int]:
    styles = [1]
    for row in rows:
        if row.get("_is_failed"):
            styles.append(4)
        elif row.get("_is_promoted"):
            styles.append(3)
        elif row.get("_is_exact"):
            styles.append(2)
        else:
            styles.append(0)
    return styles


def _safe_sheet_name(name: str, used: set) -> str:
    cleaned = re.sub(r"[\[\]:*?/\\]", "_", name).strip() or "Sheet"
    cleaned = cleaned[:31]
    candidate = cleaned
    suffix = 1
    while candidate in used:
        tail = f"_{suffix}"
        candidate = cleaned[: 31 - len(tail)] + tail
        suffix += 1
    used.add(candidate)
    return candidate


def write_batch_validate_xlsx(path: str, results: Iterable[dict], target: str, *, batch_summary: Optional[dict] = None,
                              generated_at: Optional[str] = None) -> str:
    """Write a batch-validate workbook and return the output path."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    generated_at = generated_at or datetime.now().astimezone().isoformat(timespec="seconds")
    created_utc = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    rows = build_batch_validate_xlsx_rows(results)
    exact_rows = [row for row in rows if row.get("_is_exact")]
    promoted_rows = [row for row in rows if row.get("_is_promoted")]
    failed_rows = [row for row in rows if row.get("_is_failed")]

    used_names = set()
    sheets = [
        (_safe_sheet_name("总览", used_names), _summary_rows(target, rows, batch_summary, generated_at), None),
        (_safe_sheet_name("全部明细", used_names), _detail_rows(rows), _detail_row_styles(rows)),
        (_safe_sheet_name("完全一致", used_names), _detail_rows(exact_rows), _detail_row_styles(exact_rows)),
        (_safe_sheet_name("有升级", used_names), _detail_rows(promoted_rows), _detail_row_styles(promoted_rows)),
        (_safe_sheet_name("失败", used_names), _detail_rows(failed_rows), _detail_row_styles(failed_rows)),
    ]
    sheet_names = [sheet[0] for sheet in sheets]

    with ZipFile(path, "w", ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _content_types(len(sheets)))
        zf.writestr("_rels/.rels", _root_rels())
        zf.writestr("xl/workbook.xml", _workbook_xml(sheet_names))
        zf.writestr("xl/_rels/workbook.xml.rels", _workbook_rels(len(sheets)))
        zf.writestr("xl/styles.xml", _styles_xml())
        zf.writestr("docProps/core.xml", _doc_props_core(created_utc))
        zf.writestr("docProps/app.xml", _doc_props_app(sheet_names))
        for index, (_name, sheet_rows, styles) in enumerate(sheets, 1):
            zf.writestr(f"xl/worksheets/sheet{index}.xml", _sheet_xml(sheet_rows, styles))

    return path
