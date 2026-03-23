<p align="center">
  <img src="https://img.shields.io/badge/CVE-Backporting-0d1117?style=for-the-badge&logo=linux&logoColor=white&labelColor=FCC624" alt="CVE Backporting" height="36">
</p>

<h1 align="center">CVE Backporting Engine</h1>

<p align="center">
  <strong>Automated CVE Patch Analysis & Backporting for Enterprise Linux Kernels</strong>
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License"></a>
  <a href="docs/TECHNICAL.md"><img src="https://img.shields.io/badge/Docs-Technical-blue?style=for-the-badge" alt="Docs"></a>
  <a href="docs/ADAPTIVE_DRYRUN.md"><img src="https://img.shields.io/badge/Algo-Multi--Level%20DryRun-orange?style=for-the-badge" alt="Algorithm"></a>
</p>

<p align="center">
  <em>One command — from CVE ID to deployable backport strategy.</em>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="docs/TECHNICAL.md">Technical Docs</a> ·
  <a href="docs/ADAPTIVE_DRYRUN.md">Algorithm Deep-Dive</a> ·
  <a href="docs/MULTI_LEVEL_ALGORITHM.md">Multi-Level Algorithm</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#benchmarks">Benchmarks</a>
</p>

---

**CVE Backporting Engine** is an end-to-end automated pipeline for analyzing, locating, and backporting Linux kernel CVE security patches to enterprise-maintained downstream kernel branches. It combines multi-source intelligence gathering, multi-level commit search, hunk-level dependency analysis, and a **five-level adaptive dry-run engine** to deliver actionable backport strategies — with optional AI-assisted patch generation.

If you maintain a long-term enterprise Linux kernel and need to efficiently triage and backport upstream CVE fixes, this is the tool.

---

## Why This Tool?

| Traditional Manual Workflow | CVE Backporting Engine |
|:--------------------------|:----------------------|
| Manually search MITRE, googlesource, mailing lists, compare commits one by one | **Crawler Agent** auto-aggregates multi-source intelligence with 3-level fallback |
| `git log --grep` then visually compare subjects | **3-Level Search Engine** (ID → Subject → Diff) with quantified confidence scores |
| Enterprise squash commits break traditional diff comparison completely | **Diff Containment Algorithm** — multiset-based unidirectional containment detection |
| Cross-version path renames (`fs/cifs/` → `fs/smb/client/`) cause search blind spots | **PathMapper** — bidirectional path translation across 8+ known subsystem migrations |
| Multi-million commit repos make `git log` take minutes | **SQLite + FTS5 cache** with incremental updates, daily sync in seconds |
| Uncertain whether prerequisite patches are needed before cherry-pick | **Hunk-level dependency analysis** with strong/medium/weak 3-tier grading |
| `git apply` fails with cryptic errors, no guidance on resolution | **Multi-Level Adaptive DryRun** — from strict apply to verified-direct to AI-assisted |
| Analysis results are opaque, developers can't understand the reasoning | **Analysis Narrative** — structured JSON explanation of every decision step |

---

## Key Innovations

### Multi-Level Adaptive DryRun Engine

The core innovation — a progressive fallback architecture that maximizes automatic patch adaptation:

```
Patch Input
  │
  ├─ L0:   Strict ──────────── Exact context match (git apply --check)
  ├─ L1:   Context-C1 ──────── Relaxed context (git apply -C1)
  ├─ L2:   3-Way Merge ─────── Three-way merge with base blob
  ├─ L5:   Verified-Direct ─── ⭐ In-memory file modification, bypass git apply
  ├─ L3:   Regenerated ─────── Anchor-line positioning + context rebuild
  ├─ L3.5: Zero-Context ────── Minimal diff with --unidiff-zero
  ├─ L4:   Conflict-Adapted ── Hunk-level conflict analysis + adaptation
  └─ L6:   AI-Generated ────── 🤖 LLM-assisted patch generation (optional)
```

**Level 5 (Verified-Direct)** — the newest breakthrough — bypasses `git apply` entirely:
- **In-Memory Modification** — Reads target file, locates hunks, applies changes directly in Python
- **Symbol/Macro Mapping** — Auto-detects renamed macros/constants across codebase versions
- **Indentation Adaptation** — Matches target file's whitespace style (tabs/spaces/width)

**Level 3 (Regenerated)** introduces three core algorithms:
- **Anchor-Line Positioning** — Single-line search immune to context sequence interruption by injected enterprise code
- **Line-by-Line Voting** — Statistical mode-based sequence positioning using per-line position estimates
- **Cross-Hunk Offset Propagation** — Accumulated offset from prior hunks improves subsequent search precision

### Multi-Dimensional Code Semantic Matching

When all context-based strategies fail, **Level 8** strategy triggers semantic matching:

$$\text{score} = 0.5 \times S_{\text{structure}} + 0.3 \times S_{\text{identifier}} + 0.2 \times S_{\text{keyword}}$$

Combines edit-distance structural similarity, identifier set Jaccard coefficient, and keyword sequence matching — independent of context continuity.

### Diff Containment Algorithm

Purpose-built for enterprise kernels where multiple upstream patches are squashed into single commits:

```
Community Patch (3 lines)          Enterprise Commit (200 lines)
  +line_a                            +unrelated_1
  +line_b              ──────►       +line_a    ✓
  -line_c                            +line_b    ✓
                                     -line_c    ✓
                                     +unrelated_2

  Containment: 100% (3/3)    vs    Similarity: ~30% (traditional fails)
```

### Closed-Loop Validation Framework

Non-destructive `git worktree`-based regression testing: auto-creates pre-fix snapshots, runs full pipeline, compares against ground truth, outputs Precision/Recall/F1 metrics with optional LLM root-cause analysis.

### Analysis Narrative — Developer-Friendly Explanations

Every `validate`, `batch-validate`, and `analyze` JSON output now includes an `analysis_narrative` field containing structured human-readable descriptions of:
- **workflow** — Step-by-step trace of what the tool did (CVE info → patch fetch → intro/fix detection → dependency → DryRun)
- **prerequisite_analysis** — Whether prerequisite patches are needed and why
- **patch_applicability** — Why the patch can (or cannot) be directly applied, which DryRun level succeeded
- **patch_quality_assessment** — How the generated patch compares to the real fix (validate mode)
- **developer_action** — Actionable next steps for the developer

### L0-L5 Strategy Orchestration + Pluggable Rules (NEW)

The engine now classifies each run into **L0-L5 merge-risk scenarios** and emits auditable evidence:

- **L0 (strict)**: exact context match, only this level can be marked as "harmless"
- **L1 (ignore-ws/context-C1)**: light context drift, can be harmless only after rule checks
- **L2 (3-way)**: medium merge complexity
- **L3 (regenerated)**: context rebuilt, requires focused review
- **L4 (conflict-adapted)**: conflict adaptation, manual semantic review required
- **L5 (verified-direct / advanced path)**: robust fallback, low confidence by default

Rule engine highlights:
- **Large change warning** (changed lines / hunk count thresholds)
- **Call-chain impact warning** (caller/callee fanout)
- **Critical structure warning** (lock/RCU/refcount/struct-sensitive changes)
- **Pluggable extension** via `policy.extra_rule_modules`

Validate output now includes:
- `level_decision` (level, harmless, confidence, reason, rule hits)
- `function_impacts` (callers/callees/impact score)
- `dryrun_detail.apply_attempts` (full strategy attempt trace)
- `validation_details` (workflow steps + warning summary)

---

## Architecture

```
                        ┌──────────────────────┐
                        │   Pipeline Orchestrator│
                        └──────────┬───────────┘
               ┌───────────┬───────┴───────┬────────────┐
               ▼           ▼               ▼            ▼
          ┌─────────┐ ┌──────────┐ ┌────────────┐ ┌──────────┐
          │ Crawler  │ │ Analysis │ │ Dependency  │ │  DryRun  │
          │  Agent   │ │  Agent   │ │   Agent     │ │  Agent   │
          └────┬─────┘ └────┬─────┘ └─────┬──────┘ └────┬─────┘
               │            │             │              │
          MITRE API    3-Level Search  Hunk-Level    Multi-Level
          git.kernel   ID→Subject→Diff  Overlap     Adaptive
          googlesource SequenceMatcher  Analysis    DryRun
                       FTS5 Index      Scoring      Engine
```

### Agent Responsibilities

| Agent | Input | Output | Key Algorithm |
|-------|-------|--------|---------------|
| **Crawler** | CVE ID | `CveInfo` + `PatchInfo` | 3-level source fallback + partial merge |
| **Analysis** | Patch + Target repo | `SearchResult` | L1 exact ID → L2 subject → L3 diff/containment |
| **Dependency** | Fix patch + Intro search | `List[PrerequisitePatch]` | Hunk overlap + function overlap + 3-tier grading |
| **DryRun** | Patch + Target repo | `DryRunResult` | Multi-level adaptive + verified-direct + anchor positioning + semantic match |

---

## Capabilities

### `analyze` — Full CVE Analysis Pipeline

End-to-end: intelligence → intro detection → fix location → dependency → dry-run. Output JSON includes `analysis_narrative` with developer-friendly explanations of every analysis step.

```bash
python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk
```

### `check-intro` — Vulnerability Introduction Detection

Determines if the vulnerability-introducing commit exists in your kernel.

```bash
python cli.py check-intro --cve CVE-2024-26633 --target 5.10-hulk
```

### `check-fix` — Fix Patch Detection

Determines if the fix has already been merged, with clear "fixed / needs backport" verdict.

```bash
python cli.py check-fix --cve CVE-2024-26633 --target 5.10-hulk
```

### `validate` — Tool Accuracy Verification

Rolls back to pre-fix state via `git worktree`, runs pipeline, compares against ground truth. Output JSON includes `analysis_narrative` with detailed step-by-step explanations for developers.

```bash
# Basic usage
python cli.py validate \
  --cve CVE-2024-26633 --target 5.10-hulk \
  --known-fix da23bd709b46

# Provide mainline fix commit directly (skips MITRE crawl)
python cli.py validate \
  --cve CVE-2024-26633 --target 5.10-hulk \
  --known-fix da23bd709b46 \
  --mainline-fix <community_fix_commit_id>

# Also provide mainline introduced commit
python cli.py validate \
  --cve CVE-2024-26633 --target 5.10-hulk \
  --known-fix da23bd709b46 \
  --mainline-fix <fix_commit> --mainline-intro <intro_commit>
```

### `batch-validate` — Batch Patch Accuracy Assessment

Loads CVE data from a JSON file (containing `hulk_fix_patchs` with known fix commits), runs `validate` for each CVE, and generates an aggregate patch generation accuracy report.

```bash
# Validate all CVEs in the JSON file
python cli.py batch-validate --file cve_data.json --target 5.10-hulk

# Validate the first 10 CVEs only
python cli.py batch-validate --file cve_data.json --target 5.10-hulk --limit 10
```

**JSON input format** — top-level dict keyed by CVE ID:

```json
{
  "CVE-2025-40110": {
    "cve_id": "CVE-2025-40110",
    "hulk_fix_patchs": [
      {
        "commit": "7745ad3f72ea9bc8671f95a08ba34b4d2cbb4322",
        "subject": "[Backport] drm/vmwgfx: Fix a null-ptr access"
      }
    ]
  }
}
```

**Output**:
- **Real-time JSON report** (`batch_validate_*.json`) — updated after each CVE, includes `progress`, `passed`, `failed`, `errors` lists with reasons
- **Full JSON report** (`batch_validate_*_full.json`) — final aggregate metrics with per-CVE detail
- **TUI summary** — patch accuracy rate, average core similarity, verdict distribution, DryRun method distribution, per-CVE table
- **Analysis Narrative** — each CVE entry includes `analysis_narrative` with human-readable workflow, prerequisite analysis, applicability, and developer action suggestions

Mainline fix/intro commits from JSON (`mainline_fix_patchs`, `mainline_import_patchs`) are used directly, skipping MITRE crawl. Entries that fail parsing or cause runtime errors are automatically skipped without affecting the overall batch.

### `benchmark` — Batch Accuracy Assessment (YAML)

Runs validation on a YAML-defined CVE suite, outputs aggregate metrics.

```bash
python cli.py benchmark --file benchmarks.yaml --target 5.10-hulk
```

### `build-cache` — Commit Cache Construction

Builds SQLite + FTS5 index for multi-million commit repos. Supports incremental updates.

```bash
python cli.py build-cache --target 5.10-hulk          # incremental (default)
python cli.py build-cache --target 5.10-hulk --full    # full rebuild
```

---

## <a name="quick-start"></a>Quick Start

**Runtime**: Python 3.8+

```bash
# Install dependencies
pip install -r requirements.txt

# Configure repository path
# Edit config.yaml:
#   repositories:
#     "5.10-hulk":
#       path: "/path/to/linux"
#       branch: "linux-5.10.y"

# Build commit cache (one-time, incremental updates afterward)
python cli.py build-cache --target 5.10-hulk

# Analyze a CVE
python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk
```

---

## <a name="benchmarks"></a>Performance

| Metric | Value | Notes |
|--------|-------|-------|
| Supported repo scale | 10M+ commits | SQLite + FTS5 + WAL + mmap |
| Single CVE analysis | 15-30s | Including network requests |
| Cache sync (incremental) | < 5s | Auto-detects rebase, falls back to full |
| Hunk positioning (avg) | < 100ms | Anchor-line + offset propagation |
| Search coverage | L1 + L2 + L3 | ID → Subject → Diff/Containment |
| Path mappings | 8+ built-in | Extensible via config |
| DryRun strategies | 7+ levels | Strict → C1 → 3way → Verified-Direct → Regen → Zero-Ctx → Adapted |
| Validation framework | P/R/F1 | git worktree non-destructive rollback |

---

## Project Structure

```
cve_backporting/
├── core/                          # Infrastructure Layer
│   ├── models.py                  #   Data models (CveInfo, PatchInfo, DryRunResult, ...)
│   ├── config.py                  #   YAML configuration loader
│   ├── git_manager.py             #   Git operations + SQLite/FTS5 cache engine
│   ├── matcher.py                 #   Similarity algorithms + PathMapper
│   ├── code_matcher.py            #   Code semantic matching (Level 8)
│   ├── search_report.py           #   Detailed search process reports
│   ├── ai_patch_generator.py      #   AI-assisted patch generation (Level 5)
│   ├── function_analyzer.py       #   C function definition + call chain analysis
│   ├── llm_analyzer.py            #   LLM-powered root cause analysis
│   └── ui.py                      #   Rich TUI components
├── agents/                        # Core Agent Layer
│   ├── crawler.py                 #   Crawler Agent — CVE intelligence + patch retrieval
│   ├── analysis.py                #   Analysis Agent — 3-level commit search
│   ├── dependency.py              #   Dependency Agent — prerequisite analysis
│   └── dryrun.py                  #   DryRun Agent — multi-level adaptive engine
├── pipeline.py                    # Pipeline Orchestrator
├── cli.py                         # CLI entry point
├── config.yaml                    # Configuration
├── benchmarks.example.yaml        # Benchmark suite example
├── requirements.txt
├── tests/
│   └── test_agents.py
└── docs/
    ├── TECHNICAL.md               # Complete technical documentation
    ├── ADAPTIVE_DRYRUN.md         # 5-level adaptive algorithm deep-dive
    └── MULTI_LEVEL_ALGORITHM.md   # Multi-level algorithm detailed reference
```

---

## Algorithm Highlights

### 1. Unidirectional Diff Containment

First application of multiset containment detection in CVE backport tooling — solves the squash commit matching problem that defeats traditional bidirectional similarity.

### 2. Verified-Direct Patch Application (L5)

Bypasses `git apply` entirely — reads target file content, locates hunks using anchor-line strategies, applies symbol mapping (macro/constant renames) and indentation adaptation, then performs in-memory modification. Generates clean unified diff via `difflib.unified_diff`. Solves cases where `git apply` rejects patches due to whitespace or context differences that are semantically irrelevant.

### 3. Two-Layer Hunk Positioning Architecture

**Layer 1**: Anchor-line positioning — single-line search immune to context interruption.
**Layer 2**: Seven-strategy sequence search — exact → function-name → line-window → fuzzy → context-retry → voting → longest-line.
**Cross-validation**: After finding a candidate position, `ctx_after` content is verified against actual file content to reject false matches when anchor lines (e.g. `spin_unlock(ptl)`) appear multiple times.

### 4. Direct-Read Patch Reconstruction

Reads context directly from target file at the located change point — eliminates alignment drift caused by walking hunk_lines with injected extra lines.

### 5. Cross-Hunk Offset Propagation

Accumulated positioning offset from earlier hunks automatically refines search hints for later hunks in the same file.

### 6. Closed-Loop Validation

`git worktree`-based non-destructive rollback, Precision/Recall/F1 quantification, optional LLM root-cause analysis for failures.

### 7. Cross-Version Path Mapping

Bidirectional path translation across search, comparison, and DryRun — resolves directory restructuring blind spots.

### 8. Code Semantic Matching

Multi-dimensional similarity (structure + identifiers + keywords) — independent of context sequence continuity.

---

## AI Integration

| Component | Technology | Purpose | Default |
|-----------|-----------|---------|---------|
| **Level 6: AI-Generated** | LLM (GPT-4o / DeepSeek / etc.) | Generate adapted patches when rules fail | Disabled |
| **LLM Root-Cause Analysis** | LLM | Analyze validation failures | Disabled |
| **Code Semantic Matching** | SequenceMatcher + Set ops | Multi-dimensional code similarity | Enabled (pure algorithm) |
| **Diff Containment** | Multiset counting | Detect patches in squash commits | Enabled (pure algorithm) |

Core algorithms (Level 0-5) are **fully deterministic** — no AI model inference, complete reproducibility and explainability. AI features (Level 6) are opt-in enhancements.

```yaml
# config.yaml — AI configuration
llm:
  enabled: true
  provider: "openai"
  api_key: ""                    # or LLM_API_KEY env var
  base_url: "https://api.openai.com/v1"
  model: "gpt-4o"

ai_patch_generation:
  enabled: false
```

---

## Documentation

| Document | Description |
|----------|-------------|
| **[TECHNICAL.md](docs/TECHNICAL.md)** | Complete architecture, algorithms, data models, agent specifications |
| **[ADAPTIVE_DRYRUN.md](docs/ADAPTIVE_DRYRUN.md)** | Multi-level adaptive DryRun engine — algorithm principles and formal specification |
| **[MULTI_LEVEL_ALGORITHM.md](docs/MULTI_LEVEL_ALGORITHM.md)** | Multi-level algorithm reference with mathematical foundations |

---

## Verified Test Cases

| CVE | Status | Verification Points |
|-----|--------|-------------------|
| CVE-2024-26633 | Fixed | L1 intro detection, L2 fix backport location |
| CVE-2025-40198 | N/A | Mainline identification accuracy (7 version mappings correct) |
| CVE-2024-50154 | Fixed | L1 intro + L2 fix + DryRun conflict detection |
| CVE-2024-26633 | Validated | Worktree rollback: fix detection ✔ intro L1 ✔ DryRun 3way ✔ |
| CVE-2025-40196 | Unfixed | Intro L2 ✔, stable backport auto-selection, DryRun 3way ✔ |

---

## Testing

```bash
python -m tests.test_agents                      # Full suite
python -m tests.test_agents CVE-2024-26633       # Single CVE
python -m tests.test_agents mainline             # Mainline identification
python -m tests.test_agents full CVE-2024-26633  # End-to-end with dry-run
```

---

## Known Limitations

1. L3 diff matching requires per-commit diff retrieval — slower with large candidate sets
2. Dependency analysis based on file/function overlap — cannot capture indirect data structure dependencies
3. `conflict-adapted` and `verified-direct` patches guarantee applicability but **require human review for semantic correctness**
4. MITRE API may lack structured affected data for older CVEs
5. Validation prerequisite comparison relies on ID/Subject matching — cannot cover pure code-semantic equivalence
6. L0-L2 (strict/C1/3way) success comparison uses community patch directly; L5/L3+ use regenerated patches

---

## Contributing

Issues and Pull Requests welcome.

---

## License

MIT License — see [LICENSE](LICENSE)

---

<p align="center">
  <strong>Built for Linux Kernel Security</strong>
  <br>
  <em>Deterministic algorithms. Optional AI. Full traceability.</em>
</p>
