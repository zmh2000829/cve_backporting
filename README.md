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
  <a href="plan.md">Roadmap</a> ·
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
  ├─ Strict ────────────────── Exact context match (git apply --check)
  ├─ Context-C1 ────────────── Relaxed context (git apply -C1)
  ├─ 3-Way Merge ───────────── Three-way merge with base blob
  ├─ Verified-Direct ───────── ⭐ In-memory file modification, bypass git apply
  ├─ Regenerated ───────────── Anchor-line positioning + context rebuild
  ├─ Zero-Context ──────────── Minimal diff with --unidiff-zero
  ├─ Conflict-Adapted ──────── Hunk-level conflict analysis + adaptation
  └─ AI-Generated ──────────── 🤖 LLM-assisted patch generation (optional)
```

**Verified-Direct** — the newest breakthrough — bypasses `git apply` entirely:
- **In-Memory Modification** — Reads target file, locates hunks, applies changes directly in Python
- **Symbol/Macro Mapping** — Auto-detects renamed macros/constants across codebase versions
- **Indentation Adaptation** — Matches target file's whitespace style (tabs/spaces/width)

**Regenerated** introduces three core algorithms:
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

### Process + Evidence + Conclusion Skeleton (NEW)

To make results easier to understand, `analyze`, `validate`, and `batch-validate` now expose a unified top-level `analysis_framework` block:

- `process` — what the engine checked, in which order, and what the base/final L0-L5 path was
- `evidence` — admission rules, veto rules, risk-profile rules, prerequisite patches, critical structure hits, and function-impact evidence
- `conclusion` — three user-facing answers:
  - can this patch be directly backported?
  - do prerequisite patches need to be considered?
  - is there a large-impact risk?

This block is designed to be the primary user-facing explanation layer. `L0-L5` remains available, but no longer needs to be the first thing users parse.

### L0-L5 Strategy Orchestration + Pluggable Rules (NEW)

The engine now separates:

- **DryRun baseline** (`level_decision.base_level` / `base_method`)
- **Final L0-L5 scenario** (`level_decision.level`)

The final scenario is no longer a raw `apply_method -> level` mapping. It is derived as:

- `DryRun baseline level`
- plus rule-driven **`level_floor` promotion**

This keeps the core DryRun algorithm unchanged while allowing a clean `strict-but-risky != L0` orchestration.

Default scenario meanings:

- **L0**: deterministic safe path; only exact-match baseline with **no** warning/high-risk rule promotions may be `harmless=true`
- **L1**: light context drift; enters **LLM/manual harmless review lane**, but is **not auto-harmless**
- **L2**: medium-risk merge/adaptation or large-change/call-chain warnings
- **L3**: semantic-sensitive changes, such as critical structures or regenerated context; focused review required
- **L4**: high-risk propagation, conflict adaptation, or critical changes spread along caller/callee chains; manual approval required
- **L5**: highest-difficulty escalation lane; expert takeover required

#### How To Read L0-L5 Correctly

`L0-L5` is not a raw line-count score and not an internal DryRun layer number.
It is an **operational review tier** derived from three signals together:

- **Applicability confidence**: how deterministic the DryRun baseline was
- **Prerequisite certainty**: whether related patches must be considered first
- **Semantic blast radius**: whether the change touches critical structures, state transitions, error paths, or caller/callee propagation

In other words:

- `strict != always L0`
- `L0 -> L5` must be read as a strict escalation ladder
- `single-line != low risk`

The final level should be read with:

```text
final_level = max(base_level, all rule-driven level_floor promotions)
```

This means the baseline says "how the patch applied", while the final level says
"how cautiously a maintainer should treat this backport result".

#### Deep Scenario Semantics

| Level | What it really means | Typical baseline | What must be true to stay here | Typical reasons to be here | Maintainer action |
|------|-----------------------|------------------|--------------------------------|----------------------------|-------------------|
| **L0** | Deterministic safe lane | `strict` | No warning/high-risk promotion, no strong/medium prerequisite evidence, no critical structure hit, no meaningful propagation, and no field/state/error-path semantic markers | Exact context match and stable semantics | Can be directly backported; keep only minimal regression validation |
| **L1** | Low-risk drift lane, not auto-safe | `ignore-ws` / `context-C1` / `C1-ignore-ws` | Drift is limited to nearby context/whitespace/minor textual movement; no hard veto rules | Small context drift, formatting drift, comment-only drift, logging text drift, equivalent macro alias, local variable rename | Run lightweight LLM/manual review before treating as harmless |
| **L2** | Caution lane for medium adaptation or medium warnings | `3way`, or L0/L1 promoted by rules | Core patch still looks structurally close, but evidence is no longer strong enough for low-level handling | Large diff warning, API-surface drift, error-path drift, fanout warning, medium prerequisite evidence | Do targeted hunk review and compare affected call sites / return paths |
| **L3** | Semantic-sensitive lane | `regenerated`, or lower baseline promoted upward | A critical semantic dimension is touched, or prerequisite certainty becomes blocking | Locking/lifetime/state-machine/struct-field changes, strong prerequisite requirement, regenerated context | Do focused code review plus subsystem-specific regression tests |
| **L4** | High-risk propagated lane | `conflict-adapted`, or critical changes promoted again | Critical semantic change is no longer local; it propagates or combines with hard veto signals | Critical structures plus caller/callee spread, conflict adaptation, stacked high-risk evidence | Require senior maintainer approval and explicit propagation review |
| **L5** | Highest-difficulty escalation lane | unknown or missing baseline, or any result the engine cannot stabilize into a lower lane | The engine can no longer keep the case in a controlled automated lane; this is the hardest tier to process safely | Unknown baseline, broken proof chain, missing intel, unresolved high-uncertainty path | Stop automatic landing, collect more evidence, and hand the case to a senior maintainer for full review |

Two important nuances:

- **L5 is the highest operational difficulty lane.**
  Whether the cause is broken proof, missing evidence, or stacked uncertainty, the
  maintainer should read `L5` as "this case is the hardest to land safely."
- **Zero-Context is an internal DryRun technique, not a user-facing final level.**
  Zero-context regeneration is folded into the `regenerated` family and therefore
  typically surfaces as final `L3` unless stronger promotions push it higher.

#### How This Connects To The Three User Questions

`L0-L5` should not replace the three user-facing answers. It synthesizes them.

- **Can this patch be directly backported?**
  Primarily answered by `analysis_framework.conclusion.direct_backport`
- **Do prerequisite patches need to be considered?**
  Primarily answered by `analysis_framework.conclusion.prerequisite`
- **Is there a large-impact semantic risk?**
  Primarily answered by `analysis_framework.conclusion.risk`

The level is the execution lane that results from combining those answers with the
DryRun proof quality. Real examples therefore look like:

- `base=L0`, `final=L4`: patch applies cleanly, but evidence shows prerequisite or propagation risk
- `prerequisite=independent`, `final=L5`: no related patch is required, but the engine still cannot keep the case in a lower controlled lane, so senior-maintainer takeover is required
- `single-line change`, `final=L3`: the textual change is small, but it touches state/locking/layout semantics

#### Reading Level Distributions

When evaluating `L0-L5` ratios in batch mode:

- A rise in `L3/L4` often means the engine is surfacing more semantic evidence, not that `git apply` got worse
- A rise in `L5` means more cases are ending in the highest-difficulty lane and therefore deserve immediate senior review
- The healthiest low-level distribution is not "maximum L0/L1", but "L0/L1 only when positive admission evidence is strong enough"

### CLI Policy Styles

The CLI now supports a direct profile override via `--policy-profile`. This flag overrides `policy.profile` from YAML for the current command only.

| CLI style | Parameter | Intended behavior | Large-change threshold | Large-hunk threshold | Call-chain fanout threshold | Recommended use |
| --- | --- | --- | --- | --- | --- | --- |
| Conservative | `--policy-profile conservative` | Promote earlier and keep more cases in human-review lanes | `40` lines | `4` hunks | `4` | Safety-first triage, release branches, sensitive subsystems |
| Balanced | `--policy-profile balanced` | Default tradeoff between false promotion and missed risk | `80` lines | `8` hunks | `6` | Daily analysis and routine validation |

Supported commands:

| Command | Example |
| --- | --- |
| `analyze` | `python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk --policy-profile conservative` |
| `validate` | `python cli.py validate --cve CVE-2024-26633 --target 5.10-hulk --known-fix da23bd709b46 --policy-profile balanced` |
| `batch-validate` | `python cli.py batch-validate --file cve_data.json --target 5.10-hulk --policy-profile conservative` |
| `benchmark` | `python cli.py benchmark --file benchmarks.yaml --target 5.10-hulk --policy-profile balanced` |

Rule engine highlights:
- Built-in Python rules now live in [rules/default_rules.py](/Users/junxiaoqiong/Workplace/cve_backporting/rules/default_rules.py)
- Built-in level policies now live in [rules/level_policies.py](/Users/junxiaoqiong/Workplace/cve_backporting/rules/level_policies.py)
- Rule config example now lives in [rules/policy.example.yaml](/Users/junxiaoqiong/Workplace/cve_backporting/rules/policy.example.yaml)
- Rules are now grouped into three classes:
  - `admission` — positive rules that support direct backport eligibility
  - `veto` — rules that block low-level/direct classification
  - `risk_profile` — rules that identify high-risk patterns such as locking, lifetime, state-machine, struct-field, and error-path changes
- **Large change warning**: changed lines / hunk count thresholds, promotes to at least `L2`
- **Call-chain propagation + fanout**: caller/callee impact inside the modified-file set, including cross-file edges
- **Critical structure warning**: lock/RCU/refcount/struct-sensitive changes, promotes to at least `L3`
- **Critical propagation**: critical changes that also spread along call chains promote to `L4`
- **L1 API surface** (`l1_api_surface`): signature-line add/remove mismatch, return-statement delta
- **L1 light drift samples** (`l1_light_drift_sample`): positive evidence for comment-only drift, logging text drift, equivalent macro aliases, and local-variable renames
- **Pluggable extension** via `policy.extra_rule_modules` with `register_rules(registry, config=None)`, `RULES`, `register_level_policies(...)`, or `LEVEL_POLICIES`

#### False-Positive Suppression For Level Inflation

The current rule set also includes explicit guardrails to reduce accidental `L3/L4`
promotion when the evidence is syntactic rather than semantic:

- **`critical_structures` is no longer triggered by every `struct` token.**
  Plain pointer/reference lines such as `struct foo *ctx` are not treated as
  layout risk. The rule now treats `struct` as critical only for struct-definition
  changes or layout-sensitive operations such as `sizeof`, `offsetof`, and `container_of`.
- **Call-chain propagation now filters pseudo-calls and member-access pseudo-calls.**
  Tokens such as `sizeof`, `likely`, `ARRAY_SIZE`, and `__builtin_*` are ignored, and
  expressions like `ops->helper()` or `obj.cb()` are not linked as normal symbol calls.
  Cross-file edges are only created for uniquely defined symbols, reducing false caller/callee spread.
- **`p2_state_machine_control_flow` now requires state semantics, not generic control flow.**
  A plain `if (ret) return -E...` change stays in the `error_path` lane unless the hunk
  also shows state fields, state constants, or real state-transition behavior.

This is not a relaxation of review standards. It is a tighter mapping between
evidence and conclusion, so `L3/L4` means "semantic risk really surfaced" rather than
"a broad pattern happened to match".

Regression now covers the three representative negative cases:

- plain `struct` pointer change should stay out of `critical_structures`
- `ops->helper()` should not create a call-chain edge to `helper`
- syntax-only error return changes should not trigger `p2_state_machine_control_flow`

#### Low-Level Admission And Dependency Evidence Tightening

This round also tightened the positive side of the policy:

- **`direct_backport_candidate` for L0 is stricter now.**
  A `strict` baseline is no longer enough by itself. The engine now also expects
  no prerequisite evidence, no propagation, no `special_risk` hit, and no field/state/error-path semantic markers before it says "direct backport candidate".
- **L1 now has positive low-drift samples instead of only vague review language.**
  `l1_light_drift_sample` records when the observed drift looks like comment-only changes,
  logging text changes, equivalent macro aliases, or local variable renames.
- **Prerequisite patches now carry semantic overlap evidence.**
  Dependency results expose shared fields, shared lock domains, shared state points,
  and supporting evidence lines, so "consider prerequisite patches" is no longer based
  only on hunk overlap and function overlap.

This improves all three user-facing questions:

- "Can this be directly backported?" now has a tighter L0 admission gate
- "Do prerequisite patches matter?" now has concrete field/lock/state evidence
- "Why is L1 still low-risk?" now has sample-based positive explanations

Validate output (`validation_details.rule_version` **v3**) includes:
- `level_decision` (`level`, `base_level`, `base_method`, `review_mode`, `next_action`, `harmless`, `confidence`, `reason`, `rule_hits`)
- `function_impacts` (callers/callees/impact score)
- `dryrun_detail.apply_attempts` (full strategy attempt trace)
- `validation_details` (workflow steps + warning summary + strategy buckets + `decision_skeleton`)
- `analysis_framework` (top-level process/evidence/conclusion skeleton)

Regression: `python -m unittest tests.test_policy_engine -v`

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

# Conservative safety-first lane
python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk --policy-profile conservative
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

# Force the conservative review style for this run only
python cli.py validate \
  --cve CVE-2024-26633 --target 5.10-hulk \
  --known-fix da23bd709b46 \
  --policy-profile conservative
```

### `batch-validate` — Batch Patch Accuracy Assessment

Loads CVE data from a JSON file (containing `hulk_fix_patchs` with known fix commits), runs `validate` for each CVE, and generates an aggregate patch generation accuracy report.

```bash
# Validate all CVEs in the JSON file
python cli.py batch-validate --file cve_data.json --target 5.10-hulk

# Validate the first 10 CVEs only
python cli.py batch-validate --file cve_data.json --target 5.10-hulk --limit 10

# Recommended parallel mode for a single local repo
python cli.py batch-validate --file cve_data.json --target 5.10-hulk --workers 2

# Batch validation with conservative promotion thresholds
python cli.py batch-validate --file cve_data.json --target 5.10-hulk --workers 2 --policy-profile conservative
```

Recommended usage:

- `--workers 1` is the safest default.
- `--workers 2` is the recommended setting for one local kernel repository.
- Do not start above `4`; after that, `git worktree` metadata, shared object storage, and disk I/O usually become the bottleneck.
- With `--deep`, keep `--workers` at `1` or `2`.
- Parallel batch validation is safe on a single local repo because each CVE runs in its own temporary `git worktree`; tasks do not share the same checked-out tree.

## `server` CLI and HTTP API

### Start API service

```bash
python cli.py server --host 127.0.0.1 --port 8000 --config config.yaml
```

- Shared options include `--host` (listen address, default `127.0.0.1`), `--port` (listen port, default `8000`), and `--config` (same config file used by CLI, default `config.yaml`).
- Route: `GET /health`
- Route: `POST /api/analyze`
- Route: `POST /api/analyzer` (compatibility alias)
- Route: `POST /api/validate`
- Route: `POST /api/batch-validate`

All successful responses follow:

```json
{
  "ok": true,
  "data": { ... }
}
```

Error responses use HTTP status `400`/`404`/`500` with:

```json
{
  "ok": false,
  "error": "error message"
}
```

### Common request fields

- Target repository: `target_version` (preferred) | `target` | `repo`
- `deep`: boolean, default `false`

### `POST /api/analyze` / `POST /api/analyzer`

Input body accepts:

```json
{
  "target_version": "5.10-hulk",
  "cve_id": "CVE-2024-26633",
  "deep": false,
  "no_dryrun": false
}
```

Or batch call in one request:

```json
{
  "target": "5.10-hulk",
  "cves": ["CVE-2024-26633", "CVE-2024-26634"],
  "cve_ids": ["CVE-2024-26635"],
  "deep": true
}
```

`cve_id`, `cves`, `cve_ids` are all accepted and merged by server.

Key response fields:

- `analysis_framework.process`
- `analysis_framework.evidence`
- `analysis_framework.conclusion`
- `level_decision`
- `validation_details`

### `POST /api/validate`

```json
{
  "target_version": "5.10-hulk",
  "cve_id": "CVE-2024-26633",
  "known_fix": "da23bd709b46",
  "known_prereqs": "abc111,def222",
  "mainline_fix": "aaabbb000111",
  "mainline_intro": "bbb222ccc333",
  "deep": false,
  "p2_enabled": true
}
```

`known_prereqs` can also be an array:

```json
{
  "known_prereqs": ["abc111", "def222"]
}
```

Key response fields:

- `analysis_framework.process`
- `analysis_framework.evidence`
- `analysis_framework.conclusion`
- `l0_l5.current_level`
- `l0_l5.base_level`
- `level_decision`
- `validation_details`

### `POST /api/batch-validate`

```json
{
  "target": "5.10-hulk",
  "deep": false,
  "workers": 2,
  "p2_enabled": true,
  "items": [
    {
      "cve_id": "CVE-2024-26633",
      "known_fix": "da23bd709b46",
      "known_prereqs": ["abc111"],
      "mainline_fix": "aaabbb000111",
      "mainline_intro": "bbb222ccc333"
    },
    {
      "cve_id": "CVE-2024-26634",
      "known_fix": "11aabbeff",
      "known_prereqs": "111,222"
    }
  ]
}
```

Response includes per-item result list and summary:

```json
{
  "ok": true,
  "data": {
    "operation": "batch-validate",
    "results": [],
    "errors": [],
    "summary": {
      "total": 0,
      "success": 0,
      "error": 0
    },
    "p2_enabled": true,
    "workers": 2,
    "parallel_mode": true,
    "l0_l5_summary": {
      "levels": ["L0", "L1", "L2", "L3", "L4", "L5"],
      "current_level_distribution": {},
      "base_level_distribution": {}
    },
    "batch_summary": {
      "l0_l5": {},
      "deterministic_exact_match": {
        "count": 0,
        "rate": 0.0
      },
      "critical_structure_change": {
        "count": 0,
        "rate": 0.0
      },
      "manual_prerequisite_analysis": {
        "count": 0,
        "rate": 0.0
      }
    }
  }
}
```

Each item inside `results` also contains:

- `analysis_framework`
- `l0_l5`
- `level_decision`
- `validation_details`

`workers` is optional for `/api/batch-validate`. Recommended values are the same as CLI:

- `1` for safest execution
- `2` recommended on a single local repository
- `<= 2` when `deep=true`

**JSON input format** — top-level dict keyed by CVE ID:

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
- **Special Risk Report** — `validation_details.special_risk_report` exposes the P2 locking/lifecycle/state-machine/field/error-path analysis used by both CLI and API

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

### `server` — HTTP API Gateway

Start the API service and call `analyze` / `validate` / `batch-validate` by URL.

```bash
python cli.py server --host 0.0.0.0 --port 8000
```

Available routes:

- `GET /health`
- `POST /api/analyze` (alias: `POST /api/analyzer`)
- `POST /api/validate`
- `POST /api/batch-validate`

Error responses are also actionable now. For `400/404/500`, the body includes:

- `route` — which endpoint failed
- `hint` — what the caller should fix next
- `missing_input` — required fields that were missing
- `suggested_fix` — a minimal request shape to retry with
- `absolute_date` — the concrete response date for easier audit/debug correlation

---

## <a name="quick-start"></a>Quick Start

**Runtime**: Python 3.8+

### Fastest path

1. Install dependencies.
2. Point `config.yaml` to your downstream kernel repository.
3. Run `build-cache` once for the target branch.
4. Start with `analyze` for a single CVE.
5. Use `validate` only when you already know the real downstream fix and want to measure tool accuracy.
6. Use `server` when you want to call the pipeline by HTTP instead of CLI.

```bash
# Install dependencies
pip install -r requirements.txt

# Configure repository path
# Edit config.yaml:
#   repositories:
#     "5.10-hulk":
#       path: "/path/to/linux"
#       branch: "linux-5.10.y"
#
# If you want L0-L5 rule orchestration config,
# copy the `policy:` block from `rules/policy.example.yaml`

# Build commit cache (one-time, incremental updates afterward)
python cli.py build-cache --target 5.10-hulk

# Analyze a CVE
python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk
```

### Which command should I use?

| Goal | Command | Typical usage |
|------|---------|---------------|
| Decide whether a CVE fix can be backported directly | `analyze` | Daily triage for one CVE or a CVE list |
| Check whether the introducing commit already exists in target branch | `check-intro` | Confirm vulnerability exposure on downstream |
| Check whether the fix is already merged | `check-fix` | Avoid duplicated backport work |
| Compare tool output with a known real fix | `validate` | Single-case accuracy verification |
| Measure rule buckets / dependency buckets across many CVEs | `batch-validate` | Batch strategy evaluation and report generation |
| Build or refresh commit search cache | `build-cache` | First-time setup or repo refresh |
| Expose the engine as HTTP API | `server` | Platform integration, UI integration, remote calling |

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
| DryRun strategies | 7+ methods | Strict → C1 → 3way → Verified-Direct → Regen → Zero-Ctx → Adapted |
| Validation framework | P/R/F1 | git worktree non-destructive rollback |

---

## Project Structure

```
cve_backporting/
├── plan.md                       # Current roadmap and acceptance criteria
├── commands/                      # CLI command modules
│   ├── analyze.py                 #   analyze command registration + execution
│   ├── checks.py                  #   check-intro / check-fix commands
│   ├── validate.py                #   validate / benchmark / batch-validate commands
│   ├── maintenance.py             #   build-cache / search commands
│   ├── server.py                  #   HTTP API server command
│   └── __init__.py                #   Central command registry
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
├── cli.py                         # Thin CLI entry point + shared runtime helpers
├── config.yaml                    # Configuration
├── benchmarks.example.yaml        # Benchmark suite example
├── requirements.txt
├── rules/
│   ├── default_rules.py           # Built-in risk rules
│   ├── level_policies.py          # L0-L5 orchestration policies
│   ├── policy.example.yaml        # Rule config example
│   └── README.md                  # Rule extension guide
├── tests/
│   ├── test_agents.py             # Agent / pipeline tests
│   └── test_policy_engine.py      # Rule engine regression tests
└── docs/
    ├── presentation.md            # Presentation deck / review material
    ├── TECHNICAL.md               # Complete technical documentation
    ├── ADAPTIVE_DRYRUN.md         # 5-level adaptive algorithm deep-dive
    └── MULTI_LEVEL_ALGORITHM.md   # Multi-level algorithm detailed reference
```

---

## Algorithm Highlights

### 1. Unidirectional Diff Containment

First application of multiset containment detection in CVE backport tooling — solves the squash commit matching problem that defeats traditional bidirectional similarity.

### 2. Verified-Direct Patch Application

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
| **AI-Generated (optional)** | LLM (GPT-4o / DeepSeek / etc.) | Generate adapted patches when rules fail | Disabled |
| **LLM Root-Cause Analysis** | LLM | Analyze validation failures | Disabled |
| **Code Semantic Matching** | SequenceMatcher + Set ops | Multi-dimensional code similarity | Enabled (pure algorithm) |
| **Diff Containment** | Multiset counting | Detect patches in squash commits | Enabled (pure algorithm) |

Core non-AI algorithms are **fully deterministic** — no model inference, complete reproducibility and explainability. AI features are opt-in enhancements.

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
| **[presentation.md](docs/presentation.md)** | Current presentation deck for expert review / internal reporting |
| **[plan.md](plan.md)** | Current roadmap, gaps, milestones, and acceptance criteria |
| **[rules/policy.example.yaml](rules/policy.example.yaml)** | Example `policy:` block for L0-L5 orchestration and rule plugins |

---

## Roadmap

The current roadmap is tracked in [plan.md](/Users/junxiaoqiong/Workplace/cve_backporting/plan.md). Near-term priorities are:

1. Turn `rules/` into the stable home for rule code, rule docs, and rule config examples.
2. Upgrade L0-L5 from “framework complete” to “sample-validated and auditable”.
3. Build a reproducible 20+ CVE validation set with expected level / warning / prerequisite fields.
4. Connect `level_decision` outputs to delivery-time review and approval gates.

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
