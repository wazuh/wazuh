# CodeChecker — Static Analysis Toolchain

Differential static analysis for Wazuh, replacing Coverity.  
Compares two refs (tags, branches, or SHAs), stores both runs on the CodeChecker dashboard,
surfaces new and resolved findings, and generates a structured Markdown summary compatible
with GitHub issue comments — matching the format previously produced by the Coverity workflow.

Related issue: [#36748](https://github.com/wazuh/wazuh/issues/36748) · CodeChecker 6.27.3 · clang-20

---

## Pipeline overview

```
[Build image] → [Set refs] → [--scan] → [gh issue comment]
                                │               │
                 ┌──────────────┴──────┐   results/report.md (auto-generated)
                 │  run_ci.sh          │
                 │  1. CC server :8001 │
                 │  2. Clone (cached)  │
                 │  3. SCAN_REF →      │
                 │     build → analyze │
                 │     → store (base)  │
                 │  4. TARGET_REF →    │
                 │     build → analyze │
                 │     → store (target)│
                 │  5. Flawfinder →    │
                 │     plist → store   │
                 │  6. Diff → results/ │
                 │  7. HTML report     │
                 │  8. report.md       │
                 └─────────────────────┘
```

---

## Prerequisites

- Docker Engine ≥ 24
- `gh` CLI authenticated to `wazuh/wazuh` (required for GitHub Actions and issue posting)
- ~60–90 min and ~20 GB disk for a full `manager` scan of two refs

---

## Quick start

### 1 — Build the Docker image

Run once before the first scan; repeat after any change to `Dockerfile` or scan scripts.

```bash
# From the repo root
./tools/testing/codechecker/codechecker.sh --build-image
```

> The image bundles clang-20, clang-tidy-20, cppcheck, CodeChecker 6.27.3, Meta Infer 1.2.0,
> ThreadSanitizer runtime, and Flawfinder.

### 2 — Verify the pipeline with the built-in self-test (optional)

After building the image, run a fast end-to-end check against the `defect_samples/` directory.
No `SCAN_REF` or `TARGET_REF` required; completes in **< 5 min**.

```bash
./tools/testing/codechecker/codechecker.sh --selftest
# All analyzers enabled:
ENABLE_CTU=1 RUN_INFER=1 RUN_TSAN=1 RUN_FLAWFINDER=1 \
    ./tools/testing/codechecker/codechecker.sh --selftest
```

The selftest goes through the **exact same pipeline** as a production scan
(`run_ci.sh` → `run_comparison.sh`). It creates a two-commit git repo from `defect_samples/`:
- `selftest-base` — all samples except `defects_flawfinder.c`
- `selftest-target` — adds `defects_flawfinder.c`

Expected results in `results/diff_new.txt`: `flawfinder.race.chmod`, `flawfinder.race.access`,
`flawfinder.buffer.gets`, `flawfinder.buffer.strcpy`, `flawfinder.format.sprintf`.

### 3 — Run a differential scan

```bash
SCAN_REF=4.14.7 \
TARGET_REF=main \
SCAN_TARGET=manager \
./tools/testing/codechecker/codechecker.sh --scan
```

`SCAN_REF` and `TARGET_REF` accept **any git ref**: tag, branch name, or full/short SHA.  
Results land in `tools/testing/codechecker/results/`.

### 3 — Generate the Markdown summary report

After the scan completes, parse the JSON output into a GitHub-ready Markdown summary:

```bash
./tools/testing/codechecker/generate_report.sh \
  --results  tools/testing/codechecker/results \
  --scan-ref  4.14.7 \
  --target-ref main \
  --target    server \
  --output    tools/testing/codechecker/results/report.md
```

### 4 — Post the report to a GitHub issue

```bash
gh issue comment 36748 \
  --repo wazuh/wazuh \
  --body-file tools/testing/codechecker/results/report.md
```

### 5 — View results

**Option A — HTML report (no server needed)**

```bash
xdg-open tools/testing/codechecker/results/diff_new_html/index.html   # Linux
open     tools/testing/codechecker/results/diff_new_html/index.html   # macOS
```

**Option B — Interactive dashboard**

```bash
./tools/testing/codechecker/codechecker.sh --serve
# Open http://localhost:8001 → select base run → Compare → filter "New"
```

**Option C — CLI text diff**

```bash
cat tools/testing/codechecker/results/diff_new.txt
```

### 6 — Clean up

```bash
./tools/testing/codechecker/codechecker.sh --clean
```

Removes `workspace/`, `results/`, and `cc-db/`.

---

## Environment variables

| Variable | Default | Required | Description |
|---|---|---|---|
| `SCAN_REF` | — | **yes** | Base ref — the "before" snapshot. Tag, branch, or SHA. |
| `TARGET_REF` | — | **yes** | Target ref — the "after" snapshot to diff against base. |
| `SCAN_TARGET` | `manager` | no | Wazuh component to scan: `manager` · `agent`. `manager` auto-resolves to `server` on 4.x and `manager` on 5.x by reading `VERSION.json` from the checked-out tree. |
| `SCAN_NAME` | `wazuh-$SCAN_REF` | no | Dashboard run label for the base run. |
| `TARGET_NAME` | `wazuh-$TARGET_REF` | no | Dashboard run label for the target run. |
| `ENABLE_CTU` | `1` | no | Cross-translation-unit analysis. Finds interprocedural bugs. Adds ~2–3× scan time. Set `0` to disable. |
| `RUN_INFER` | `0` | no | Run Meta Infer / RacerD after main scan. Detects resource leaks and lock imbalances. Adds ~20 min. |
| `RUN_TSAN` | `0` | no | Run ThreadSanitizer via unit tests. Runtime data-race detection. Requires kernel tuning (see below). |
| `RUN_FLAWFINDER` | `1` | no | Run Flawfinder CWE-362/CWE-119 supplementary security scan. Enabled by default. Set `0` to skip. |
| `JOBS` | `nproc` | no | Parallel analysis jobs. |
| `IMAGE` | `ghcr.io/wazuh/codechecker:latest` | no | Docker image to pull/use. |

---

## Using tags, branches, or SHAs as refs

All three forms are resolved identically by `run_comparison.sh`:

```bash
# Tag (immutable — recommended for periodic comparisons)
SCAN_REF=4.14.7  TARGET_REF=4.15.0

# Branch (resolves to tip at fetch time)
SCAN_REF=main  TARGET_REF=fix/37131-ebpf-toctou

# Full SHA (most reproducible)
SCAN_REF=69b8bca773ea149dd0da271584e9a243483083d5 \
TARGET_REF=bcc3dac7dd8c9f38205f295a5d0e2a33da834ce2

# Mixed (common for PR-level spot checks)
SCAN_REF=4.14.7  TARGET_REF=fix/37131-ebpf-toctou
```

The ref is embedded in the dashboard run name (`wazuh-<ref>-<target>`).  
Slashes in branch names (e.g. `fix/37131-...`) are preserved — they are valid in CodeChecker run names.

---

## Optional analyses

### Infer / RacerD (static race detection, ~20 min extra)

Detects resource leaks, lock imbalances, and thread-safety violations interprocedurally.

```bash
RUN_INFER=1 \
SCAN_REF=4.14.7 \
TARGET_REF=main \
SCAN_TARGET=manager \
./tools/testing/codechecker/codechecker.sh --scan
```

Results appear as a separate run `wazuh-<TARGET_REF>-infer` on the dashboard.

### ThreadSanitizer (dynamic race detection)

> **Warning:** TSan requires `vm.mmap_rnd_bits ≤ 28` on kernel 6.x. Lower it on the host before running.

```bash
sudo sysctl -w vm.mmap_rnd_bits=28

RUN_TSAN=1 \
SCAN_REF=4.14.7 \
TARGET_REF=main \
SCAN_TARGET=manager \
./tools/testing/codechecker/codechecker.sh --scan

sudo sysctl -w vm.mmap_rnd_bits=32   # restore after scan
```

TSan runs in two phases: unit test suite compiled with `-fsanitize=thread`, and `wazuh-db` exercised via concurrent socket queries.

### Flawfinder (CWE-362 / CWE-119 security scan, enabled by default)

Flawfinder scans the target source tree for security-sensitive patterns (TOCTOU races, buffer bounds,
format string issues) that clangsa/cppcheck/clang-tidy do not cover. Findings are stored on the
dashboard as `<TARGET_NAME>-flawfinder`.

```bash
# Enabled by default — no extra flag needed.

# To disable:
RUN_FLAWFINDER=0 \
SCAN_REF=4.14.7 \
TARGET_REF=main \
./tools/testing/codechecker/codechecker.sh --scan
```

> **Implementation note:** `report-converter -t flawfinder` does not exist in CodeChecker 6.27.3.
> `flawfinder_to_plist.py` (baked at `/cc/`) converts `flawfinder --csv` output directly to
> plist format, which `CodeChecker store` accepts.
>
> Flawfinder runs **twice** — once on BASE_REF and once on TARGET_REF (immediately after each
> `run_scan`, while the tree is at the correct ref).  Both runs are stored to the dashboard as
> `<run-name>-flawfinder`.  `run_diff` then compares the two flawfinder report directories and
> merges the differential findings into the same `diff_new.json` / `diff_resolved.json` files
> as the clangsa/cppcheck results, so Flawfinder findings appear in `generate_report.sh` output.

### Combining all optional analyses

```bash
sudo sysctl -w vm.mmap_rnd_bits=28

SCAN_REF=4.14.7 \
TARGET_REF=main \
SCAN_TARGET=manager \
ENABLE_CTU=1 \
RUN_INFER=1 \
RUN_TSAN=1 \
RUN_FLAWFINDER=1 \
./tools/testing/codechecker/codechecker.sh --scan

sudo sysctl -w vm.mmap_rnd_bits=32
```

---

## Markdown Report Generation

`generate_report.sh` is called automatically at the end of every scan (`run_ci.sh` invokes it
after `run_comparison.sh` completes). The output is written to `results/report.md` and included
in the CI artifact. No manual step is required for CI runs.

To regenerate the report from an existing `results/` directory (e.g. after downloading the
artifact or re-running locally):

### Usage

```bash
./tools/testing/codechecker/generate_report.sh \
  --results   <results_dir>   \   # path to results/ from --scan (required)
  --scan-ref  <base_ref>      \   # SCAN_REF used in the scan (required)
  --target-ref <target_ref>   \   # TARGET_REF used in the scan (required)
  --target    <build_target>  \   # manager / agent (default: manager)
  --output    <output.md>         # output path (default: <results_dir>/report.md)
```

**Full example:**

```bash
./tools/testing/codechecker/generate_report.sh \
  --results    tools/testing/codechecker/results \
  --scan-ref   4.14.7 \
  --target-ref main \
  --target     manager \
  --output     tools/testing/codechecker/results/report.md

cat tools/testing/codechecker/results/report.md
```

### Report format

The generated `report.md` follows this structure:

```markdown
## Summary

| Run ID | CodeChecker version | Platform | Total detected | Newly detected | Newly eliminated |
|---|---|---|---|---|---|
| wazuh-main-manager | **6.27.3** | Ubuntu 24.04 | 371 | 26 | 2 |

## Results

<details open><summary><b>New defects:</b></summary>

| Status | Bug Hash | Type | Severity | Date | Analyzer | File |
|---|---|---|---|---|---|---|
| 🟡 | `a1b2c3d4` | performance-unnecessary-copy-initialization | LOW | 2025-10-31 | clangsa | /src/shared_modules/http-request/src/HTTPRequest.cpp |
| 🟡 | `e5f6a7b8` | unix.BlockInCriticalSection | MEDIUM | 2025-10-31 | clangsa | /src/syscheckd/src/whodata/audit_healthcheck.c |

</details>

<details open><summary><b>Fixed defects:</b></summary>

| Status | Bug Hash | Type | Severity | Date | Analyzer | File |
|---|---|---|---|---|---|---|
| 🟣 | `c9d0e1f2` | flawfinder.race.chmod | HIGH | 2025-10-31 | flawfinder | /src/syscheckd/src/ebpf/src/ebpf_whodata.cpp |

</details>

### Status legend

🔴 Fix pending · 🟡 Untriaged · 🟢 Intentional · 🔵 Ignored · 🟣 Fixed · ⚪ False positive

## Conclusion
```

### Field mapping from CodeChecker output

| Report field | Source |
|---|---|
| Run ID | `CodeChecker cmd runs` — run name |
| CodeChecker version | Hardcoded from image tag (`6.27.3`) |
| Total detected | Line count in `summary_target.txt` |
| Newly detected | Finding count in `diff_new.json/` |
| Newly eliminated | Finding count in `diff_resolved.txt` |
| Bug Hash | `bugHash` field in each JSON finding |
| Type | `checkerId` field (e.g. `flawfinder.race.chmod`) |
| Severity | `severity` field (`HIGH`/`MEDIUM`/`LOW`/`UNSPECIFIED`) |
| Date | `detectedAt` field |
| Analyzer | `analyzerName` field (`clangsa`/`cppcheck`/`flawfinder`) |
| Status | `reviewStatus` field; fixed findings default to 🟣 |

### Post the report to a GitHub issue

```bash
# Append as a comment on an existing issue
gh issue comment 36748 \
  --repo wazuh/wazuh \
  --body-file tools/testing/codechecker/results/report.md

# Or create a new dedicated issue
gh issue create \
  --repo wazuh/wazuh \
  --title "CodeChecker scan: wazuh-4.14.7 → main (manager)" \
  --body-file tools/testing/codechecker/results/report.md \
  --label "static-analysis"
```

---

## Output files

| Path | Contents |
|---|---|
| `results/diff_new.txt` | New findings introduced in TARGET vs BASE (plain text) |
| `results/diff_resolved.txt` | Findings that disappeared in TARGET (plain text) |
| `results/diff_unresolved.txt` | Findings present in both BASE and TARGET (plain text) |
| `results/diff_new.json/` | Machine-readable new findings (JSON) — clangsa/cppcheck/flawfinder merged |
| `results/diff_resolved.json/` | Machine-readable resolved findings (JSON) — clangsa/cppcheck/flawfinder merged |
| `results/diff_new_html/` | Browsable HTML diff report — no server required |
| `results/full_report_html/` | Full HTML report of the TARGET run |
| `results/summary_base.txt` | Per-checker/severity counts for BASE run |
| `results/summary_target.txt` | Per-checker/severity counts for TARGET run |
| `results/flawfinder_base.csv` | Raw Flawfinder CSV output for BASE ref |
| `results/flawfinder_target.csv` | Raw Flawfinder CSV output for TARGET ref |
| `results/compile_commands_*.json` | Build capture files (for debugging) |
| `results/report.md` | Generated Markdown summary for GitHub issue posting |

---

## GitHub Actions workflows

> **Manual trigger only.** All workflows use `workflow_dispatch` — they are never triggered
> automatically by a push, commit, or pull request.  
> The workflow files must be on the **default branch** (`main`) before `gh workflow run` works.

### Workflows at a glance

| File | Purpose | Inputs |
|---|---|---|
| `5_codeanalysis_codechecker-image.yml` | Build and push Docker image to GHCR | none |
| `5_codeanalysis_codechecker.yml` | Run differential scan, generate report, upload artifact | `scan_ref`, `target_ref`, `scan_target`, `enable_ctu`, `run_infer`, `run_tsan`, `run_flawfinder`, `issue_number` |

---

### Step 1 — Build and push the Docker image

Run once before the first CI scan; run again after any change to `Dockerfile`, scripts, or `flawfinder_to_plist.py`.

```bash
gh workflow run \
  5_codeanalysis_codechecker-image.yml \
  --repo wazuh/wazuh \
  --ref main
```

Monitor the image build:

```bash
gh run list \
  --workflow=5_codeanalysis_codechecker-image.yml \
  --repo wazuh/wazuh \
  --limit 3

gh run watch <run-id> --repo wazuh/wazuh
```

### Step 2 — Trigger a differential scan

**Minimal (server target, CTU + Flawfinder on by default):**

```bash
gh workflow run \
  5_codeanalysis_codechecker.yml \
  --repo wazuh/wazuh \
  --ref main \
  -f scan_ref=4.14.7 \
  -f target_ref=main \
  -f scan_target=server
```

**With all optional analyses enabled:**

```bash
gh workflow run \
  5_codeanalysis_codechecker.yml \
  --repo wazuh/wazuh \
  --ref main \
  -f scan_ref=4.14.7 \
  -f target_ref=main \
  -f scan_target=manager \
  -f enable_ctu=true \
  -f run_infer=true \
  -f run_tsan=true \
  -f run_flawfinder=true
```

**PR-level spot check (branch vs tag, CTU off for speed):**

```bash
gh workflow run \
  5_codeanalysis_codechecker.yml \
  --repo wazuh/wazuh \
  --ref main \
  -f scan_ref=4.14.7 \
  -f target_ref=fix/37131-ebpf-toctou \
  -f scan_target=manager \
  -f enable_ctu=false \
  -f run_infer=false \
  -f run_tsan=false \
  -f run_flawfinder=true
```

### Step 3 — Monitor the run

```bash
# List the most recent scan runs and get the run ID
gh run list \
  --workflow=5_codeanalysis_codechecker.yml \
  --repo wazuh/wazuh \
  --limit 5

# Stream live log (blocks until completion)
gh run watch <run-id> --repo wazuh/wazuh

# View full log after completion
gh run view <run-id> --log --repo wazuh/wazuh
```

### Step 4 — Download the results artifact

The scan uploads a ZIP containing HTML reports, JSON findings, text diffs, and `report.md`.
Retained for **30 days**.

```bash
# Download to a local directory
gh run download <run-id> \
  --repo wazuh/wazuh \
  --dir /tmp/cc-results

# Browse the diff HTML report
xdg-open /tmp/cc-results/*/diff_new_html/index.html   # Linux
open     /tmp/cc-results/*/diff_new_html/index.html   # macOS

# Read the Markdown summary
cat /tmp/cc-results/*/report.md

# Quick CLI review of new findings
cat /tmp/cc-results/*/diff_new.txt

# Review Flawfinder security findings
cat /tmp/cc-results/*/flawfinder_target.csv
```

### Step 5 — Post the report to a GitHub issue

The CI workflow posts the report automatically when `issue_number` is provided.
To post manually from the downloaded artifact:

```bash
gh issue comment 36748 \
  --repo wazuh/wazuh \
  --body-file /tmp/cc-results/*/report.md
```

---

## Directory layout

```
tools/testing/codechecker/
├── Dockerfile                # combined analyzer + server image
│                             # clang-20 · cppcheck · CodeChecker 6.27.3
│                             # Meta Infer 1.2.0 · TSan runtime · Flawfinder
├── codechecker.sh            # host-side script: --build-image / --scan / --selftest / --serve / --clean
├── run_ci.sh                 # in-container CI entrypoint (called by codechecker.sh --scan/--selftest)
├── run_comparison.sh         # differential scan logic + Flawfinder integration
├── run_infer.sh              # Infer/RacerD static race scan
├── run_tsan_tests.sh         # ThreadSanitizer: unit tests + wazuh-db system test
├── run_tsan_wdb.sh           # targeted TSan harness for wdb_global
├── flawfinder_to_plist.py    # converts flawfinder --csv output to CodeChecker plist format
├── generate_report.sh        # generates Markdown summary from diff JSON for GitHub issues
├── merge_reports_json.py     # merges flawfinder diff JSON into main diff_new/diff_resolved JSON
├── skipfile.txt              # CodeChecker analysis skip rules (+*/src/* / -*/external/*)
├── .dockerignore             # excludes workspace/, results/, cc-db/ from the image build context
├── defect_samples/           # known-defect C/C++ files for pipeline self-validation
│   ├── Makefile              # standalone build (make all / make defects_tsan)
│   ├── defects_c.c           # clangsa/cppcheck: null deref, malloc, uninit, block-in-cs
│   ├── defects_cpp.cpp       # C++ checker samples
│   ├── defects_ctu_callee.c  # CTU: callee that always returns NULL
│   ├── defects_ctu_caller.c  # CTU: caller that dereferences it (cross-TU null deref)
│   ├── defects_infer.c       # Infer: fd leak + lock imbalance
│   ├── defects_tsan.c        # TSan: data-race binary (built with -fsanitize=thread)
│   ├── defects_flawfinder.c  # Flawfinder: TOCTOU (CWE-362), buffer (CWE-119), format (CWE-134)
│   └── src/
│       └── Makefile          # selftest build path — used by run_comparison.sh (cd $WAZUH_DIR/src)
└── README.md

.github/workflows/
├── 5_codeanalysis_codechecker.yml          # main scan + report workflow (workflow_dispatch)
└── 5_codeanalysis_codechecker-image.yml    # image build + push workflow (workflow_dispatch)

.github/actions/codechecker/scan/
└── action.yml                              # composite action wrapping docker run
```

### Runtime directories (git-ignored)

| Path | Contents |
|---|---|
| `workspace/` | Cloned Wazuh source tree (reused across scans) |
| `results/` | HTML reports, text diffs, JSON findings, Flawfinder CSV, `report.md` |
| `cc-db/` | CodeChecker SQLite database (dashboard state) |
