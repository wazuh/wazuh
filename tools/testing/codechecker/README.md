# CodeChecker static analysis tooling

Replacement for Coverity static analysis using the open-source CodeChecker platform
(clang-20 / clang-tidy / cppcheck / Meta Infer / ThreadSanitizer).

Related issue: [#36748](https://github.com/wazuh/wazuh/issues/36748)

## Quick start

### Build the Docker image

```bash
./tools/testing/codechecker/codechecker.sh --build-image
```

### Run a paired differential scan

```bash
SCAN_REF=coverity-w51-4.14.2 \
TARGET_REF=coverity-w52-4.14.2 \
SCAN_TARGET=server \
./tools/testing/codechecker/codechecker.sh --scan
```

Artifacts land in `tools/testing/codechecker/results/`:

| File | Contents |
|---|---|
| `diff_new_html/` | Browsable HTML — new findings in TARGET vs BASE |
| `full_report_html/` | Full HTML report of the target run |
| `diff_new.json` | Machine-readable new findings |
| `diff_new.txt` / `diff_resolved.txt` / `diff_unresolved.txt` | Plain-text diffs |
| `summary_base.txt` / `summary_target.txt` | Per-run counts by checker/severity |

### Clean up

```bash
./tools/testing/codechecker/codechecker.sh --clean
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `SCAN_REF` | — | **Required.** Base ref (tag or SHA) |
| `TARGET_REF` | — | **Required.** Target ref to scan |
| `SCAN_TARGET` | `server` | Wazuh make target: `server` / `agent` / `manager` |
| `SCAN_NAME` | `wazuh-$SCAN_REF` | Dashboard run name for base |
| `TARGET_NAME` | `wazuh-$TARGET_REF` | Dashboard run name for target |
| `ENABLE_CTU` | `1` | Cross-translation-unit analysis (adds ~2–3× time; set `0` to disable) |
| `RUN_INFER` | `0` | Infer/RacerD static race scan (~20 min extra) |
| `RUN_TSAN` | `0` | ThreadSanitizer via unit tests + wazuh-db system test |
| `JOBS` | `nproc` | Parallel jobs |
| `IMAGE` | `ghcr.io/wazuh/codechecker:latest` | Docker image to use |

## Optional analyses

### Infer/RacerD (static data-race detection)

```bash
RUN_INFER=1 SCAN_REF=... TARGET_REF=... ./codechecker.sh --scan
```

### ThreadSanitizer (dynamic race detection)

TSan requires `vm.mmap_rnd_bits ≤ 28` on kernel 6.x. Lower it on the host first:

```bash
sudo sysctl -w vm.mmap_rnd_bits=28
RUN_TSAN=1 SCAN_REF=... TARGET_REF=... ./codechecker.sh --scan
sudo sysctl -w vm.mmap_rnd_bits=32   # restore
```

TSan runs in two phases:
1. **Unit tests** — the Wazuh unit test suite compiled with `-fsanitize=thread` via CMake/ctest.
2. **System test** — `wazuh-db` rebuilt with TSan and exercised via concurrent socket queries.

## GitHub Actions

Trigger the scan manually from `.github/workflows/5_codeanalysis_codechecker.yml`.
The HTML report (`diff_new_html/` + `full_report_html/`) is uploaded as a
downloadable artifact on the Actions run page.

## Directory layout

```
tools/testing/codechecker/
├── Dockerfile            # combined analyzer + server image (clang-20, Infer, TSan)
├── codechecker.sh        # host-side script: --build-image / --scan / --clean
├── run_ci.sh             # in-container CI entrypoint (started by codechecker.sh)
├── run_comparison.sh     # differential scan logic
├── run_infer.sh          # Infer/RacerD static race scan
├── run_tsan_tests.sh     # ThreadSanitizer: unit tests + wazuh-db system test
├── skipfile.txt          # CodeChecker analysis skip rules
└── README.md
```
