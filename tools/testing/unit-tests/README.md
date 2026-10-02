# Unit Tests

Docker-based runner for Wazuh's C unit test suites and the agent RTR checks, with a Markdown report.

## Overview

`unit-tests.sh` runs, inside the `ghcr.io/wazuh/unit-tests:latest` image (Ubuntu 22.04 with GCC, MinGW, CMocka, Wine, lcov, cppcheck, astyle and valgrind) and on the checkout this script belongs to:

1. A clean build (`make clean-deps`, `make clean`), then `make deps` and `make TARGET=server TEST=1` (the Makefile rewrites `server` to `manager`).
2. The manager CMocka suites under `src/unit_tests/`, with coverage.
3. `ctest` over the main build tree.
4. The RTR checks (`python3 build.py -r <component>`) of `data_provider`, `shared_modules/dbsync`, `shared_modules/rsync`, `wazuh_modules/syscollector` and `syscheckd`.
5. An agent build (`TARGET=agent TEST=1`) and its CMocka suites, with coverage.
6. A clean Windows agent build (`TARGET=winagent TEST=1`) and its CMocka suites under Wine.

Each step writes `result-*.txt` and a `*.log` into `src/`, and the report is generated from the result files.

> **Note:** two of those steps do not run as written. Step 2 configures `src/unit_tests` with `-DTARGET=server`, which the unit-test CMake project refuses (it accepts only `manager`, `agent` and `winagent`); the script runs with `set -e`, so the run stops there. And `shared_modules/rsync` is not a module of this tree, so `build.py` rejects that RTR run. To run the suites as CI does, follow `src/unit_tests/Readme.md`.

## Prerequisites

- Docker with permission to run containers
- Access to the `ghcr.io/wazuh/unit-tests:latest` image, or build it locally with `--build-image`

## Usage

```bash
# Run everything in the Docker image and print the report (default)
./unit-tests.sh

# Run with parallel compilation
./unit-tests.sh --jobs 4
```

## Options

| Option | Description |
|--------|-------------|
| `--build-image` | Build the Docker image from the `Dockerfile` next to the script and exit |
| `--build` | Run the steps directly on the current host, without Docker (this is what the container runs) |
| `--results` | Generate the Markdown report from existing `result-*.txt` files in `src/` |
| `--clean` | Remove the generated files (`result-*.txt` and `*.log` in `src/`) |
| `--jobs N` | Number of parallel compilation jobs (default: `THREADS`, or 1) |
| `--help` | Show the help message |

With no option, or with only `--jobs`, the script runs in Docker and then prints the report.

## Output

The report has one section per result file found: the RTR components, the `ctest` run, and the CMocka suites of each target with their coverage:

```markdown
## Linux Manager cmocka tests

### Tests

|Test|Status|
|---|:-:|
|test_component_init|🟢|
|test_error_handling|🔴|

### Coverage

|Coverage type|Percentage|Result|
|---|---|---|
|Lines|85.4%|1234 of 1445 lines|
```

## Examples

```bash
# Standard execution
./unit-tests.sh

# Fast compilation with 8 jobs
./unit-tests.sh --jobs 8

# Clean previous results
./unit-tests.sh --clean

# Re-generate report from existing results
./unit-tests.sh --results
```
