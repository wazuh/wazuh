# Tools

1. [Summary](#summary)
2. [Directory structure](#directory-structure)
3. [Scripts and Packages](#scripts-and-packages)
    - [API communication](#api-communication)
    - [Engine suite](#engine-suite)
    - [Engine metrics](#engine-metrics)
    - [Engine schema](#engine-schema)
    - [Engine bench](#engine-bench)
    - [EVTX to XML](#evtx-to-xml)
    - [Third-party notices](#third-party-notices)
    - [Check valgrind](#check-valgrind)
    - [Check ASAN](#check-asan)

# Summary

This directory includes packages and scripts designed to make engine development and testing easier. None
of them is installed with the manager, except `engine-schema`, which the installer runs from the source tree
to generate the schema files. The `engine-suite`, `engine-metrics` and `engine-bench` tools talk to the engine
over its API socket,
`/var/wazuh-manager/queue/sockets/engine-api-http.sock` on an installed manager. The commands below run from
`src/engine/`.

# Directory structure

```plaintext
tools/
├── api-communication/     # Python client library for the engine API socket
├── engine-bench/          # perf + flame graph profiler (engine-bench)
├── engine-metrics/        # Metrics dashboard and CLI (engine-metrics)
├── engine-schema/         # Schema generator from the Wazuh Common Schema (engine_schema.py)
├── engine-suite/          # engine-router, engine-test, engine-event-dumper, engine-public, engine-private
├── evtx2xml/              # EVTX to XML converter (evtx2xml)
├── third-party-notices/   # THIRD-PARTY-NOTICES and README table generator (generate.py)
├── check_ASAN.sh
├── check_Valgrind.sh
└── ...                    # Other one-off helper scripts
```

# Scripts and Packages

## API communication

The `api-communication` package is the Python client of the engine API: `APIClient` sends protobuf request
messages as JSON over the API socket and deduces the endpoint from the message type. `engine-suite`,
`engine-metrics` and `engine-bench` (through `test/engine-test-utils`) depend on it, and it is not published,
so install it first. See the
[api-communication README](./api-communication/README.md).

```bash
pip3 install tools/api-communication
```

## Engine suite

The `engine-suite` package installs the `engine-router` (routes), `engine-test` (test integrations and
testing sessions), `engine-event-dumper` (event dumper), `engine-public` (policy and resource validation,
logtest cleanup, IOC, status) and `engine-private` (namespaces, content CRUD, geo, raw event indexer)
commands. See the [engine-suite README](./engine-suite/README.md).

```bash
pip3 install tools/engine-suite
```

## Engine metrics

Real-time web dashboard and CLI for the engine metrics (`engine-metrics dashboard|dump|list|get|enable|disable`).
See the [engine-metrics README](./engine-metrics/README.md).

## Engine schema

Generates `engine-schema.json`, `wazuh-logpar-overrides.json`, `wazuh-decoders.json` and the geo and IOC
enrichment configurations from the Wazuh Common Schema. See the
[engine-schema README](./engine-schema/README.md).

## Engine bench

Profiles an engine started from a test environment with `perf` and renders a flame graph. See the
[engine-bench README](./engine-bench/README.md).

## EVTX to XML

This module converts event files in EVTX format (used by Windows for event logs) to XML format. This allows you to view and work with Windows event logs in a more accessible and standard format. For more information see the [evtx2xml README](./evtx2xml/README.md).

## Third-party notices

`third-party-notices/generate.py` generates `THIRD-PARTY-NOTICES` and the third-party table of the root
`README.md` from `third-party-notices/components.json`; the license texts it inlines live in
`third-party-notices/texts/` ([origin of each text](./third-party-notices/texts/README.md)).

## Check valgrind

- **Running Valgrind**: Runs every `*_ctest`/`*_utest` binary under Valgrind (`--leak-check=full`) to identify memory leaks and other similar problems.
- **Test Search Settings**: Allows you to specify the directory where to search for tests, exclude certain directories, and pass a gtest filter.
- **Report Generation**: Writes the Valgrind output to a report file.

The script reads the engine build tree from `-b` (default `src/build/engine`, where the manager build
configures the engine), which must hold `source/` and the `wazuh-engine` binary whatever `-t` says, and
first requires every static library found there to be built with a sanitizer; a missing tree exits with
`Build directory does not exist`.

### Usage
```bash
Usage: tools/check_Valgrind.sh [options] [arguments]

Options:
  -h, --help          Show this help message
  -b, --build-dir DIR Engine build directory (default: src/build/engine)
  -e, --exclude DIRS  Colon-separated list of directories to exclude
  -t, --test-dir DIR  Directory to search for tests (default: build directory)
  -r, --regex PATTERN Optional regular expression to filter tests (default: no filtering)
  -o, --output FILE   File to redirect output (default: ${SCRIPT_DIR}/valgrindReport.log)
```

The `--output` default is `valgrindReport.log` next to the script. `-r` is passed to the test binaries as
`--gtest_filter`.

- **Run only the OrchestratorTest suite of the router component**:
```bash
bash tools/check_Valgrind.sh -t ../build/engine/source/router/ -r 'OrchestratorTest*'
```

- **Run all tests except those of the builder and kvdbstore**:
```bash
bash tools/check_Valgrind.sh -e ../build/engine/source/builder/:../build/engine/source/kvdbstore/
```

## Check ASAN

- **ASAN, TSAN, and MSAN check**: Checks that the test binaries, the static libraries and the `wazuh-engine` binary are compiled with AddressSanitizer, ThreadSanitizer, or MemorySanitizer, and stops at the first that is not.
- **Test Execution**: Uses `ctest --output-on-failure -V` to run the tests in the specified directory and appends the results to a file if indicated.
- **Flexible Configuration**: Allows you to specify the test directory, exclude certain directories, and filter tests with a `ctest --tests-regex`.

It expects the same build tree as `check_Valgrind.sh`. CI's ASAN gate does not use it (see the
`5_testunit_engine.yml` workflow).

### Usage
```bash
Usage: tools/check_ASAN.sh [options] [arguments]

Options:
  -h, --help          Show this help message
  -b, --build-dir DIR Engine build directory (default: src/build/engine)
  -e, --exclude DIRS  Colon-separated list of directories to exclude
  -t, --test-dir DIR  Directory to search for tests (default: build directory)
  -r, --regex PATTERN Optional regular expression to filter tests (default: no filtering)
  -o, --output FILE   File to redirect output (default: stdout)
```
- **Run only the OrchestratorTest suite of the router component**:
```bash
bash tools/check_ASAN.sh -t ../build/engine/source/router/ --regex 'OrchestratorTest'
```
- **Run all tests except those of the builder and kvdbstore**:
```bash
bash tools/check_ASAN.sh -e ../build/engine/source/builder/:../build/engine/source/kvdbstore/
```
