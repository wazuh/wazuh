# General Build Script
## Index
- [General Build Script](#general-build-script)
  - [Index](#index)
  - [Purpose](#purpose)
  - [Dependencies](#dependencies)
  - [Compile Wazuh](#compile-wazuh)
  - [How to use the tool](#how-to-use-the-tool)
    - [Optional arguments:](#optional-arguments)
    - [Ready to review checks](#ready-to-review-checks)
    - [Address sanitizer checks](#address-sanitizer-checks)
    - [Scan-build analysis](#scan-build-analysis)

## Purpose
The `build.py` script compiles, tests and validates the **agent** C++ modules and their code readiness ("ready to review", RTR). It is meant for developers, to speed up those checks, and for automation: the `5_testcomponent_*-rtr.yml` workflows run it.

The modules it accepts are `MODULE_LIST` in `ci/utils.py`: `wazuh_modules/syscollector`, `shared_modules/dbsync`, `shared_modules/sync_protocol`, `shared_modules/agent_metadata`, `shared_modules/schema_validator`, `shared_modules/file_helper`, `data_provider`, `syscheckd`, `wazuh_modules/sca`, `wazuh_modules/agent_info` and `client-agent/https_client`. Below, `<module>` is one of them. The manager's modules are tested with `ctest` labels instead; see `docs/dev/test-execution.md`.

> **Warning:** `-r`, `-d` and `--scanbuild` start with `make clean`, which removes the whole `build/` tree under `src/`, a manager build included.

## Dependencies
The tool needs these programs:
  - cppcheck
  - valgrind
  - lcov and gcov (gcov comes with GCC)
  - astyle
  - scan-build (`--scanbuild` only)

## Compile Wazuh
`-r`, `-d` and `--scanbuild` build what they need themselves. The other checks run on an existing build: compile the agent with the `TEST` option first, from `src/`:
```
make TARGET=agent TEST=1
```
`TEST` accepts only `YES`, `yes`, `y`, `Y` or `1`; `TEST=on` is ignored.

## How to use the tool
Run it from `src/`:

```
usage: python3 build.py [-h] [-r] [-d] [-m] [-t] [-c] [-v] [--clean] [--cppcheck] [--asan] [--path]
                        [--scheck] [--sformat] [--scanbuild] [--target] [--deleteLogs] [--cpus]
```

### Optional arguments:

|Argument|Description|
|---|---|
| `-h`, `--help` | Show the help message and exit |
| `-r <module>`, `--readytoreview <module>` | Run all the quality checks needed to create a PR (see [Ready to review checks](#ready-to-review-checks)) |
| `-d <module>`, `--readytoreviewandclean <module>` | The same as `-r`, and then delete the logs it produced |
| `--target <agent\|manager\|winagent>` | Target `-r`, `-d` and `-c` build and test. Default: `agent` |
| `-m <module>`, `--make <module>` | Compile the module (`make` in its directory of the build tree) |
| `-t <module>`, `--tests <module>` | Run the module's tests: `ctest` in the build tree, filtered by the label that is the module's last path component (`dbsync`, `syscollector`, …) |
| `-c <module>`, `--coverage <module>` | Collect the tests' coverage and generate the report in `<module>/coverage_report/`. Fails under 90 % of lines or functions (75 % for `data_provider`, 80 % for `syscheckd`) |
| `-v <module>`, `--valgrind <module>` | Rebuild the agent with `TEST=1 DEBUG=1` and no sanitizers, and run the module's test binaries under valgrind |
| `--clean <module>` | `make clean` in the module's build directory |
| `--cppcheck <module>` | Run cppcheck on the module |
| `--asan <module> --path <json>` | Run the [address sanitizer checks](#address-sanitizer-checks). `--path` names the test tool configuration (`ci/input/test_tool_config.json` is the one `-r` uses); without it the help is printed instead |
| `--scheck <module>` | Run AStyle on the module to check the formatting (`ci/input/astyle.config`) |
| `--sformat <module>` | Run AStyle on the module, formatting the files in place |
| `--scanbuild <agent\|manager\|winagent>` | Run the [scan-build analysis](#scan-build-analysis) on a target |
| `--deleteLogs <module>` | Delete the output folders the module's checks produced |
| `--cpus <N>` | Number of parallel jobs for the compilations |

### Ready to review checks
`-r` (and `-d`) runs, in order, stopping at the first failure:
  1. cppcheck on the module.
  2. AStyle check on the module.
  3. `make clean`, `make deps TARGET=<target>` and `make TARGET=<target> TEST=1 DEBUG=1`, plus `FSANITIZE=1` for every target except `winagent`.
  4. The module's tests (`ctest -L <label>`).
  5. Coverage, except `data_provider` and `shared_modules/file_helper` on `winagent`.
  6. Valgrind on the tests, except on `winagent`.
  7. `make clean-internals` and a build without `TEST`.
  8. For `syscheckd` on `winagent` only: the test tool under Wine and the check of its output.
  9. The [address sanitizer checks](#address-sanitizer-checks), except on `winagent` and for `shared_modules/agent_metadata`, `shared_modules/file_helper`, `wazuh_modules/agent_info`, `wazuh_modules/sca` and `client-agent/https_client`.

If every check passes it prints `[RTR: PASSED]` and returns 0; otherwise it prints the failure and returns an error.

### Address sanitizer checks
  1. `make clean-internals`, then `make TARGET=agent DEBUG=1 FSANITIZE=1`.
  2. Run every test tool invocation the configuration lists for the module (from the build tree's `bin/`); any non-zero exit fails the check.

If every check passes it prints `[ASAN: PASSED]`.

### Scan-build analysis
For any target:
  1. `make clean` and remove the external dependencies.
  2. `make deps TARGET=<target>`, then compile the target with `DEBUG=1`.
  3. `make clean-internals`.
  4. Run `scan-build --status-bugs` over `make TARGET=<target> DEBUG=1`. For `agent` and `manager` the external dependencies are excluded; for `winagent` the MinGW compilers and the `i686-w64-mingw32` analyzer target are used.

If the analysis finds no bug it prints `[SCANBUILD: PASSED]` and returns 0; otherwise it prints scan-build's output and returns an error.
