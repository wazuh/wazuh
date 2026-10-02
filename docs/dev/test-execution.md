# Test execution

Every lane below is also a CI workflow under `.github/workflows/` (`5_testunit_*`, `5_testcomponent_*`, `5_testintegration_*`). Reproduce the workflow's commands to get the same result locally.

## Unit tests

### C unit tests (CMocka)

The C daemons and libraries are tested by the CMocka suites under `src/unit_tests/`, a separate CMake project that links the libraries of a `TEST=1` build. CI runs them in `5_testunit_linux-win.yml` for the `manager`, `agent` and `winagent` targets.

Requirements: GCC (CI uses GCC 14), CMake 3.22.1 or newer (the engine requires it), CMocka, and `lcov` for coverage. The Windows agent also needs MinGW, a CMocka cross-built with MinGW, and a 32-bit Wine to run the tests.

For the manager or the Linux agent, from the repository root:

```bash
make -C src deps TARGET=manager
make -C src TARGET=manager TEST=1
mkdir -p src/unit_tests/build && cd src/unit_tests/build
cmake -DTARGET=manager ..
make
ctest --output-on-failure
```

- The CMake `TARGET` must match the one Wazuh was built with, and must be `manager`, `agent` or `winagent`: the unit-test project refuses any other value, `server` included.
- `TEST` accepts only `YES`, `yes`, `y`, `Y` or `1`; `TEST=on` is ignored and builds no test libraries.
- `make coverage` in the same directory runs the tests and writes an HTML report to `coverage-report/`. Pass `-DGCOV_PATH=<gcov>` to `cmake` with the `gcov` of the compiler that built the tree, or lcov cannot read the coverage data.
- `ctest -R` matches test names. To run one directory, use `ctest --test-dir <dir>`, or run a binary such as `./syscheckd/test_create_db` directly.
- The Windows agent configures with `-DTARGET=winagent -DCMAKE_TOOLCHAIN_FILE=../Toolchain-win32.cmake` and runs the `.exe` binaries under Wine, with `WINEARCH=win32` and a `WINEPATH` that names the MinGW runtime and `src/build/bin`.
- On macOS there is no separate unit-test project: `make -C src TARGET=agent TEST=1` builds the tests in the main build tree, and `ctest` runs from there (`cd src/build && ctest -V`, with `DYLD_LIBRARY_PATH` naming the directory CMocka is installed in).

The step-by-step procedure for each target, including the toolchain, the MinGW build of CMocka, Wine and the coverage wrapper the Windows agent needs, is in `src/unit_tests/Readme.md`.

### C++ module tests

The C++ modules of the manager (task_manager, inventory_sync_server, vulnerability_scanner, manager_config, uds_http_server, …) carry GoogleTest suites in the main build tree. CI configures the main build tree with `UNIT_TEST=ON`, builds one test target and runs it with `ctest` filtered by label:

```bash
make -C src deps TARGET=manager
cmake -S src -B src/build -DTARGET=manager -DUNIT_TEST=ON
cmake --build src/build --target <module>_utest
cd src/build && ctest --output-on-failure -L <label>
```

The label is not always the target name: each workflow (`5_testunit_<module>.yml`) names the target it builds and the label it runs. A `UNIT_TEST=ON` tree builds no daemon executables, and the option stays in the CMake cache until it is set back to `OFF`.

### Engine

```bash
make -C src deps TARGET=manager
make -C src TARGET=manager ENGINE_TEST=1
cd src/build/engine && ctest --output-on-failure
```

Do not combine `ENGINE_TEST` with `TEST`: with any `TEST` value set, the engine test option is skipped and the engine tests are built with AddressSanitizer forced on.

### Framework and API

The framework and API workflows run Python 3.12 and need `wazuh-manager-conf`, which `wazuh.core.manager_conf` runs (from `src/build/bin` in a checkout):

```bash
make -C src deps TARGET=manager
cmake -S src -B src/build -DTARGET=manager && cmake --build src/build --target wazuh-manager-conf
python -m venv venv && source venv/bin/activate
pip install -r framework/requirements-dev.txt --no-build-isolation
export PYTHONPATH=$PWD/api:$PWD/framework
python -m pytest framework --ignore=tests     # 5_testunit_framework.yml
python -m pytest api/api --ignore=test        # 5_testunit_api.yml
```

## Integration tests

### Manager

The suites under `tests/integration/` run against an **installed** manager and use the [QA integration framework](https://github.com/wazuh/qa-integration-framework). CI runs them with the Python version in `.github/workflows/.python-version-it`.

1. Install the manager under test, from sources (see [Run from Sources](run-sources.md)) or from a package, and make sure it starts: the indexer credential `WAZUH_INDEXER_MANAGER_PASSWORD` must be in `/etc/wazuh/credentials.env` (see [Credentials](../ref/getting-started/credentials.md)).

2. Install the integration test framework from the branch that matches yours. CI tries the branch name, then the base branch, then the version in `VERSION.json`, then `main`:

   ```bash
   git clone -b "$QA_BRANCH" --single-branch https://github.com/wazuh/qa-integration-framework.git
   sudo pip install qa-integration-framework/
   rm -rf qa-integration-framework/
   ```

3. Run one suite at a time, as root, pointing the framework at the installation:

   ```bash
   cd tests/integration
   sudo WAZUH_PATH=/var/wazuh-manager python -m pytest --tier <TIER> <TEST FOLDER>/ \
     --html=results.html --self-contained-html
   ```

The test execution generates an HTML report at `tests/integration/results.html`. The suites, their targets and tiers are listed in `.github/test_modules_manager.json`.

### API

The API integration tests deploy a Docker Compose environment (a three-node manager cluster, agents and an HAProxy load balancer) built from the **pushed** branch, and run [Tavern](https://tavern.readthedocs.io/en/latest/) test files against it:

```bash
pip install -r framework/requirements-dev.txt
cd api/test/integration
python3 -m pytest test_agent_GET_endpoints.tavern.yaml --disable-warnings
```

The environment, the test files, the RBAC tests, `--nobuild` and the `run_tests.py` helper are described in `api/test/integration/README.md`.
