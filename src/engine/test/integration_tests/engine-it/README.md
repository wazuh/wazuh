# engine-it

`engine-it` runs the engine's behave integration suites (`src/engine/test/integration_tests/`) against an
engine binary in a sandbox environment. How to prepare the environment and run the suites:
[integration tests README](../README.md).

## Installation

From `src/engine/`, after its dependencies `tools/api-communication`, `tools/engine-suite` and
`test/engine-test-utils` (none is published; `behave` is installed from PyPI):

```bash
pip3 install test/integration_tests/engine-it
```

## Usage

```bash
usage: engine-it [-h] -e ENVIRONMENT -t TEST_DIR {init,run} ...
```

- `-e/--environment`: the environment directory prepared by `test/setupEnvironment.py`. It must contain the
  engine binary `wazuh-engine` and, for `run`, the `config.env` written by `init`.
- `-t/--test-dir`: the directory holding the suites (`test/integration_tests`).
- `init`: copies `<test-dir>/configuration_files/config.env` into the environment (replacing the path
  placeholder with the environment directory, and keeping a previous one as `config.env.bak`), seeds the
  store, starts the engine and creates the `testing` namespace with the test resources, then stops it. Exits 1
  on any error.
- `run [-f FEATURE]`: runs `behave --tags ~exclude --format progress2` on every subdirectory of the test
  directory that has both `features/` and `steps/`, or only on the given feature file. It exports `ENV_DIR`,
  `BINARY_DIR` (the engine binary) and `CONF_FILE` (the `config.env`) for the suites' `environment.py`, and
  exits 1 if any suite fails. It exits 0 when it finds no suite, so CI checks that at least one started.
