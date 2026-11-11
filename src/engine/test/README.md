# End-to-End Tests for the Wazuh Engine

This directory contains the end-to-end test suites of the engine (`wazuh-manager-analysisd`, built as
`src/build/engine/wazuh-engine`). They run the engine binary in standalone mode
(`WAZUH_ENGINE_STANDALONE=true`) inside a sandbox directory and drive it through its API socket.

## Test Categories

- **Integration Tests** (`integration_tests/`): behave features that exercise the engine API (router,
  tester, content CRUD, namespaces, geo, status), run with the `engine-it` tool.
- **Helper Functions Tests** (`helper_tests/`): tests generated from the helper function descriptions, run
  with the `engine-helper-test` tool. The same descriptions generate the helper functions reference.
- **Acceptance Tests** (`acceptance_test/`): a load test of a manager installation, run by hand.

Both the integration and the helper tests run in
[5_testintegration_engine.yml](../../../.github/workflows/5_testintegration_engine.yml) (jobs `api_tests` and
`helper_tests`). The acceptance test is not run by CI.

## Environment Setup Script

The `setupEnvironment.py` script prepares the sandbox directory the integration and helper tests run in:

- copies the `engine-schema`, `wazuh-logpar-overrides` and `allowed-fields` schemas from `ruleset/schemas/`
  into `<env>/store/schema/<name>/0`;
- creates `<env>/queue/sockets`, `queue/keystore`, `kvdb`, `logs`, `outputs` and `content`;
- copies the IANA time zone database from `src/external/tzdata` into `<env>/tzdb/iana`;
- copies the engine binary `src/build/engine/wazuh-engine` into `<env>/wazuh-engine`;
- stores test indexer credentials in `<env>/queue/keystore` with `src/build/bin/wazuh-manager-keystore`
  (run with `WAZUH_MANAGER_HOME=<env>`), because the engine's indexer connector refuses to start without them.
  Run as root, that tool switches to the `wazuh-manager` account, so the script gives `<env>/queue/keystore`
  to that user first; a sandbox created by root then needs no manual `chown`. This assumes the usual
  umask: only `<env>/queue/keystore` changes hands, not the directories above it, so under a umask that
  clears the search bit for others (`027`, say) `wazuh-manager` cannot traverse `<env>` and `<env>/queue`
  and the tool fails with the same `Permission denied` as before.

It exits with an error when the time zone database (run `make -C src deps TARGET=manager` first), the engine
binary or the keystore tool (build the manager tree first) is missing. It writes no `config.env`: the
`init` subcommand of each test tool does.

### Prerequisites

- **Python 3.8+** and **pip3**
- **api-communication**: client library for the engine API socket.
- **engine-suite**: engine command-line tools; the test tools import its shared settings.
- **engine-test-utils**: utilities used by the tests (engine process handler).
- **engine-it** and/or **engine-helper-test**: the test runners.

### Installation

From `src/engine/` (the order matters: each package depends on the previous ones, which are not published):

```bash
pip3 install tools/api-communication
pip3 install tools/engine-suite
pip3 install test/engine-test-utils
pip3 install test/integration_tests/engine-it
pip3 install test/helper_tests/engine-helper-test
```

### Usage

```bash
./test/setupEnvironment.py [-h] [-e ENVIRONMENT]
```

**Optional Arguments:**

- `-h, --help`: Show the help message and exit.
- `-e ENVIRONMENT, --environment ENVIRONMENT`: Directory for the test environment. Default: `environment/`
  at the root of the repository.

**Example:**

```bash
./test/setupEnvironment.py -e /tmp/engine
```

This command sets up the testing environment in the `/tmp/engine` directory. Run it on a fresh directory:
the time zone copy fails when `<env>/tzdb/iana` already exists.

## Running Tests

Follow the instructions in the README of each suite:

- [Integration test](./integration_tests/README.md)
- [Helper test](./helper_tests/README.md)
- [Acceptance test](./acceptance_test/README.md)
