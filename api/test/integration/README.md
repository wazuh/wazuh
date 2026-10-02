# API Integration Tests

## General information

An integration test checks that the application modules behave as expected when they are integrated, that is, that
the components interact correctly.

The API integration tests verify that the API works in a complete Wazuh environment, built with
[`docker`](https://www.docker.com/) and Docker Compose V2 (`docker compose`, the plugin).

The `api/test/integration` directory contains the API integration test files and the files used to deploy the
environment.

## API integration tests files

The API integration tests use the [`tavern`](https://tavern.readthedocs.io/en/latest/) framework, a
[`pytest`](https://docs.pytest.org/) plugin for testing HTTP APIs. The test files are YAML and their names follow one
of these formats:

`test_{module}_endpoints.tavern.yaml`, `test_{module}_{METHOD}_endpoints.tavern.yaml` or
`test_rbac_{rbac_mode}_{module}_endpoints.tavern.yaml`

where `module` is the module the tested endpoints belong to (`agent`, `cluster`, `default`, `mitre`, `overview`,
`security`, `all` for RBAC, and the cross-cutting `auth`, `hardening` and `ratelimit` described in
[Test groups and overlays](#test-groups-and-overlays)), `METHOD` splits a module's tests by HTTP method, and `rbac_mode` is the RBAC mode
(`white` or `black`) used for the test (see [RBAC API integration tests](#rbac-api-integration-tests)).

Variables shared by every test (ports, the test user and password, endpoints) are in `common.yaml`, loaded through
`tavern-global-cfg` in `pytest.ini`. `_test_smoke.tavern.yaml` is the smoke test CI runs before the rest.

## Docker environment

The environment is described by `env/docker-compose.yml` and is composed of **12 containers**:

- 3 Wazuh managers forming a cluster: `wazuh-master` (API published on host port `55000`), `wazuh-worker1` and
  `wazuh-worker2`.
- 4 Wazuh agents (`wazuh-agent1` to `wazuh-agent4`) built from the same branch as the managers.
- 4 old Wazuh agents (`wazuh-agent5` to `wazuh-agent8`), installed from the 4.x package repository at version
  `4.14.1` (`env/base/agent/old.Dockerfile`).
- 1 HAProxy load balancer, `haproxy-lb`, that publishes `1514`, `1515` and the API as host port `55010`.

The managers and the new agents are built from the GitHub tarball of the **current branch**, or of the branch, tag or
commit set in the `WAZUH_BRANCH` environment variable (`https://github.com/wazuh/wazuh/tarball/<branch>`), not from
the local working tree, so the branch must be pushed:
`conftest.py` fails the run with *Current branch tarball doesn't exist* otherwise. The Dockerfiles, entrypoints and
other configuration files are in `env/base/`.

Each test also applies **specific configurations and health checks**, found in `env/configurations/`. Python scripts
used by those health checks are in `env/tools/`.

Apart from this setup, two disconnected agents (`wazuh-agent9` and `wazuh-agent10`) are inserted on the master from
`env/configurations/base/manager/configuration_files/master_only/agent_info.yaml`.

### How is the environment deployed?

The environment is deployed automatically when an API integration test is run with `pytest <test_name>` from this
directory.

`conftest.py` deploys it. The session-scoped, autouse fixture `api_test` prepares the configuration for the test
being run (the RBAC mode and resources for an RBAC test), builds the images and brings the containers up
(`docker compose build --build-arg WAZUH_BRANCH=<branch> --no-cache`, then `docker compose up -d`), and waits for
the managers, agents and load balancer to be healthy. When the test finishes it cleans the temporary folders, saves
the logs if any test failed, records the environment status, and stops and removes the containers.

`conftest.py` also holds the functions that build the HTML report and configure [RBAC](#rbac-api-integration-tests).

The environment always runs in **cluster** mode; the tests have no marks.

## RBAC API integration tests

Some test names follow the structure `test_rbac_{rbac_mode}_{module}_endpoints.tavern.yaml`.

These tests check a Wazuh environment configured with RBAC resources. `conftest.py` changes the RBAC mode and
creates the RBAC resources the test in execution needs. The `env/configurations/rbac` directory holds the specific
configuration of each RBAC API integration test, for both **white** and **black** modes. Every other test runs in
white mode.

## Test groups and overlays

Besides the module and RBAC files, three files check what every endpoint shares:

- `test_auth_endpoints.tavern.yaml`: 401 on every operation (no token, forged, unsigned, Basic
  instead of Bearer), 405 on every path, 415 on every body operation, 404 on undeclared routes,
  security headers, token revocation, injection, traversal, query bounds and response time.
- `test_hardening_endpoints.tavern.yaml`: 413 and CORS, with the `hardening` overlay's `api.yaml`.
- `test_ratelimit_endpoints.tavern.yaml`: login blocking and request rate limits, with the
  `ratelimit` overlay's `api.yaml`. Limits count per client address: failed requests go to
  `master_port`, whose only other traffic is `conftest.py`'s successful login, and authenticated
  requests go through HAProxy (`balanced_port`). HAProxy's own health check sends an
  unauthenticated request through it every 5 seconds, so its address cannot carry the failed ones.

`conftest.py` copies `env/configurations/base` and then `env/configurations/<module>` into the
environment, `<module>` being the second word of the file name.

## Coverage and test selection in CI

[mapping/endpoint_coverage.py](mapping/endpoint_coverage.py) fails when an operation of the spec
lacks its success or failure cases, and generates [mapping/COVERAGE.md](mapping/COVERAGE.md), the
endpoint-by-endpoint list of what is covered and by which file. [mapping/select_tests.py](mapping/select_tests.py)
picks the files a pull request runs from [mapping/selection_rules.yaml](mapping/selection_rules.yaml).
Both run in the setup job of the workflow; see [mapping/README.md](mapping/README.md).

## Tests execution

To perform a Wazuh API integration test, install the dependencies CI uses:

```bash
pip install -r framework/requirements-dev.txt
```

Then run a test from this directory:

```bash
cd api/test/integration
python3 -m pytest test_agent_GET_endpoints.tavern.yaml --disable-warnings
```

`conftest.py` adds one option:

| Option | Effect |
|--------|--------|
| `--nobuild` | Skip `docker compose build` and bring the environment up from the images already built. |

The `run_tests.py` script runs a group of tests and saves their reports:

```text
$ python3 run_tests.py -h
usage: run_tests.py [options]

API integration tests

options:
  -h, --help            show this help message and exit
  -l TEST_LIST, --list TEST_LIST
                        Specify a list of tests separated by a comma.
  -e, --exclude         Run every test excluding the already saved in the RESULTS_FOLDER.
  -r, --results         Get result summary from the already run tests.
  -k KEYWORD, --keyword KEYWORD
                        Specify the keyword to filter tests out. Default None.
  -R {both,yes,no}, --rbac {both,yes,no}
                        Specify what to do with RBAC tests. Run everything, only RBAC ones or no RBAC. Default "both".
  -i ITERATIONS, --iterations ITERATIONS
                        Specify how many times will every test be run. Default 1.
```

`run_tests.py` does not show the tests' full output. The reports are saved in `api/test/integration/_test_results`,
and HTML reports in `_test_results/html_reports`. When a test fails, the containers' logs are copied to
`_test_results/logs`: `api.log`, `cluster.log` and `wazuh-manager.log` from each manager, `ossec.log` from each
agent, and the HAProxy container log. The Docker build and startup output is in `_test_results/logs/docker.log`.
