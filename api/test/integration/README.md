# API Integration Tests

## General information

An integration test is used to check that the behavior of the different application modules is the expected one when
they are integrated. In other words, the integration tests check the correct interaction between the application
components.

The API integration tests are used to verify that the API is working properly in a complete Wazuh environment.
This environment is built using [`docker`](https://www.docker.com/).

The `wazuh/api/test/integration` directory contains all the API integration tests files and directories used for the
environment deployment.

## API integration tests files

The API integration tests files use the [`tavern`](https://tavern.readthedocs.io/en/latest/) framework. Tavern is
a [`pytest`](https://docs.pytest.org/en/7.1.x/) based API testing framework for HTTP, MQTT, or other protocols. These
files are written in the `yaml` language and their names can follow the following formats:

`test_{module}_endpoints.tavern.yaml` or `test_rbac_{rbac_mode}_{module}_endpoints.tavern.yaml`

where `module` is the module which the endpoints tested belong; and `rbac_mode` is the RBAC mode (white or black) used
for the test (see [RBAC API integration tests](#RBAC-API-integration-tests)).

## Docker environment

The Wazuh environment used to perform the API integration tests is built using `docker`.

This environment is composed of **12 docker containers**. These containers have the following components installed: 3
Wazuh managers, that compose a Wazuh cluster (1 master, 2 workers); 4 Wazuh agents with the same version as the managers
forming the cluster; 4 Wazuh agents with version 4.14.1 (old); and 1 HAProxy load balancer.

The Wazuh version used for the managers and non-old agents is the one specified by the branch used to perform the API
integration tests.

The `docker-compose.yml` file used to deploy the environment is at `wazuh/api/test/integration/env`. The `Dockerfile`,
`entrypoint.sh`, and other configuration files can be found in the `base` directory.

We also use specific **configurations and health checks depending on the test executed**. These configurations can be
found at the `configurations` directory. Python scripts commonly used by some of these health checks and files are
located in the `tools` directory.

Apart from this setup, we simulate 2 disconnected and 2 never-connected agents.

### How is the environment deployed?

The environment deployment is done automatically when performing an API integration test. The tests are executed
with `pytest <test_name>`.

The `conftest.py` file is the one in charge of deploying the API integration tests environment. When a test is
performed, the `api_test` function is also executed. This function is responsible for setting up the environment and
cleaning temporary folders, stopping and removing containers; and saving log and environment status, once the test has
finished. The execution of `api_test` is done automatically thanks to the `pytest.fixture` decorator.

In the `conftest.py` file, we can also find functions used to make the HTML report,
configure [RBAC](#RBAC-API-integration-tests), etc.

The environment is brought up automatically when running an API integration test. As seen in the table, the environment runs in **cluster** mode and tests are executed with `pytest`:

| Command                          | Environment                                          |
|----------------------------------|------------------------------------------------------|
| `pytest TEST_NAME`               | Wazuh cluster environment                            |


Talking about [RBAC API integration tests](#RBAC-API-integration-tests), they don't have any marks, so there is no need
to specify one when running them. If a mark is specified, no tests will be run due to the filters. In other words,
**RBAC tests are always going to be performed in the default cluster setup**.

## RBAC API integration tests

As said in previous sections, some test names follow the structure
`test_rbac_{rbac_mode}_{module}_endpoints.tavern.yaml`.

These tests are used to check the proper functioning of a Wazuh environment with RBAC configurations. The `conftest.py`
file includes functions in charge of changing the RBAC mode and creating the specified RBAC resources for the test in
execution. The `env/configurations/rbac` directory includes all the specific configurations for each RBAC API
integration test, for both **white** and **black** modes.

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

Docker Compose v2 (`docker compose`) is required.

Once these requirements are satisfied, we can perform the API integration tests:

```text
$ python3 -m pytest test_agent_GET_endpoints.tavern.yaml --disable-warnings
========================================== test session starts ===========================================
platform linux -- Python 3.9.9, pytest-5.4.3, py-1.11.0, pluggy-0.13.1
rootdir: /home/user/git/wazuh/api/test/integration, inifile: pytest.ini
plugins: html-2.1.1, metadata-2.0.1, tavern-1.0.0
collected 92 items

test_agent_GET_endpoints.tavern.yaml ............................................................. [ 66%]
...............................                                                                    [100%]

============================== 92 passed, 98 warnings in 217.61s (0:03:37) ===============================
```

```text
API integration tests

optional arguments:
  --build-managers-only
                  Recreates only the managers' image once the AIT test environment is built.
  --nobuild
                  Prevents rebuilding the environment when running tests once the images are already created.
  --disable-warnings
                  Disables warnings during test execution.
```

We can also use the `wazuh/api/test/integration/run_tests.py` script. This script includes the possibility to collect a
group of tests to be passed. Script arguments:

```text
$ python3 run_tests.py -h
usage: run_tests.py [options]

API integration tests

optional arguments:
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

The `run_test.py` script does not show the tests' full output. The full reports are saved
at `wazuh/api/test/integration/_test_results`. Containers' logs (`wazuh-manager.log`, agent's `ossec.conf`, `api.log` and `cluster.log`) are stored
at `_test_results/logs`. Reports in HTML format are also generated and can be found at `_test_results/html_reports`.
