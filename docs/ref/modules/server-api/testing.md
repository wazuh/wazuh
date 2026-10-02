# Testing

The Server API and Framework use `pytest` as the test runner. Unit tests live next to each module;
the API integration tests run against a Docker cluster.

---

## Test Locations

| Location | Scope |
|----------|-------|
| `framework/wazuh/tests/` | Interface layer unit tests (including the RBAC catalog guard, `test_security.py`) |
| `framework/wazuh/core/tests/` | Core logic unit tests |
| `framework/wazuh/core/cluster/tests/`, `framework/wazuh/core/cluster/dapi/tests/` | Cluster and DAPI unit tests |
| `framework/wazuh/core/indexer/tests/` | Indexer client unit tests |
| `framework/wazuh/rbac/tests/` | RBAC unit tests |
| `framework/scripts/tests/` | Framework CLI scripts (`rbac_control`, ...) |
| `api/api/test/` | API layer unit tests |
| `api/api/controllers/test/` | Controller tests |
| `api/test/integration/` | API integration tests (tavern, Docker environment); see `api/test/integration/README.md` |

---

## Running Tests

Install the development requirements, then run the suites from the repository root the way CI does
(`5_testunit_framework.yml`, `5_testunit_api.yml`):

```bash
pip install -r framework/requirements-dev.txt
export PYTHONPATH=$PWD/api:$PWD/framework

# Framework
python -m pytest framework -vv --ignore=tests

# API
python -m pytest api/api -vv --ignore=test
```

`wazuh.core.manager_conf` runs the manager configuration CLI, taken from `src/build/bin/wazuh-manager-conf`
in a repository checkout. CI builds that target before running the framework suite; without it, the
CLI-parity test in `framework/wazuh/core/tests/test_manager_conf.py` is skipped, so a local run passes
without checking it.

### Running specific test modules

```bash
# Interface layer tests
python -m pytest framework/wazuh/tests/

# Core logic tests
python -m pytest framework/wazuh/core/tests/

# API layer tests
python -m pytest api/api/test/
```

---

## Configuration

The unit suites are configured by `framework/pytest.ini` and `api/api/pytest.ini`; the integration
tests by `api/test/integration/pytest.ini`.
