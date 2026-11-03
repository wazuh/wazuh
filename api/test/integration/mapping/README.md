# API integration tests: coverage guard and CI selection

Two scripts, both run by the setup job of
[5_testintegration_api-endpoints.yml](../../../../.github/workflows/5_testintegration_api-endpoints.yml)
before any image is built. Both need only Python 3 and PyYAML.

## Endpoint coverage: `endpoint_coverage.py`

Every operation of [spec.yaml](../../../api/spec/spec.yaml) owes the tavern suite a set of cases
(buckets):

| Bucket | Required when |
|---|---|
| 2xx | always |
| 400 | the operation takes a parameter other than `pretty`/`wait_for_complete`, or a body |
| 401 | the operation has an auth scheme (all of them) |
| 403 | the operation has `x-rbac-actions`; only a `test_rbac_*` file counts |
| 404 | the spec declares 404 |
| 405 | always, on its path (an undeclared method) |
| 413, 415 | the operation takes a body |

The script matches every stage of every `test_*.tavern.yaml` to the operation it calls (the most
literal spec path wins, `parametrize` marks are expanded) and fails when a bucket is empty.

```bash
python3 endpoint_coverage.py           # check; exit 1 lists every gap
python3 endpoint_coverage.py --write   # regenerate COVERAGE.md
```

It also fails when:

- a stage calls a path the spec does not declare, unless it asserts 404 (unknown-route tests);
- a stage asserts something other than 405 on an undeclared method, or 405 on a declared one;
- an entry of [coverage_exceptions.yaml](coverage_exceptions.yaml) has no reason, names an unknown
  operation or bucket, or is stale (the bucket is covered, or not required);
- [COVERAGE.md](COVERAGE.md) differs from what the tavern files and the spec produce.

So a new endpoint needs its stages, including a row in each matrix of
`test_auth_endpoints.tavern.yaml` (401, 405, 415) and, with a body, of
`test_hardening_endpoints.tavern.yaml` (413), and `COVERAGE.md` regenerated. A bucket that cannot be
covered goes to `coverage_exceptions.yaml` with the reason; `pending: true` marks a gap that is
still to be covered.

## Test selection: `select_tests.py` and `selection_rules.yaml`

The lane runs when a pull request touches its `paths:`. Which tavern files it then runs is decided
by [selection_rules.yaml](selection_rules.yaml), an ordered list of rules (first match wins) that
map GitHub path globs to test groups. A group is a tavern file name without `test_`, the method
suffix and `_endpoints.tavern.yaml` (`test_agent_GET_endpoints` → `agent`,
`test_rbac_black_agent_endpoints` → `rbac_black_agent`).

- A changed file outside the workflow `paths:` selects nothing: it cannot reach the environment.
- A rule selects `none`, `self` (the changed tavern file), `all`, or a list of groups (`*` allowed).
- A changed file inside the `paths:` that matches no rule selects everything.
- The union of all changed files is run; renames count both paths. An empty union runs only the
  smoke test.

```bash
python3 select_tests.py --files framework/wazuh/mitre.py src/remoted/main.c
python3 select_tests.py --base origin/main     # what CI does on a pull request
python3 select_tests.py --test-list agent_GET_endpoints,cluster_endpoints
python3 select_tests.py --check                # validate rules, groups and workflow paths
```

`--check` (and [tests/test_select_tests.py](tests/test_select_tests.py)) fails when a rule path
matches no tracked file, a rule group matches no tavern file, a test group has no rule of its own,
a tracked file inside the workflow `paths:` matches no rule, or a rule selects tests for a file the
workflow `paths:` never trigger on. A new tavern module or source file therefore needs its rule,
and a trigger path needs its rule, in the same change.

## Unit tests

```bash
cd api/test/integration/mapping && python3 -m pytest
```

The local `pytest.ini` keeps the tavern `conftest.py` of the parent directory (which brings the
docker environment up) out of these tests.
