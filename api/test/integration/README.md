# API Integration Tests

## Wazuh environment selection

The API integration tests are performed in a Wazuh environment built using `docker`.

This Wazuh environment will have a different configuration depending on
the [`pytest` mark](https://docs.pytest.org/en/6.2.x/mark.html) used to run the tests with.

- If the `standalone` mark is specified, a Wazuh environment with **1 manager and 12 agents** will be built (no cluster)
  .

- If the `cluster` mark is specified, a Wazuh cluster setup with **3 managers and 12 agents** will be built.

- If **no mark** is specified, a Wazuh cluster setup with **3 managers and 12 agents** will be built.

The following table shows how these marks must be used with the `pytest` command and the environment they build:

| Command  | Environment  |  
|---|---|
|  `pytest TEST_NAME` |  Wazuh cluster environment |  
| `pytest -m cluster TEST_NAME` | Wazuh cluster environment  |
|  `pytest -m standalone TEST_NAME` | Wazuh environment with cluster disabled (standalone)  | 

Apart from choosing the environment to be built, the marks are also used to filter the API integration tests cases. By
default, tests without the `standalone` or `cluster` marks, will have both of them implicitly. Test cases with **only
standalone** can only be passed in a Wazuh environment with cluster disabled; and cases with **only cluster** mark can
only be passed in a Wazuh cluster environment.

Talking about **RBAC API integration tests**, they don't have any marks so there is no need to specify one when running
them. If a mark is specified, no tests will be run due to the filters. In other words, **RBAC tests are always going to be
performed in the default cluster setup**.
