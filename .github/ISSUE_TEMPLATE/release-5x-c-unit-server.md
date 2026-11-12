---
name: Release - 5.x - C unit tests - Server
about: Report the results after running the server C unit tests for a release stage.
title: 'Release {{VERSION}} - {{STAGE}} - C unit tests - Server'
labels: 'level/task, type/test'
assignees: ''
---

This issue aims to run all server C unit tests for the current stage, through the workflows listed below, and report the results.

## C unit tests information
|  |  |
|--|--|
| **Main release stage issue** | {{STAGE_ISSUE}} |
| **Version** | {{VERSION}} |
| **Stage** | {{STAGE}} |
| **Tag** | [{{TAG}}](https://github.com/wazuh/wazuh/tree/{{TAG}}) |
| **Previous C unit tests issue** | {{PREVIOUS_ISSUE}} |

## Workflows
```yaml
workflows:
  - name: "CA bundle unit tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testunit_cabundle.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "Content manager unit tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testunit_contentmanager.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "Credentials unit tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testunit_credentials.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "Engine unit tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testunit_engine.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "Indexer connector unit tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testunit_indexerconnector.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "Inventory sync server unit tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testunit_inventorysyncserver.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "Keystore server unit tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testunit_keystoreserver.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "Manager certs unit tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testunit_managercerts.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "Manager config unit tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testunit_managerconfig.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "Metrics unit tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testunit_metrics.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "Shared modules utils unit tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testunit_shared_modules_utils.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "Task manager unit tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testunit_taskmanager.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "UDS HTTP server unit tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testunit_uds_http_server.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "Vulnerability scanner unit tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testunit_vulnerability-scanner.yml"
    ref: "{{TAG}}"
    inputs: {}
```

## Test report procedure
Any failing test should be properly addressed with a new issue, detailing the error and the possible cause. Then, it will be determined if that failure is to be fixed immediately or marked as expected if there is enough support and approval. In case a test is marked as expected-fail, the issue detailing the error should always be used as a reference in the test.

## Conclusion
List every new or known issue that appeared while testing this task, with its link, before closing this issue.

| Status | Test | Failure type | New or known issues (with link) | Notes |
|---|---|---|---|---|
|  | 5_testunit_engine / Build Manager |  |  |  |
|  | 5_testunit_inventorysyncserver / inventorysyncserver-modules |  |  |  |
|  | 5_testunit_inventorysyncserver / inventorysyncserver-asan |  |  |  |
|  | 5_testunit_vulnerability-scanner / vulnerability-scanner-modules |  |  |  |
|  | 5_testunit_vulnerability-scanner / vulnerability-scanner-modules-asan |  |  |  |
|  | 5_testunit_indexerconnector / indexerconnector-modules |  |  |  |
|  | 5_testunit_indexerconnector / indexerconnector-asan |  |  |  |
|  | 5_testunit_contentmanager / contentmanager-modules |  |  |  |
|  | 5_testunit_contentmanager / contentmanager-asan |  |  |  |
|  | 5_testunit_metrics / metrics-modules |  |  |  |
|  | 5_testunit_metrics / metrics-asan |  |  |  |
|  | 5_testunit_shared_modules_utils / shared_modules_utils-modules |  |  |  |
|  | 5_testunit_shared_modules_utils / shared_modules_utils-asan |  |  |  |
|  | 5_testunit_uds_http_server / udshttpserver-modules |  |  |  |
|  | 5_testunit_uds_http_server / udshttpserver-asan |  |  |  |
|  | 5_testunit_cabundle / cabundle-modules |  |  |  |
|  | 5_testunit_cabundle / cabundle-asan |  |  |  |
|  | 5_testunit_credentials / credentials-python-tests |  |  |  |
|  | 5_testunit_keystoreserver / keystoreserver-modules |  |  |  |
|  | 5_testunit_keystoreserver / keystoreserver-asan |  |  |  |
|  | 5_testunit_managercerts / managercerts-modules |  |  |  |
|  | 5_testunit_managercerts / managercerts-asan |  |  |  |
|  | 5_testunit_managerconfig / managerconfig-modules |  |  |  |
|  | 5_testunit_managerconfig / managerconfig-asan |  |  |  |
|  | 5_testunit_taskmanager / taskmanager-modules |  |  |  |
|  | 5_testunit_taskmanager / taskmanager-asan |  |  |  |
|  | 5_testunit_linux-win / Unit-Tests (manager) (run from the Agent C unit issue) |  |  |  |

## Auditors' validation
In order to close and proceed with the release or the next candidate version, the following auditors must give the green light to this RC.

- [ ] @wazuh/devel-xdrsiem-server-div1
- [ ] @wazuh/devel-xdrsiem-qa-release
