---
name: Release - 4.x - Workload benchmarks metrics
about: Report the workload benchmarks metrics for a release stage.
title: 'Release {{VERSION}} - {{STAGE}} - Workload benchmarks metrics'
labels: 'level/task, type/test'
assignees: ''
---

The following issue aims to run all `workload benchmarks` for the current release candidate, report the results, and open new issues for any encountered errors.

## Workload benchmarks metrics information
|  |  |
|--|--|
| **Main release stage issue** | {{STAGE_ISSUE}} |
| **Version** | {{VERSION}} |
| **Stage** | {{STAGE}} |
| **Tag** | [{{TAG}}](https://github.com/wazuh/wazuh/tree/{{TAG}}) |
| **Revision** | 1 |
| **Previous Workload benchmarks metrics issue** | {{PREVIOUS_ISSUE}} |

## Workflows
```yaml
workflows:
  - name: "Workload benchmarks metrics"
    type: "jenkins"
    instance: "jenkins-staging.qa.wazuh.info"
    job: "{{VERSION}}/CLUSTER-Workload_benchmarks_metrics"
    inputs:
      QA_AUTOMATION_REFERENCE: "{{TAG}}"
      TARGET_PKG_VERSION: "{{VERSION}}"
      TARGET_PKG_REVISION: "1"
      TARGET_REPOSITORY: "pre-release"
      VERBOSITY: "-v"
      SOURCE_REFERENCE: "{{TAG}}"
      TEST_TIME: "600"
      LOAD_BALANCER: "elb"
      PROTOCOL: "TCP"
      OS: "debian10"
      AGENT_SIMULATED_VERSION: "{{VERSION}}"
      EVENTS_SIZE: "0"
      MODE: "AGENTS"
      AGENTS_NUMBER: "50000"
      MANAGER_WORKERS: "25"
      INDEXER_NODES: "0"
      DASHBOARD: "false"
      PARSE_CLUSTER_LOGS: "true"
      CLUSTER_TESTS: "performance,reliability"
      KIBANA_API_REQUESTS: "false"
      TEST_PERFORMANCE_API_ENDPOINTS: "true"
      EXTRA_LOAD_API_REQUESTS: "false"
      UNIFY_BINARY_PROCESSES_FOR_PLOTTING: "false"
      MANAGERS_AWS_DEPLOYMENT: "EC2"
      MANAGER_INSTANCES: "auto"
      AGENT_INSTANCES: "auto"
      VOLUME_IOPS: "3000"
      FIM_EPS: "0"
      ROOTCHECK_EPS: "0"
      SYSCOLLECTOR_EPS: "0"
      VULNERABILITY_EPS: "0"
      LOGCOLLECTOR_EPS: "0"
      SCA_EPS: "0"
      WINDOWS_EVENT_EPS: "0"
      HOST_INFO_EPS: "0"
      FIM_INTEGRITY_EPS: "0"
      USE_INFINITE_MODE_EVENTS: "true"
      MANAGER_MONITORING_PROCESSES: "wazuh-db,wazuh-apid,wazuh_clusterd"
      MANAGER_MONITORING_STATS: ""
      INDEXER_MONITORING: ""
      INDEXER_MONITORING_STATS: ""
      DASHBOARD_MONITORING: ""
      API_REQUESTS_PERCENTAGE: ""
      LOGGING: "alerts.log"
      GROUPS_NUMBER: "0"
      FILES_NUMBER_PER_GROUP: "0"
      BYTES_NUMBER_PER_FILE: "0"
      DEVELOPMENT: "false"
      DESTROY_INSTANCES: "true"
```

## Test report procedure
All individual test checks must be marked as:
|                                  |                                            |
|---------------------------------|--------------------------------------------|
| Pass | The test ran successfully. |
| Xfail | The test was expected to fail and it failed. It must be properly justified and reported in an issue.  |
| Skip | The test was not run. It must be properly justified and reported in an issue.  |
| Fail | The test failed. A new issue must be opened to evaluate and address the problem. |

All test results must have one the following statuses: 
|                                  |                                            |
|---------------------------------|--------------------------------------------|
| :green_circle:  | All checks passed. |
| :red_circle:  | There is at least one failed check. |
| :yellow_circle:  | There is at least one expected fail or skipped test and no failures. |

Any failing test must be properly addressed with a new issue, detailing the error and the possible cause. It must be included in the `Fixes` section of the current release candidate main issue.

Any expected fail or skipped test must have an issue justifying the reason. All auditors must validate the justification for an expected fail or skipped test.

An extended report of the test results must be attached as a zip or txt. This report can be used by the auditors to dig deeper into any possible failures and details.

## Conclusion
List every new or known issue that appeared while testing this task, with its link, before closing this issue.

| Status | Test | Failure type | New or known issues (with link) | Notes |
|---|---|---|---|---|
|  | API Performance Tests |  |  |  |
|  | Cluster tests |  |  |  |

## Auditors' validation
The definition of done for this one is the validation of the conclusions and the test results from all auditors.

All checks from below must be accepted in order to close this issue.

- [ ] @wazuh/devel-xdrsiem-server
- [ ] @wazuh/devel-xdrsiem-qa-release
