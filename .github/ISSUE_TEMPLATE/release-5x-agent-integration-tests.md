---
name: Release - 5.x - Agent integration tests
about: Report the results after running the agent integration tests for a release stage.
title: 'Release {{VERSION}} - {{STAGE}} - Agent integration tests'
labels: 'level/task, type/test'
assignees: ''
---

The tests will be performed on GitHub workflows. Linux, Windows, and macOS will be used as required.

## Agent integration tests information
|  |  |
|--|--|
| **Main release stage issue** | {{STAGE_ISSUE}} |
| **Version** | {{VERSION}} |
| **Stage** | {{STAGE}} |
| **Tag** | [{{TAG}}](https://github.com/wazuh/wazuh/tree/{{TAG}}) |
| **Previous agent integration tests issue** | {{PREVIOUS_ISSUE}} |

## Workflows
```yaml
workflows:
  - name: "IT Linux: agentd (tier-0-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_linux-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "agentd"
      shard_name: "tier-0-1"
      pytest_target: "test_agentd/"
      pytest_tier_args: "--tier 0 --tier 1"
  - name: "IT Linux: aws (tier-0)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_linux-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "aws"
      shard_name: "tier-0"
      pytest_target: "test_aws/"
      pytest_tier_args: "--tier 0"
      setup_aws_credentials: "true"
  - name: "IT Linux: aws (tier-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_linux-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "aws"
      shard_name: "tier-1"
      pytest_target: "test_aws/"
      pytest_tier_args: "--tier 1"
      setup_aws_credentials: "true"
  - name: "IT Linux: enrollment (tier-0-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_linux-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "enrollment"
      shard_name: "tier-0-1"
      pytest_target: "test_enrollment/"
      pytest_tier_args: "--tier 0 --tier 1"
      pre_install: "sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0 2>/dev/null || true; sudo sysctl -w net.ipv6.conf.lo.disable_ipv6=0 2>/dev/null || true; sudo ip -6 addr add ::1/128 dev lo 2>/dev/null || true"
  - name: "IT Linux: execd (tier-0-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_linux-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "execd"
      shard_name: "tier-0-1"
      pytest_target: "test_execd/"
      pytest_tier_args: "--tier 0 --tier 1"
  - name: "IT Linux: fim (tier-0)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_linux-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "fim"
      shard_name: "tier-0"
      pytest_target: "test_fim/"
      pytest_tier_args: "--tier 0"
      pre_install: "sudo apt-get update && sudo apt-get install auditd -y && (sudo /usr/sbin/auditd || true)"
  - name: "IT Linux: fim (tier-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_linux-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "fim"
      shard_name: "tier-1"
      pytest_target: "test_fim/"
      pytest_tier_args: "--tier 1"
      pre_install: "sudo apt-get update && sudo apt-get install auditd -y && (sudo /usr/sbin/auditd || true)"
  - name: "IT Linux: fim (tier-2)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_linux-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "fim"
      shard_name: "tier-2"
      pytest_target: "test_fim/"
      pytest_tier_args: "--tier 2"
      pre_install: "sudo apt-get update && sudo apt-get install auditd -y && (sudo /usr/sbin/auditd || true)"
  - name: "IT Linux: github (tier-0-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_linux-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "github"
      shard_name: "tier-0-1"
      pytest_target: "test_github/"
      pytest_tier_args: "--tier 0 --tier 1"
  - name: "IT Linux: logcollector (tier-0-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_linux-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "logcollector"
      shard_name: "tier-0-1"
      pytest_target: "test_logcollector/"
      pytest_extra_args: "--ignore=test_logcollector/test_read/test_read_journald_basic.py --ignore=test_logcollector/test_read/test_read_journald_ofe.py"
      pytest_tier_args: "--tier 0 --tier 1"
  - name: "IT Linux: office365 (tier-0-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_linux-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "office365"
      shard_name: "tier-0-1"
      pytest_target: "test_office365/"
      pytest_tier_args: "--tier 0 --tier 1"
  - name: "IT Linux: sca (tier-0-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_linux-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "sca"
      shard_name: "tier-0-1"
      pytest_target: "test_sca/"
      pytest_tier_args: "--tier 0 --tier 1"
  - name: "IT Linux: syscollector (tier-0-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_linux-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "syscollector"
      shard_name: "tier-0-1"
      pytest_target: "test_syscollector/"
      pytest_tier_args: "--tier 0 --tier 1"
  - name: "IT Windows: agentd (tier-0-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_windows-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "agentd"
      shard_name: "tier-0-1"
      pytest_target: "test_agentd\\"
      pytest_tier_args: "--tier 0 --tier 1"
  - name: "IT Windows: enrollment (tier-0-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_windows-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "enrollment"
      shard_name: "tier-0-1"
      pytest_target: "test_enrollment\\"
      pytest_tier_args: "--tier 0 --tier 1"
  - name: "IT Windows: execd (tier-0-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_windows-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "execd"
      shard_name: "tier-0-1"
      pytest_target: "test_execd\\"
      pytest_extra_args: "-m win32"
      pytest_tier_args: "--tier 0 --tier 1"
  - name: "IT Windows: fim (tier-0)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_windows-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "fim"
      shard_name: "tier-0"
      pytest_target: "test_fim\\"
      pytest_tier_args: "--tier 0"
      pytest_ignore_args: "--ignore=test_fim\\test_files\\test_basic_usage\\test_rename.py"
      start_service: "true"
  - name: "IT Windows: fim (tier-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_windows-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "fim"
      shard_name: "tier-1"
      pytest_target: "test_fim\\"
      pytest_tier_args: "--tier 1"
      pytest_ignore_args: "--ignore=test_fim\\test_files\\test_basic_usage\\test_rename.py"
      start_service: "true"
  - name: "IT Windows: fim (tier-2)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_windows-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "fim"
      shard_name: "tier-2"
      pytest_target: "test_fim\\"
      pytest_tier_args: "--tier 2"
      pytest_ignore_args: "--ignore=test_fim\\test_files\\test_basic_usage\\test_rename.py"
      start_service: "true"
  - name: "IT Windows: github (tier-0-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_windows-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "github"
      shard_name: "tier-0-1"
      pytest_target: "test_github\\"
      pytest_tier_args: "--tier 0 --tier 1"
  - name: "IT Windows: logcollector (tier-0-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_windows-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "logcollector"
      shard_name: "tier-0-1"
      pytest_target: "test_logcollector\\"
      pytest_tier_args: "--tier 0 --tier 1"
  - name: "IT Windows: office365 (tier-0-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_windows-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "office365"
      shard_name: "tier-0-1"
      pytest_target: "test_office365\\"
      pytest_tier_args: "--tier 0 --tier 1"
  - name: "IT Windows: sca (tier-0-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_windows-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "sca"
      shard_name: "tier-0-1"
      pytest_target: "test_sca\\"
      pytest_extra_args: "-m win32"
      pytest_tier_args: "--tier 0 --tier 1"
  - name: "IT Windows: syscollector (tier-0-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_windows-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "syscollector"
      shard_name: "tier-0-1"
      pytest_target: "test_syscollector\\"
      pytest_tier_args: "--tier 0 --tier 1"
  - name: "IT macOS: fim (tier-0)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_macos-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "fim"
      shard_name: "tier-0"
      pytest_target: "test_fim/"
      pytest_tier_args: "--tier 0"
  - name: "IT macOS: fim (tier-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_macos-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "fim"
      shard_name: "tier-1"
      pytest_target: "test_fim/"
      pytest_tier_args: "--tier 1"
  - name: "IT macOS: logcollector (tier-0-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_macos-integration-tests.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      module_name: "logcollector"
      shard_name: "tier-0-1"
      pytest_target: "test_logcollector/"
      pytest_tier_args: "--tier 0 --tier 1"
  - name: "IT Linux: msgraph (tier-0-1)"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_msgraph-tier-0-1-lin.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
```

### Legend

🟢 The pipeline has been executed successfully.
🟡 The pipeline is still in progress.
🔴 The pipeline has failed.

## Conclusion
List every new or known issue that appeared while testing this task, with its link, before closing this issue.

| Status | Test | Failure type | New or known issues (with link) | Notes |
|---|---|---|---|---|
|  | IT Linux: agentd (tier-0-1) |  |  |  |
|  | IT Linux: aws (tier-0) |  |  |  |
|  | IT Linux: aws (tier-1) |  |  |  |
|  | IT Linux: enrollment (tier-0-1) |  |  |  |
|  | IT Linux: execd (tier-0-1) |  |  |  |
|  | IT Linux: fim (tier-0) |  |  |  |
|  | IT Linux: fim (tier-1) |  |  |  |
|  | IT Linux: fim (tier-2) |  |  |  |
|  | IT Linux: github (tier-0-1) |  |  |  |
|  | IT Linux: logcollector (tier-0-1) |  |  |  |
|  | IT Linux: office365 (tier-0-1) |  |  |  |
|  | IT Linux: sca (tier-0-1) |  |  |  |
|  | IT Linux: syscollector (tier-0-1) |  |  |  |
|  | IT Windows: agentd (tier-0-1) |  |  |  |
|  | IT Windows: enrollment (tier-0-1) |  |  |  |
|  | IT Windows: execd (tier-0-1) |  |  |  |
|  | IT Windows: fim (tier-0) |  |  |  |
|  | IT Windows: fim (tier-1) |  |  |  |
|  | IT Windows: fim (tier-2) |  |  |  |
|  | IT Windows: github (tier-0-1) |  |  |  |
|  | IT Windows: logcollector (tier-0-1) |  |  |  |
|  | IT Windows: office365 (tier-0-1) |  |  |  |
|  | IT Windows: sca (tier-0-1) |  |  |  |
|  | IT Windows: syscollector (tier-0-1) |  |  |  |
|  | IT macOS: fim (tier-0) |  |  |  |
|  | IT macOS: fim (tier-1) |  |  |  |
|  | IT macOS: logcollector (tier-0-1) |  |  |  |
|  | IT Linux: msgraph (tier-0-1) |  |  |  |

## Auditors' validation
In order to close and proceed with the release or the next candidate version, the following auditors must give the green light to this stage.

- [ ] @wazuh/devel-xdrsiem-agent
- [ ] @wazuh/devel-xdrsiem-qa-release
