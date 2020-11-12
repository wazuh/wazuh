---
name: API/Framework issue 
about: Report a bug or make a feature request.
title: ''
labels: ''
assignees: ''

---

|Wazuh version|Component|
|---|---|
| X.Y.Z-rev | Wazuh component |

<!--
Whenever possible, issues should be created for bug reporting and feature requests.
For questions related to the user experience, please refer:
- Wazuh mailing list: https://groups.google.com/forum/#!forum/wazuh
- Join Wazuh on Slack: https://wazuh.com/community/join-us-on-slack

Please fill the table above. Feel free to extend it at your convenience.
-->



## Checks

- **Unit tests** without failures. Updated and/or expanded if there are new functions/methods/outputs:
  - [ ] Cluster (`framework/wazuh/core/cluster/tests/` & `framework/wazuh/core/cluster/dapi/tests/`)
  - [ ] Core (`framework/wazuh/core/tests/`)
  - [ ] SDK (`framework/wazuh/tests/`)
  - [ ] RBAC (`framework/wazuh/rbac/tests/`)
  - [ ] API (`api/api/tests/`)
- **API tavern integration tests** without failures. Updated and/or expanded if needed (`api/test/integration/`):
  - [ ] Affected tests 
  - [ ] Affected RBAC (black and white) tests
- [ ] **Changelog** (`CHANGELOG.md`)
- [ ] **Documentation** (`/wazuh-documentation/source/user-manual/api`)
    
<!-- If changes are made to any of the following components, uncomment the corresponding line 
- [ ] **Integration tests** without failures for API configuration (`/wazuh-qa/tests/integration/test_api/test_config/`)
- [ ] **System tests** for agent enrollment process (`/wazuh-qa/tests/system/test_cluster/test_agent_enrollment`)
- [ ] **System tests** for agent info sync process in cluster (`/wazuh-qa/tests/system/test_cluster/test_agent_info_sync`)
- [ ] **System tests** for agent key polling (`/wazuh-qa/tests/system/test_cluster/test_agent_key_polling`)
- [ ] **System tests** for JWT invalidation (`/wazuh-qa/tests/system/test_jwt_invalidation`)
-->