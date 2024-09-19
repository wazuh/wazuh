---
name: Vulnerability Detection - Report false negative/positive
about: Report false positive or false negative vulnerability detection for a specific package.
title: 'False [Positive/Negative] for [CVE-XXXX-XXXX] for [APPLICATION NAME] on [OS NAME/VERSION]'
labels: ''
assignees: ''

---
<!-- 
To help us address this issue, please provide detailed information about the affected application and operating system. This data should be retrieved via the Wazuh API.
For instructions on using the Wazuh API, refer to: https://documentation.wazuh.com/current/user-manual/api/index.html

Note: If reporting multiple CVEs, the title of the issue can indicate this by using a general description (e.g., "Multiple CVEs" or "Several CVEs") rather than listing each CVE individually.

-->

### Description

<!-- 
Provide a brief description of the issue you are experiencing. Explain whether it is a false positive or a false negative, and include any relevant context or observations.
-->


### Vulnerability Report

<!-- Please specify whether you are reporting a false positive or a false negative, and provide details on the affected CVEs. -->

- **Type**:
  - [ ] False positive
  - [ ] False negative
- **CVEs**:
  - CVE-XXXX-XXXX
  - [Add more if necessary]

### Package Details

<!-- 
Insert in the block below the result of the query to retrieve Syscollector information for the specified package:

GET /syscollector/<AGENT_ID>/packages?name=<PACKAGE_NAME>

Reference:
 - https://documentation.wazuh.com/current/user-manual/api/reference.html#operation/api.controllers.syscollector_controller.get_packages_info

NOTE: If reporting multiple packages, use separate blocks for each.
-->

```json

```

### Operating System Details

<!-- 
Insert in the block below the result of the query to retrieve Syscollector OS information:

GET /syscollector/<AGENT_ID>/os

Reference: https://documentation.wazuh.com/current/user-manual/api/reference.html#operation/api.controllers.syscollector_controller.get_os_info
-->

```json

```

### Hotfixes

<!-- 
NOTE: This section applies only to the Windows operating system. You may remove this section if the report is for a non-Windows application.

Insert in the block below the result of the query to retrieve Syscollector hotfixes information

GET /syscollector/<AGENT_ID>/hotfixes

Reference: https://documentation.wazuh.com/current/user-manual/api/reference.html#operation/api.controllers.syscollector_controller.get_hotfix_info
-->

```json

```

---

## Tasks
<!-- This section is to be completed by the Wazuh team. -->

- [ ] **Perform Root Cause Analysis**: Investigate and document the root cause of the false positive/negative. 
- [ ] **Create Related Issues**: Open any required issues for content generation fixes, translation updates, or sanitizations.
- [ ] **Validate Content Availability**: Ensure that the changes introduced by the issues above are published and available for use.
- [ ] **Add Efficacy Tests**: Add or update tests to verify that the content accurately detects or avoids the reported CVEs.