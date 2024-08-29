---
name: External integrations issue
about: Report a bug or make a feature request for the AWS, Azure, GCloud or docker-listener
  external integrations.
title: ''
labels: ''
assignees: ''

---

| Affected integration |
|---|
| AWS, GCloud, Azure...|

<!--
Whenever possible, issues should be created for bug reporting and feature requests.
For questions related to the user experience, please refer to:
- Wazuh mailing list: https://groups.google.com/forum/#!forum/wazuh
- Join Wazuh on Slack: https://wazuh.com/community/join-us-on-slack

Please fill in the table above. Feel free to extend it at your convenience.
-->


## Description
<!--
In case of a feature request of a new service please provide example logs of that service copying them inside the <details> tag below.

In case of a bug report:
- Indicate the Wazuh version.
- Tell if it has failed on a manager, an agent, or both.
- Attach logs that illustrate the bug inside the <detail> tag below -you may want to set debug options `wazuh_modules.debug=2` and restart Wazuh (see https://documentation.wazuh.com/current/user-manual/reference/internal-options.html) to get verbose logs. This may help investigate the issue-.

<details><summary><SERVICE> logs</summary>

<p>

```
<COPY LOGS HERE>
```
</p>

</details>
-->

## Tasks
- [ ] Test in a manager.
- [ ] Test in an agent.
- [ ] Unit tests without failures. Updated if there are any relevant changes.
- [ ] Integration tests without failures. Updated if there are any relevant changes.
- [ ] Update the documentation if necessary.
- [ ] Add entry to the changelog if necessary.
