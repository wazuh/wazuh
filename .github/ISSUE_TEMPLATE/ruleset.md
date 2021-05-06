---
name: Ruleset issue 
about: Report a bug or make a feature request.
title: ''
labels: ''
assignees: ''

---

|Wazuh version| Component | Action type |
|---| --- | --- |
| X.Y.Z-rev | Rules/Decoders/SCA | Add new/Error/Improve |

<!--
This template reflects sections that must be included in new issues
Contributions from the community are really appreciated. If this is the case, please add the
"contribution" to properly track the issue.
-->

## Description
<!-- Add a detailed description of your issue -->

### Reason
<!-- Detail the reason that motivates this proposed change on the ruleset -->

### Current results
<!--  Include current results -->

### Expected results
<!--  Include expected results -->

## Resources
### Log / Alert examples
<!-- Add any known log, or log source to be managed -->

### Log format reference 
<!-- Add any URL or doc related to vendor or provider log format -->

## Tests
<!-- Depending on tests performed manually, the following checks should be selected and marked. -->

- [ ] Added .ini test file for covering related rules
- [ ] Executed unit tests (runtests.py) for checking ruleset integrity
- [ ] Verified mitre.db integrity
- [ ] Verified compliance mapping 
- [ ] Verified no errors/warnings related in ossec.log
- [ ] Kibana shows alerts
