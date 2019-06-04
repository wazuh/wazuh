|Related issue|
|---|
||

<!--
This template reflects sections that must be included in new Pull requests.
Contributions from the community are really appreciated. If this is the case, please add the 
"contribution" to properly track the Pull Request.

Please fill the table above. Feel free to extend it at your convenience.
-->

## Description

<!--
Add a clear description of how the problem has been solved.
-->

## Configuration options

<!--
When proceed, this section should include new configuration parameters.
-->

## Logs/Alerts example

<!--
Paste here related logs and alerts
-->

## Tests

<!--
At least, the following checks should be marked to accept the PR.
-->

- Compilation without warnings in every supported platform
  - [ ] Linux
  - [ ] Windows
  - [ ] MAC OS X
- [ ] Source installation
- [ ] Package installation
- [ ] Source upgrade
- [ ] Package upgrade
- Memory tests
  - [ ] Valgrind report for affected components
  - [ ] CPU impact
  - [ ] RAM usage impact
- [ ] Retrocompatibility with older Wazuh versions
- [ ] Working on cluster environments
- [ ] Configuration on demand reports new parameters
- [ ] Review logs syntax and correct language
- [ ] QA templates contemplate the added capabilities
