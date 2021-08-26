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
Depending on the affected components by this PR, the following checks should be selected and marked.
-->

<!-- Minimum checks required -->
- Compilation without warnings in every supported platform
  - [ ] Linux
  - [ ] Windows
  - [ ] MAC OS X
- [ ] Source installation
- [ ] Package installation
- [ ] Source upgrade
- [ ] Package upgrade
- [ ] Review logs syntax and correct language
- [ ] QA templates contemplate the added capabilities

<!-- Depending on the affected OS -->
- Memory tests for Linux
  - [ ] Scan-build report
  - [ ] Coverity
  - [ ] Valgrind (memcheck and descriptor leaks check)
  - [ ] Dr. Memory
  - [ ] AddressSanitizer
- Memory tests for Windows
  - [ ] Scan-build report
  - [ ] Coverity
  - [ ] Dr. Memory
- Memory tests for macOS
  - [ ] Scan-build report
  - [ ] Leaks
  - [ ] AddressSanitizer

<!-- Checks for huge PRs that affect the product more generally -->
- [ ] Retrocompatibility with older Wazuh versions
- [ ] Working on cluster environments
- [ ] Configuration on demand reports new parameters
- [ ] The data flow works as expected (agent-manager-api-app)
- [ ] Added unit tests (for new features)
- [ ] Stress test for affected components

<!-- Ruleset required checks, rules/decoder -->
- Decoder/Rule tests
  - [ ] Added unit testing files ".ini"
  - [ ] runtests.py executed without errors