<!--
This template reflects sections that must be included in new Pull requests.
- If a determined section does not apply, it must not be removed but completed with `N/A`.
- Contributions from the community are really appreciated.
-->

## Description

<!--
Provide a brief description of the problem this pull request addresses. Include relevant context to help reviewers understand the purpose and scope of the changes.

If this pull request resolves an existing issue, reference it here. For example:
Closes #<issue_number>
-->

## Proposed Changes

<!--
Summarize the changes made in this pull request. Include:
- Features added
- Bugs fixed
- Any relevant technical details
-->

### Results and Evidence

<!--
Provide evidence of the changes made, such as:
- Logs
- Alerts
- Screenshots
- Before/after comparisons
-->

### Manual tests with their corresponding evidence

<!--
Depending on the affected components by this PR, the following checks should be selected and marked.
The team currently has automated tests whose output should be thoroughly reviewed and contrasted.
-->

<!-- Minimum checks required depending on if it is Agent or Manager related -->
- Compilation without warnings on every supported platform
  - [ ] Linux
  - [ ] Windows 
  - [ ] MAC OS X
- [ ] Log syntax and correct language review

<!-- Depending on the affected OS -->
- Memory tests for Linux
  - [ ] Coverity
  - [ ] Valgrind (memcheck and descriptor leaks check)
  - [ ] AddressSanitizer
- Memory tests for Windows
  - [ ] Coverity
  - [ ] UMDH
- Memory tests for macOS
  - [ ] Leaks
  - [ ] AddressSanitizer

- Decoder/Rule tests _(Wazuh v4.x)_
  - [ ] Added unit testing files ".ini"
  - [ ] `runtests.py` executed without errors

- Engine _(Wazuh v5.x and above)_
  - [ ] Test run in parallel
  - [ ] ASAN for test (utest/ctest)
  - [ ] TSAN for test and wazuh-engine.

### Artifacts Affected

<!--
List the artifacts impacted by this pull request, such as:
- Executables (specify platforms if applicable)
- Default configuration files
- Packages
-->

### Configuration Changes

<!--
If applicable, list any configuration changes introduced by this pull request, including:
- New configuration parameters
- Changes to default values
- Backward compatibility notes
-->

### Tests Introduced

<!--
If applicable, describe any new unit or integration tests added as part of this pull request. Include:
- Scope of the tests
- Any relevant details about test coverage
-->

## Review Checklist

<!--
- Each task must be checked to merge the PR (should also be checked if any of these do not apply, giving the corresponding feedback).
- List any manual tests completed to verify the functionality of the changes. Include any manual tests that are still required for final approval.
-->

- [ ] Code changes reviewed
- [ ] Relevant evidence provided
- [ ] Tests cover the new functionality
- [ ] Configuration changes documented
- [ ] Developer documentation reflects the changes
- [ ] Meets requirements and/or definition of done
- [ ] No unresolved dependencies with other issues
- [ ] ...

<!--
Include any additional information relevant to the review process.
-->
