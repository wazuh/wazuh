|||
| :--                                   | :--                                                       |
| **Main release issue**                | RELEASE_ISSUE                                             |
| **Main release candidate issue**      | RELEASE_CANDIDATE_ISSUE_URL                               |
| **Version**                           | WAZUH_VERSION                                             |
| **Release candidate**                 | RC_VERSION                                                |
| **wazuh/wazuh tag**                   | https://github.com/wazuh/wazuh/tree/vWAZUH_VERSION-TAG    |
| **wazuh/wazuh-qa tag**                | https://github.com/wazuh/wazuh-qa/tree/vWAZUH_VERSION-TAG |
| **Previous release testing issue**    | PREVIOUS_IT                                               |
| **Build**                             | COMPLETE_THIS_FIELD :warning: :warning: :warning:         |

</br>

<details><summary>Parameters</summary></br>

- `PKG_VERSION`: PKG_VERSION
- `PKG_REVISION`: PKG_REVISION
- `TARGET_REPOSITORY`: TARGET_REPOSITORY
- `QA_REFERENCE`: QA_REFERENCE
- `JENKINS_REFERENCE`: JENKINS_REFERENCE
- `LINUX_OS`: LINUX_OS (MANAGER OS)
- `MODULES`: SELECTED_MODULES

</details>

</br>

# Conclusion

</br>

> |Color|Status |
> |:--:|:--|
> | :green_circle: |All tests passed successfully|
> | :yellow_circle: | Known issues were found |
> | :red_circle: | New errors, failures, or defects were found |


## Description

The objective of this issue is to check that the integration tests pass successfully against the version `WAZUH_VERSION` of Wazuh.
