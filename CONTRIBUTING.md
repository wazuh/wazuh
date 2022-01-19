## Introduction

Thanks for your interest in contributing to Wazuh. In this guide, you can find how the contributing process works and what to expect from it.

## When to open an issue

If you're unsure whether Wazuh is malfunctioning or has a configuration/usage problem, please use our [Slack community channel](https://wazuh.com/community/join-us-on-slack/)  to ask for support! The Wazuh team monitors and actively participates in this channel!.

Also, before opening an issue, check if there is one already opened for the same problem!

On the other hand, consider opening an issue if:
*  You're getting an uncontrolled error, like a stack trace, core dump, or some other undefined behavior.
*  A component of Wazuh is not behaving as documented.
*  Wazuh is not behaving as expected.

GitHub will offer you a set of templates to work on the issue report. If you're unsure how to include some of the required information, please ask about it in our [Slack community channel](https://wazuh.com/community/join-us-on-slack/).

## How to alert about vulnerability

Wazuh has thousands of users around the world. Help us protect our community by reporting any security issue to **[security@wazuh.com](mailto:security@wazuh.com)**.

When to contact the security mailbox:
* If you have a suspicion that an issue could be a vulnerability.
* If you're a security researcher who has found evidence of a vulnerability.

Please include all the relevant information about the context in which Wazuh might exhibit the problem, including:
- Version of all Wazuh pacakges.
- Operating system version, including patch level.
- Deployment method used.
- The link to the release used.
- Details about the discovery process.
- A way to reproduce the issue.

The information sent to the security mailbox [security@wazuh.com](mailto:security@wazuh.com) will be confidential. We will ask for permission before publishing anything sent to it publicly.

After the report, we will analyze the possible vulnerability, and if we verify there is a vulnerability in Wazuh, we will work on a fix. When the fix is available, we will publish the vulnerability details, and we will register a CVE, so our community can check if their Wazuh version is affected.

Security vulnerabilities are a top priority for us, so we will work hard to deliver a fix as soon as humanly possible.

All vulnerabilities will be credited to their authors appropriately:
- In our announcements.
- In the CVE.
- In the related issues.

As a user, you can subscribe to our [security anouncement](mailto:wazuh-security-anouncement+subscribe@googlegroups.com) mail list to receive information about published vulnerabilities.

## How to contribute documentation

If you see any typo, error or inacuracy on our [documentation site](https://documentation.wazuh.com) , please see our documentation [contributing guide](https://github.com/wazuh/wazuh-documentation/blob/develop/CONTRIBUTING.md)
in our documentation [repo](https://github.com/wazuh/wazuh-documentation/).

## How to contribute code

**Please do not hesitate to ask about this process in in our [Slack community channel](https://wazuh.com/community/join-us-on-slack/).**

As with many other open-source projects, the general workflow comprises the following steps:

 * Set up a development environment as explained in the developers [wiki]().
 * Clone (and maybe fork) this repository.
 * Work on the changes you want to contribute.
 * When your finish your changes, test your changes, as explained in the testing [wiki]().
 * If all the tests passed, create a pull request following the GitHub [documentation](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/about-pull-requests).

From this point on, the process of code review starts. A member of Wazuh team will be assigned to review the pull request.

This reviewer will be in charge of ensuring:
* The code follows our development guides and code quality standards. Information regarding these guides can be found in the project [wiki]().
* All the relevant tests have been passed successfully.
* The PR does not break other components which might not be directly related to the changes.


Sometimes more than one review will be necessary, and a reviewer might want others' opinions before accepting a PR by assigning other team members as additional reviewers.

When the PR is accepted, it will be merged and included in the [release process](wiki). Some changes might be back-ported to older releases to fix bugs and security vulnerabilities.

You might find other repositories in the Wazuh organization. Please check the CONTRIBUTING.md guide of each repo if you want to contribute to other Wazuh repositories!

### Git usage notes

All the PRs and commits must be signed with a verifiable key. Please read GitHub [documentation about this](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

## Contributions and license agreement

All contributions will be attributed to its creator through the git history, and the creators' names will be added in our CONTRIBUTORS file. 

All the contributions will be automatically licensed using AGPL 2.0. Please be sure to accept this before opening issues, PRs, or other contributions.

Any contribution might be removed on future releases, refactors, or other changes, but the contributors' name will not be deleted from the CONTRIBUTORS file.

If your contact information changed, open a PR against the CONTRIBUTORS file with an update.


