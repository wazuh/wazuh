# Wazuh Open Source Project Security Policy

Version: 2026-07-06

## Introduction
This document outlines the Security Policy for Wazuh's open source projects. It emphasizes our commitment to maintain a secure environment for our users and contributors, and reflects our belief in the power of collaboration to identify and resolve security vulnerabilities.

## Scope
This policy applies to all open source projects developed, maintained, or hosted by Wazuh.

## Reporting Security Vulnerabilities
If you believe you've discovered a potential security vulnerability in one of our open source projects, we strongly encourage you to report it to us responsibly.

Please submit your findings as security advisories under the "Security" tab in the relevant GitHub repository. Alternatively, you may send the details of your findings to [security@wazuh.com](mailto:security@wazuh.com).

## Reporting Vulnerabilities in Non-GA Versions

Wazuh publishes pre-release versions (Alphas, Betas, and Release Candidates) of its open source projects ahead of General Availability (GA) to gather community feedback. If you discover a potential security vulnerability in one of these non-GA versions, please report it following the process described above.

Upon receiving such a report, we will determine whether the vulnerability:

- **Affects only non-GA version(s)**: We will manage the report privately by opening a GitHub Security Advisory (GHSA). Since the affected code has not been part of a GA release, the vulnerability is not eligible for a CVE ID, consistent with the [CNA Operational Rules](https://www.cve.org/ResourcesSupport/AllResources/CNARules). Once resolved, the GHSA will be converted into a public issue instead of a security advisory.
- **Also affects a previously released GA version**: We will continue managing the report as a GHSA and evaluate requesting a CVE ID for the GA-affected versions, in accordance with the eligibility criteria in the CNA Operational Rules.

## Vulnerability Disclosure Policy
Upon receiving a report of a potential vulnerability, our team will initiate an investigation. If the reported issue is confirmed as a vulnerability, we will take the following steps:

1. **Acknowledgment**: We will acknowledge the receipt of your vulnerability report and begin our investigation.
2. **Validation**: We will validate the issue and work on reproducing it in our environment.
3. **Remediation**: We will develop a fix, have it reviewed, and merge it once thoroughly tested.
4. **Release**: We will publish a security release for the affected project that includes the fix.
5. **Rollout**: We will confirm that the fix has been applied to environments managed by Wazuh before proceeding with disclosure.
6. **Disclosure**: Once the fix has been released and confirmed in managed environments, we will publicly disclose the vulnerability by publishing a CVE (Common Vulnerabilities and Exposures), where applicable, and acknowledging the discovering party.
7. **Exceptions**: In order to preserve the security of the Wazuh community at large, we might extend the disclosure period to allow users to patch their deployments.

Steps 1 through 6 will be completed within 90 days from the report of the vulnerability. This period allows for end-users to update their systems and minimizes the risk of widespread exploitation of the vulnerability.

## Automatic Scanning
We leverage GitHub Actions to perform automated scans of our supply chain. These scans assist us in identifying vulnerabilities and outdated dependencies in a proactive and timely manner.

## Credit
We believe in giving credit where credit is due. If you report a security vulnerability to us, and we determine that it is a valid vulnerability, we will publicly credit you for the discovery when we disclose the vulnerability. If you wish to remain anonymous, please indicate so in your initial report.

We do appreciate and encourage feedback from our community, but currently we do not have a bounty program. We might start bounty programs in the future.

## Compliance with this Policy
We consider the discovery and reporting of security vulnerabilities an important public service. We encourage responsible reporting of any vulnerabilities that may be found in our site or applications.

Furthermore, we will not take legal action against or suspend or terminate access to the site or services of those who discover and report security vulnerabilities in accordance with this policy because of the fact.

We ask that all users and contributors respect this policy and the security of our community's users by disclosing vulnerabilities to us in accordance with this policy.

## Changes to this Security Policy
This policy may be revised from time to time. Each version of the policy will be identified at the top of the page by its effective date.

If you have any questions about this Security Policy, please contact us at [security@wazuh.com](mailto:security@wazuh.com)