# Wazuh Open Source Project Security Policy

Version: 2023-06-12

## Introduction
This document outlines the Security Policy for Wazuh's open source projects. It emphasizes our commitment to maintain a secure environment for our users and contributors, and reflects our belief in the power of collaboration to identify and resolve security vulnerabilities.

## Scope
This policy applies to all open source projects developed, maintained, or hosted by Wazuh.

## Reporting Security Vulnerabilities
If you believe you've discovered a potential security vulnerability in one of our open source projects, we strongly encourage you to report it to us responsibly.

Please submit your findings as [security advisories](https://github.com/wazuh/wazuh/security/advisories) under the "Security" tab in the relevant GitHub repository. Alternatively, you may send the details of your findings to security@wazuh.com.

## Vulnerability Disclosure Policy
Upon receiving a report of a potential vulnerability, our team will initiate an investigation. If the reported issue is confirmed as a vulnerability, we will take the following steps:

1. Acknowledgment: We will acknowledge the receipt of your vulnerability report and begin our investigation.

2. Validation: We will validate the issue and work on reproducing it in our environment.

3. Remediation: We will work on a fix and thoroughly test it

4. Release & Disclosure: After 90 days from the discovery of the vulnerability, or as soon as a fix is ready and thoroughly tested (whichever comes first), we will release a security update for the affected project. We will also publicly disclose the vulnerability by publishing a CVE (Common Vulnerabilities and Exposures) and acknowledging the discovering party.

5. Exceptions: In order to preserve the security of the Wazuh community at large, we might extend the disclosure period to allow users to patch their deployments.

This 90-day period allows for end-users to update their systems and minimizes the risk of widespread exploitation of the vulnerability.

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

If you have any questions about this Security Policy, please contact us at security@wazuh.com
