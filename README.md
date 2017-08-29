# Wazuh

Wazuh helps you to gain deeper security visibility into your infrastructure by monitoring hosts at an operating system and application level. This solution, based on lightweight multi-platform agents, provides the following capabilities:

- **Log management and analysis:** Wazuh agents read operating system and application logs, and securely forward them to a central manager for rule-based analysis and storage.
- **File integrity monitoring:** Wazuh monitors the file system, identifying changes in content, permissions, ownership, and attributes of files that you need to keep an eye on.
- **Intrusion and anomaly detection:** Agents scan the system looking for malware, rootkits or suspicious anomalies. They can detect hidden files, cloaked processes or unregistered network listeners, as well as inconsistencies in system call responses.
- **Policy and compliance monitoring:** Wazuh monitors configuration files to ensure they are compliant with your security policies, standards or hardening guides. Agents perform periodic scans to detect applications that are known to be vulnerable, unpatched, or insecurely configured.

This diverse set of capabilities is provided by integrating OSSEC, OpenSCAP and Elastic Stack, making them work together as a unified solution, and simplifying their configuration and management.

Wazuh provides an updated log analysis ruleset, and a RESTful API that allows you to monitor the status and configuration of all Wazuh agents.

Wazuh also includes a rich web application (fully integrated as a Kibana app), for mining log analysis alerts and for monitoring and managing your Wazuh infrastructure.

## Wazuh Open Source components and contributions

* [Wazuh](https://documentation.wazuh.com/current/index.html) was born as a fork of [OSSEC HIDS](https://github.com/ossec/ossec-hids). It contains many new features, improvements and bug fixes.

* [Wazuh App](https://documentation.wazuh.com/current/index.html#example-screenshots) is a rich web application (fully integrated as a Kibana app), for mining log analysis alerts and for monitoring and managing your Wazuh infrastructure.

* [Wazuh Ruleset](https://documentation.wazuh.com/current/user-manual/ruleset/index.html) is our repository to centralize decoders, rules, rootchecks and SCAP content. The ruleset is used by the manager to detect attacks, intrusions, software misuse, configuration problems, application errors, malware, rootkits, system anomalies or security policy violations. Also, it includes the compliance mapping with PCI DSS v3.1 and CIS. Users can contribute to this rule set by submitting pull requests to our [Github repository](https://github.com/wazuh/wazuh-ruleset).

* [Wazuh RESTful API](https://documentation.wazuh.com/current/user-manual/api/index.html) is used to monitor and control your Wazuh installation, providing an interface to interact with the manager from anything that can send an HTTP request.

* [Pre-compiled installation packages](https://documentation.wazuh.com/current/installation-guide/packages-list/index.html) include repositories for RedHat, CentOS, Fedora, Debian, Ubuntu and Windows.

* [Puppet scripts](https://documentation.wazuh.com/current/deploying-with-puppet/index.html) for automatic Wazuh deployment and configuration.

* [Docker containers](https://documentation.wazuh.com/current/docker/index.html) to virtualize and run your Wazuh manager and an all-in-one integration with ELK Stack.

## Documentation

* [Full documentation](http://documentation.wazuh.com)
* [Wazuh installation guide](https://documentation.wazuh.com/current/installation-guide/index.html)

## Branches

* `stable` branch on correspond to the last Wazuh stable version.
* `master` branch contains the latest code, be aware of possible bugs on this branch.
* `development` branch includes all the new features we're adding and testing.

## Contribute

If you want to contribute to our project please don't hesitate to send a pull request. You can also join our users [mailing list](https://groups.google.com/d/forum/wazuh), by sending an email to [wazuh+subscribe@googlegroups.com](mailto:wazuh+subscribe@googlegroups.com), to ask questions and participate in discussions.

## Software and libraries used

* Modified version of Zlib and a small part of OpenSSL (SHA1 and Blowfish libraries).
* OpenSSL Project for use in the OpenSSL Toolkit (http://www.openssl.org/).
* Cryptographic software written by Eric Young (eay@cryptsoft.com).
* Software developed by the Zlib project (Jean-loup Gailly and Mark Adler).
* Software developed by the cJSON project (Dave Gamble).
* Node.js (Ryan Dahl).
* NPM packages Body Parser, Express, HTTP-Auth and Moment.

## Credits and Thank you

* Daniel Cid, who started the OSSEC project.
* [OSSEC core team members](http://ossec.github.io/about.html#ossec-team).
* [OSSEC developers and contributors](https://github.com/ossec/ossec-hids/blob/master/CONTRIBUTORS).

## License and copyright

WAZUH
Copyright (C) 2017 Wazuh Inc.  (License GPLv2)

Based on OSSEC
Copyright (C) 2015 Trend Micro Inc.

## References

* [Wazuh website](http://wazuh.com)
* [OSSEC project website](http://ossec.github.io)
