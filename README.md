# [Wazuh](http://wazuh.com)

Wazuh is a free and open-source platform used for threat prevention, detection, and response. It is capable of protecting workloads across on-premises, virtualized, containerized, and cloud-based environments.

Wazuh solution consists of an endpoint security agent deployed to the monitored system and a management server, which collects and analyzes data gathered by the agents. Besides, Wazuh has been fully integrated with the Elastic Stack, providing a search engine and data visualization tool that allows users to navigate through their security alerts.

Join our community!

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://wazuh.com/community/join-us-on-slack/)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)
[![Twitter](https://img.shields.io/twitter/follow/wazuh?style=social)](https://twitter.com/wazuh)
[![YouTube](https://img.shields.io/youtube/views/peTSzcAueEc?style=social)](https://www.youtube.com/watch?v=peTSzcAueEc)


## Capabilities

<table>
<tr>
<td><a href="https://documentation.wazuh.com/current/index.html">Security Analytics</a></td> 
<td><a href="https://documentation.wazuh.com/current/index.html">Intrusion Detection</a></td>
<td><a href="https://documentation.wazuh.com/current/index.html">Log Data Analysis</a></td>
<td><a href="https://documentation.wazuh.com/current/index.html">File Integrity Monitoring</a></td>
</tr>
<tr>
<td><a href="https://documentation.wazuh.com/current/index.html">Vulnerability Detection</a></td>
<td><a href="https://documentation.wazuh.com/current/index.html">Configuration Assessment</a></td>
<td><a href="https://documentation.wazuh.com/current/index.html">Incident Response</a></td>
</tr>
<tr>
<td><a href="https://documentation.wazuh.com/current/index.html">Regulatory Compliance</a></td>
<td><a href="https://documentation.wazuh.com/current/index.html">Cloud Security Monitoring</a></td>
<td><a href="https://documentation.wazuh.com/current/index.html">Containers Security</a></td>
</tr>
</table>

## User interface

The WUI provides a powerful user interface for data visualization and analysis. You can also manage the configuration and monitor the status using the WUI.

**Security events** | **Integrity monitoring** |  **Vulnerability detection**
|---|---|---|
|![Overview](https://github.com/wazuh/wazuh-kibana-app/blob/master/public/assets/app2.png) | ![Overview](https://github.com/wazuh/wazuh-kibana-app/blob/master/public/assets/app3.png) | ![Overview](https://github.com/wazuh/wazuh-kibana-app/blob/master/public/assets/app4.png)%7C

|**Regulatory compliance** | **Agents overview**| **Agent summary**|
|---|---|---|
|![Overview](https://github.com/wazuh/wazuh-kibana-app/blob/master/public/assets/app5.png) |![Overview](https://github.com/wazuh/wazuh-kibana-app/blob/master/public/assets/app6.png) | ![Overview](https://github.com/wazuh/wazuh-kibana-app/blob/master/public/assets/app7.png)%7C

## Installation

Our extensive [documentation](https://documentation.wazuh.com/current/installation-guide/index.html) can guide you through multiple deployment scenarios. Take a look at the automation tools configurations maintained by the Wazuh team.

<table>
<tr>
<td><a href="https://github.com/wazuh/wazuh-cloudformation">Wazuh AWS CloudFormation</a></td>
<td><a href="https://github.com/wazuh/wazuh-docker">Docker containers</a></td>
<td><a href="https://github.com/wazuh/wazuh-ansible">Wazuh Ansible</a></td>
<td><a href="https://github.com/wazuh/wazuh-chef">Wazuh Chef</a></td>
</tr>
<tr>
<td><a href="https://github.com/wazuh/wazuh-puppet">Wazuh Puppet</a></td>
<td><a href="https://github.com/wazuh/wazuh-kubernetes">Wazuh Kubernetes</a></td>
<td><a href="https://github.com/wazuh/wazuh-bosh">Wazuh Bosh</a></td>
<td><a href="https://github.com/wazuh/wazuh-salt">Wazuh Salt</a></td>
</tr>
</table>

## Get involved

Become part of the [Wazuh's community](https://wazuh.com/community/) to learn from other users, participate in discussions, talk to Wazuh developers and contribute to the project.

If you want to contribute to our project, please check out our [contributing guide](CONTRIBUTING.md) and help us improve Wazuh. We will review all your questions and proposals. We're open-source enthusiasts.

You can also join our [Slack community channel](https://wazuh.com/community/join-us-on-slack/) and [mailing list](https://groups.google.com/d/forum/wazuh) by sending an email to [wazuh+subscribe@googlegroups.com](mailto:wazuh+subscribe@googlegroups.com), to ask questions and participate in discussions.


And take a look at our [wiki](wiki) for the latest development guides.

## Security

Wazuh has thousands of users around the world. Help us protect our community by reporting any security issue to **[security@wazuh.com](mailto:security@wazuh.com)**.

After the [report](CONTRIBUTING.md), we will analyze the possible vulnerability, and if we verify there is a vulnerability in Wazuh, we will work on a fix. When the fix is available, we will publish the vulnerability details, and we will register a CVE, so our community can check if their Wazuh version is affected.

All vulnerabilities will be credited to their authors appropriately.

As a user, you can subscribe to our **[security anouncement](mailto:wazuh-security-anouncement+subscribe@googlegroups.com)** mail list to receive information about published vulnerabilities.

## We love open source

Here we have some of the open-source projects we rely on:

* Modified version of Zlib and an embedded part of OpenSSL (SHA1, SHA256, SHA512, AES and Blowfish libraries).
* OpenSSL Project for use in the OpenSSL Toolkit (http://www.openssl.org/).
* Cryptographic software by Eric Young (eay@cryptsoft.com).
* Software developed by the Zlib project (Jean-loup Gailly and Mark Adler).
* Software developed by the cJSON project (Dave Gamble).
* Software developed by the MessagePack project (https://msgpack.org/).
* Software developed by the CURL project (https://curl.haxx.se/).
* Software developed by the bzip2 project (Julian Seward).
* Software developed by the libYAML project (Kirill Simonov).
* The Linux audit userspace project (https://github.com/linux-audit/audit-userspace).
* A embedded part of the Berkeley DB library (https://github.com/berkeleydb/libdb).
* CPython interpreter by Guido van Rossum and the Python Software Foundation (https://www.python.org).
* PyPi packages: [azure-storage-blob](https://github.com/Azure/azure-storage-python), [boto3](https://github.com/boto/boto3), [cryptography](https://github.com/pyca/cryptography), [docker](https://github.com/docker/docker-py), [pytz](https://pythonhosted.org/pytz/), [requests](http://python-requests.org/) and [uvloop](http://github.com/MagicStack/uvloop).
* PCRE2 library by Philip Hazel (https://www.pcre.org/).

## Authors

Wazuh Copyright (C) 2015-2021 Wazuh Inc. (License GPLv2)

Based on the OSSEC project started by Daniel Cid.
