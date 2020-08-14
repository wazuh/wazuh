# Wazuh

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://wazuh.com/community/join-us-on-slack/)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)
[![Coverity](https://scan.coverity.com/projects/10992/badge.svg)](https://scan.coverity.com/projects/wazuh-wazuh)
[![Twitter](https://img.shields.io/twitter/follow/wazuh?style=social)](https://twitter.com/wazuh)
[![YouTube](https://img.shields.io/youtube/views/peTSzcAueEc?style=social)](https://www.youtube.com/watch?v=peTSzcAueEc)


Wazuh is a free and open source platform used for threat prevention, detection, and response. It is capable of protecting workloads across on-premises, virtualized, containerized, and cloud-based environments. Wazuh is widely used by thousands of organizations around the world, from small businesses to large enterprises.

Wazuh solution consists of an endpoint security agent, deployed to the monitored systems, and a management server, which collects and analyzes data gathered by the agents. Besides, Wazuh has been fully integrated with the Elastic Stack, providing a search engine and data visualization tool that allows users to navigate through their security alerts, the Wazuh WUI.

**Available modules**

![Overview](https://github.com/wazuh/wazuh-kibana-app/blob/master/public/img/app.png)

**Security events**

![Overview](https://github.com/wazuh/wazuh-kibana-app/blob/master/public/img/app2.png)

**Integrity monitoring**

![Overview](https://github.com/wazuh/wazuh-kibana-app/blob/master/public/img/app3.png)

**Agent overview**

![Overview](https://github.com/wazuh/wazuh-kibana-app/blob/master/public/img/app4.png)

## Orchestration

Here you can find all the automation tools manteined by the Wazuh team.

* [Wazuh AWS CloudFormation](https://github.com/wazuh/wazuh-cloudformation) to deploy both a Wazuh production-ready environment and a Wazuh demo environment in Amazon Web Services (AWS).

* [Docker containers](https://github.com/wazuh/wazuh-docker) to virtualize and run your Wazuh manager and an all-in-one integration with ELK stack.

* [Wazuh Ansible](https://github.com/wazuh/wazuh-ansible) playbooks to install the Wazuh instances and the Elastic stack.

* [Wazuh Chef](https://github.com/wazuh/wazuh-chef) to deploy the Wazuh platform using Check cookbocks.

* [Wazuh Puppet](https://github.com/wazuh/wazuh-puppet) for automatic Wazuh deployment and configuration.

* [Wazuh Kubernetes](https://github.com/wazuh/wazuh-kubernetes) to deploy a Wazuh cluster with a basic Elastic stack on Kubernetes.

* [Wazuh Bosh](https://github.com/wazuh/wazuh-bosh) to install Wazuh with Bosh.

* [Wazuh Salt](https://github.com/wazuh/wazuh-salt) to install Wazuh with SaltStack.

## Branches

* `master` branch on correspond to the last Wazuh stable version.
* `develop` branch contains the latest code, be aware of possible bugs on this branch.

## Software and libraries used

* Modified version of Zlib and a embedded part of OpenSSL (SHA1, SHA256, SHA512, AES and Blowfish libraries).
* OpenSSL Project for use in the OpenSSL Toolkit (http://www.openssl.org/).
* Cryptographic software written by Eric Young (eay@cryptsoft.com).
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

## Documentation

* [Full documentation](http://documentation.wazuh.com)
* [Wazuh installation guide](https://documentation.wazuh.com/current/installation-guide/index.html)

## Get involved

Become part of the [Wazuh's community](https://wazuh.com/community/) to learn from other users, participate in discussions, talk to our developers and contribute to the project.

If you want to contribute to our project please don’t hesitate to make pull-requests, submit issues or send commits, we will review all your questions.

You can also join our [Slack #community channel](https://wazuh.com/community/join-us-on-slack/) and [mailing list](https://groups.google.com/d/forum/wazuh) by sending an email to [wazuh+subscribe@googlegroups.com](mailto:wazuh+subscribe@googlegroups.com), to ask questions and participate in discussions.

## Online content and social networks

Stay up to date on news, releases, engineering articles and more.

* [Linkedin](https://www.linkedin.com/company/wazuh)
* [YouTube](https://www.youtube.com/c/wazuhsecurity)
* [Twitter](https://twitter.com/wazuh)
* [Wazuh blog](https://wazuh.com/blog/)
* [Slack announcements channel](https://wazuh.com/community/join-us-on-slack/)

## Authors

Wazuh Copyright (C) 2015-2020 Wazuh Inc. (License GPLv2)

Based on the OSSEC project started by Daniel Cid.

## References

* [Wazuh website](http://wazuh.com)
