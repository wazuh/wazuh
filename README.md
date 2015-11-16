OSSEC v2.8 Copyright (C) 2014 Trend Micro Inc.

OSSEC Wazuh v1.0

# Information about OSSEC 

OSSEC is a full platform to monitor and control your systems. It mixes together 
all the aspects of HIDS (host-based intrusion detection), log monitoring and 
SIM/SIEM together in a simple, powerful and open source solution.

Visit our website for the latest information. [www.ossec.net](http://www.ossec.net)

# Information about OSSEC forked by Wazuh


Wazuh team is currently supporting OSSEC enterprise users, and decided to develop and publish additional modules as a way to contribute back to the Open Source community. Find below a list and description of these modules, that have been released under the terms of GPLv2 license.

* OSSEC HIDS [Rule set](http://documentation.wazuh.com/en/latest/ossec_rule_set.html#ossec-rule-set): Includes compliance mapping with **PCI DSS v3.1**, CIS and additional decoders and rules. Users can contribute to this rule set by submitting pull requests to our [Github repository](https://github.com/wazuh/ossec-rules). Our team will continue to maintain and update it periodically.
* OSSEC Manager with extended JSON logging capabilities, for easy integration with [ELK Stack](http://documentation.wazuh.com/en/latest/ossec_wazuh.html) and third party log management tools. This new format includes compliance support and modifications in OSSEC binaries needed by the [OSSEC RESTful API] (http://documentation.wazuh.com/en/latest/installing_ossec_api.html#ossec-api).
* [OSSEC RESTful API](http://documentation.wazuh.com/en/latest/installing_ossec_api.html#ossec-api): Used to monitor and control your OSSEC installation, providing an interface to interact with the manager from anything that can send an HTTP request.
* [Pre-compiled installation packages](http://documentation.wazuh.com/en/latest/ossec.html#ossec-installers), both for OSSEC agent and manager: Include repositories for RedHat, CentOS, Fedora, Debian, Ubuntu and Windows.
* [Puppet scripts](http://documentation.wazuh.com/en/latest/puppet.html#ossec-puppet) for automatic OSSEC deployment and configuration.
* [Docker containers](http://documentation.wazuh.com/en/latest/docker.html#ossec-docker) to virtualize and run your OSSEC manager and an all-in-one integration with ELK Stack.

## Documentation

* Full documentation at [documentation.wazuh.com](http://documentation.wazuh.com)

## Current Release

**Master** branch on this repository correspond to the last **OSSEC-Wazuh** stable version.

* Release version can be downloaded from: [Downloads](http://www.wazuh.com)
* Or can be cloned from the **master** branch

## Development ##

The development version is on *development* branch on this repository, be aware of posible bugs on this branch.


## Install

Please refer to [Installation guide](http://documentation.wazuh.com/en/latest/about.html)

## Contribute

If you want to contribute to this documentation or our projects please don't hesitate to send a pull request. You can also join our users [mailing list](https://groups.google.com/d/forum/wazuh), by sending an email to [wazuh+subscribe@googlegroups.com](mailto:wazuh+subscribe@googlegroups.com), to ask questions and participate in discussions.


## Credits and Thanks ##

* OSSEC comes with a modified version of zlib and a small part 
  of openssl (sha1 and blowfish libraries)
* This product includes software developed by the OpenSSL Project
  for use in the OpenSSL Toolkit (http://www.openssl.org/).
* This product includes cryptographic software written by Eric 
  Young (eay@cryptsoft.com)
* This product include software developed by the zlib project 
  (Jean-loup Gailly and Mark Adler).
* This product include software developed by the cJSON project 
  (Dave Gamble)
* [OSSEC Project] (https://github.com/ossec/ossec-hids)
