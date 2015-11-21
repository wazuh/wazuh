
OSSEC HIDS forked by Wazuh, Inc.

OSSEC Copyright (C) 2015 Trend Micro Inc.

OSSEC is a full platform to monitor and control your systems. It mixes together all the aspects of HIDS (host-based intrusion detection), log monitoring and SIM/SIEM together in a simple, powerful and open source solution. 

* OSSEC website is http://ossec.net
* OSSEC project documentation can be found at http://ossec.github.io/docs/
* Wazuh website is http://wazuh.com
* OSSEC Wazuh fork documentation can be found at http://documentation.wazuh.com

This fork provides compliance support, extended logging, and additional management features. These capabilities are required for the integration with ELK Stack and OSSEC Wazuh RESTful API (also included in this repository). 

## Wazuh Open Source modules and contributions

Wazuh team is currently supporting OSSEC enterprise users, and decided to develop and publish additional modules as a way to contribute back to the Open Source community. Find below a list and description of these modules, that have been released under the terms of GPLv2 license.

* [OSSEC Wazuh Ruleset](http://documentation.wazuh.com/en/latest/ossec_ruleset.html): Includes compliance mapping with PCI DSS v3.1, CIS and additional decoders and rules. Users can contribute to this rule set by submitting pull requests to our [Github repository](https://github.com/wazuh/ossec-rules). Our team will continue to maintain and update it periodically.

* [OSSEC Wazuh fork](http://documentation.wazuh.com/en/latest/ossec_wazuh.html) with extended JSON logging capabilities, for easy [integration with ELK Stack](http://documentation.wazuh.com/en/latest/ossec_elk.html) and third party log management tools. The manager also include modifications in OSSEC binaries needed by the [OSSEC Wazuh RESTful API](http://documentation.wazuh.com/en/latest/ossec_api.html).

* [OSSEC Wazuh RESTful API](http://documentation.wazuh.com/en/latest/ossec_api.html): Used to monitor and control your OSSEC installation, providing an interface to interact with the manager from anything that can send an HTTP request.

* [Pre-compiled installation packages](http://documentation.wazuh.com/en/latest/ossec_installation.html), both for OSSEC agent and manager: Include repositories for RedHat, CentOS, Fedora, Debian, Ubuntu and Windows.

* [Puppet scripts](http://documentation.wazuh.com/en/latest/ossec_puppet.html) for automatic OSSEC deployment and configuration.

* [Docker containers](http://documentation.wazuh.com/en/latest/ossec_docker.html) to virtualize and run your OSSEC manager and an all-in-one integration with ELK Stack.

## Documentation

* Full documentation at [documentation.wazuh.com](http://documentation.wazuh.com)

## Branches

* `master` branch on correspond to the last OSSEC Wazuh stable version.
* `development` branch contains the latest code, be aware of possible bugs on this branch.  

## Installation

Please refer to [Installation guide](http://documentation.wazuh.com/en/latest/ossec_wazuh.html)

## Contribute

If you want to contribute to our project please don't hesitate to send a pull request. 

You can also join our users [mailing list](https://groups.google.com/d/forum/wazuh), by sending an email to [wazuh+subscribe@googlegroups.com](mailto:wazuh+subscribe@googlegroups.com), to ask questions and participate in discussions.

## Credits and Thank you

Thank you Daniel Cid, who started the OSSEC project.

Thank you [OSSEC core team members](http://ossec.github.io/about.html#ossec-team).

Thank you [OSSEC developers and contributors](https://github.com/ossec/ossec-hids/blob/master/CONTRIBUTORS).

* [OSSEC Project] (https://github.com/ossec/ossec-hids)
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
