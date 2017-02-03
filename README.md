# OSSEC Wazuh fork

OSSEC is a full platform to monitor and control your systems. It mixes together all the aspects of HIDS (host-based intrusion detection), log monitoring and SIM/SIEM together in a simple, powerful and open source solution.

This fork provides compliance support, extended logging, and additional management features. These capabilities are required for the integration with ELK Stack and OSSEC Wazuh RESTful API (also included in this repository).

## Wazuh Open Source modules and contributions

Wazuh team is currently supporting OSSEC enterprise users, and decided to develop and publish additional modules as a way to contribute back to the Open Source community. Find below a list and description of these modules:

* [OSSEC Wazuh Ruleset](http://documentation.wazuh.com/en/latest/ossec_ruleset.html): Includes compliance mapping with PCI DSS v3.1, CIS and additional decoders and rules. Users can contribute to this rule set by submitting pull requests to our [Github repository](https://github.com/wazuh/wazuh-ruleset). Our team will continue to maintain and update it periodically.

* [OSSEC Wazuh fork](http://documentation.wazuh.com/en/latest/ossec_wazuh.html) with extended JSON logging capabilities, for easy [integration with ELK Stack](http://documentation.wazuh.com/en/latest/ossec_elk.html) and third party log management tools. The manager also include modifications in OSSEC binaries needed by the [OSSEC Wazuh RESTful API](http://documentation.wazuh.com/en/latest/ossec_api.html).

* [OSSEC Wazuh RESTful API](http://documentation.wazuh.com/en/latest/ossec_api.html): Used to monitor and control your OSSEC installation, providing an interface to interact with the manager from anything that can send an HTTP request.

* [Pre-compiled installation packages](http://documentation.wazuh.com/en/latest/ossec_installation.html), both for OSSEC agent and manager: Include repositories for RedHat, CentOS, Fedora, Debian, Ubuntu and Windows.

* [Puppet scripts](http://documentation.wazuh.com/en/latest/ossec_puppet.html) for automatic OSSEC deployment and configuration.

* [Docker containers](http://documentation.wazuh.com/en/latest/ossec_docker.html) to virtualize and run your OSSEC manager and an all-in-one integration with ELK Stack.

## Documentation

* [Full documentation](http://documentation.wazuh.com)
* [OSSEC Wazuh fork installation guide](http://documentation.wazuh.com/en/latest/wazuh_installation.html)

## Branches

* `stable` branch on correspond to the last OSSEC Wazuh stable version.
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

OSSEC Copyright (C) 2015 Trend Micro Inc. (License GPLv2)

## References

* [Wazuh website](http://wazuh.com)
* [OSSEC project website](http://ossec.github.io)
