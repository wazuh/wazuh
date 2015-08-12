ossec-debian
============

OSSEC is an Open Source Host-based Intrusion Detection System that performs log analysis, file integrity checking, policy monitoring, rootkit detection, real-time alerting and active response.

These are the files used to create OSSEC-HIDS version 2.8 debian packages, the ones included both in ossec.net website and in WAZUH repository. You can find these packages at:

http://www.ossec.net/?page_id=19

or directly at: http://ossec.wazuh.com/repos/apt/

There are two different packages that can be built with these files:

* ossec-hids: Package that includes both the server and the agent.
* ossec-hids-agent: Package that includes just the agent.

Each one of the subdirectories includes:

* Patches
* Debian control files: changelog, compat, control, copyright, lintian-overrides, postinst, postrm, preinst, rules

Additionally a script, ```generate_ossec.sh```, is included to generate the Debian packages for Jessie, Sid and Wheezy Debian distributions, both for i386 and amd64 architectures. This script uses Pbuilder to build the packages, and uploads those to an APT repository, setup with Reprepro.

For more details on how to create Debian Packages and an APT repository you can check my post at:

http://santi-bassett.blogspot.com/2014/07/setting-up-apt-repository-with-reprepro.html

Please don't hesitate to contribute (preferably via pull requests) to improve these packages.
