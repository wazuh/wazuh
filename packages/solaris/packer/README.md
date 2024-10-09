Vagrant Box
===========

In this repository, you can find the necessary tools to build a Vagrant box for solaris 10 or 11 using packer.

## Tools needed to build the package

To build a Wazuh package you need to install the following tools:
- `Virtual Box`: [installation guide](https://www.virtualbox.org/manual/UserManual.html#installation)
- `Vagrant`: [installation guide](https://www.vagrantup.com/docs/installation/)
- `Git`:  [installation guide](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git).
- `Packer`: [installation guide](https://www.packer.io/intro/getting-started/install.html)

1. Download the official Solaris10 ISO, to do this you, must first accept the [Oracle license agreement](https://www.oracle.com/technetwork/server-storage/solaris10/downloads/index.html) and then download the ISO:
- [Solaris 10](http://download.oracle.com/otn/solaris/10/sol-10-u11-ga-x86-dvd.iso)

2. Store the iso in packer/packer and use `packer build -only=virtualbox-iso -on-error=ask solaris10.json`, this will generate the Vagrant box.

3. Add the Vagrant box so you can use it locally, `vagrant add <box_name>.box`

## More Packages

- [AIX](/aix/README.md)
- [HP-UX](/hp-ux/README.md)
- [RPM](/rpms/README.md)

## References

https://github.com/BigAl/solaris-packer

## Contribute

If you want to contribute to our project please don't hesitate to send a pull request. You can also join our users [mailing list](https://groups.google.com/d/forum/wazuh) by sending an email to [wazuh+subscribe@googlegroups.com](mailto:wazuh+subscribe@googlegroups.com)or join our Slack channel by filling this [form](https://wazuh.com/community/join-us-on-slack/) to ask questions and participate in discussions.

## License and copyright

WAZUH
Copyright (C) 2015 Wazuh Inc.  (License GPLv2)
