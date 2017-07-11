## Ossec-agent SELinux module
SELinux module provides additional security protection for ossec application

## Installation
1. Run semodule -i ossec\_agent.pp.bz2 on a running SELinux installation
2. Run restorecon -R /var/ossec
3. Restart ossec agent via systemd/init/etc
4. Check if it get right context ( ps -AZ )

You should do chcon manually if your put ossec installation in different place, see .fc file for details

## Configuration
Nothing to configure :)

## Bug reports & contribution
Contact: ivan.agarkov@gmail.com

