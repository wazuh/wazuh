#!/bin/sh

## Stop and remove application
sudo /bin/rm -r /Library/Ossec*

# remove launchdaemons
/bin/rm -f /Library/LaunchDaemons/com.wazuh.agent.plist

## remove StartupItems
/bin/rm -rf /Library/StartupItems/WAZUH

## Remove User and Groups
/usr/bin/dscl . -delete "/Users/wazuh"
/usr/bin/dscl . -delete "/Groups/wazuh"

/usr/sbin/pkgutil --forget com.wazuh.pkg.wazuh-agent
/usr/sbin/pkgutil --forget com.wazuh.pkg.wazuh-agent-etc

# In case it was installed via Puppet pkgdmg provider

if [ -e /var/db/.puppet_pkgdmg_installed_wazuh-agent ]; then
    rm -f /var/db/.puppet_pkgdmg_installed_wazuh-agent
fi

echo
echo "Wazuh agent correctly removed from the system."
echo

exit 0
