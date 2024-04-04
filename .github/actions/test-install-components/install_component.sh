#!/bin/bash
package_name=$1
target=$2

echo "Installing Wazuh $target."

if [ -n "$(command -v yum)" ]; then
    install="yum install -y --nogpgcheck"
elif [ -n "$(command -v apt-get)" ]; then
    install="dpkg --install"
else
    common_logger -e "Couldn't find type of system"
    exit 1
fi

if [ "${ARCH}" = "i386" ] || [ "${ARCH}" = "armv7hl" ]; then
    linux="linux32"
fi

WAZUH_MANAGER="10.0.0.2" $linux $install "/packages/$package_name"
/var/ossec/bin/wazuh-control start
/var/ossec/bin/wazuh-control status | tee /packages/status.log