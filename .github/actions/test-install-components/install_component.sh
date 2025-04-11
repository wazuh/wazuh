#!/bin/bash
package_name=$1
target=$2

echo "Installing Wazuh $target."

if [ -n "$(command -v yum)" ]; then
    install="yum install -y --nogpgcheck"
    installed_log="/var/log/yum.log"

    if [ ! -f "$installed_log" ]; then
        installed_log="/var/log/dnf.log"
    fi

elif [ -n "$(command -v dpkg)" ]; then
    install="dpkg --install"
    installed_log="/var/log/dpkg.log"
else
    common_logger -e "Couldn't find type of system"
    exit 1
fi

if [ "${ARCH}" = "i386" ] || [ "${ARCH}" = "armv7hl" ]; then
    linux="linux32"
fi


WAZUH_MANAGER="10.0.0.2" $linux $install "/packages/$package_name"| tee /packages/status.log
grep -i " installed.*wazuh-$target" $installed_log| tee -a /packages/status.log
