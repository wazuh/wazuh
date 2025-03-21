#!/bin/bash
package_name=$1
target=$2

if [ -z "$package_name" ] || [ -z "$target" ]; then
    echo "Error: Both package_name and target must be provided."
    echo "Usage: $0 <package_name> <target>"
    exit 1
fi

echo "Upgrading Wazuh $target."

if [ -n "$(command -v yum)" ]; then
    upgrade="yum upgrade -y $package_name"
    upgrade_log="/var/log/yum.log"
elif [ -n "$(command -v apt-get)" ]; then
    upgrade="apt-get install -y $package_name"
    upgrade_log="/var/log/dpkg.log"
else
    echo "Couldn't determine package manager."
    exit 1
fi

$upgrade | tee /packages/status.log

if grep -i " upgraded.*wazuh-$target" $upgrade_log | tee -a /packages/status.log; then
    echo "Wazuh $target was upgraded successfully."
    exit 0
else
    echo "Failed to upgrade Wazuh $target."
    exit 1
fi
