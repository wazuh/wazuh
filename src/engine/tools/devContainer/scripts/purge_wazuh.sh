#!/bin/env bash
# Script to remove Wazuh manager and agent from the system 

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root or with sudo."
    exit 1
fi

# Check if apt-get is available
if command -v apt-get >/dev/null 2>&1; then
    apt-get remove --purge -y wazuh-manager wazuh-agent || true
else
    echo "Apt package manager not found. Skipping removal of Wazuh packages."
fi

# If using yum, remove Wazuh manager and agent
if command -v yum >/dev/null 2>&1; then
    yum remove -y wazuh-manager wazuh-agent || true
else
    echo "Yum package manager not found. Skipping removal of Wazuh packages."
fi

# Check if WAZUH_HOME is set
if [ -z "$WAZUH_HOME" ]; then
    WAZUH_HOME="/var/wazuh-manager"
fi

if [ ! -d "$WAZUH_HOME" ]; then
    echo "Wazuh home directory $WAZUH_HOME does not exist."
    exit 1
fi

# Umount proc filesystem if it exists (Mounted for development purposes)
if mountpoint -q ${WAZUH_HOME/proc}; then
    umount /var/wazuh-manager/proc
fi


# Stop and remove Wazuh services
if [ -f /etc/init.d/wazuh-manager ]; then
    service wazuh-manager stop
    update-rc.d -f wazuh-manager remove
    rm -f /etc/init.d/wazuh-manager
fi

if [ -f /etc/init.d/wazuh-agent ]; then
    service wazuh-agent stop
    update-rc.d -f wazuh-agent remove
    rm -f /etc/init.d/wazuh-agent
fi

# Stop and remove Wazuh systemd services
if [ -f /etc/systemd/system/wazuh-manager.service ]; then
    systemctl stop wazuh-manager
    systemctl disable wazuh-manager
    rm -f /etc/systemd/system/wazuh-manager.service
fi

if [ -f /etc/systemd/system/wazuh-agent.service ]; then
    systemctl stop wazuh-agent
    systemctl disable wazuh-agent
    rm -f /etc/systemd/system/wazuh-agent.service
fi

# Just in case, stop Wazuh control script
$WAZUH_HOME/bin/wazuh-control stop

# Remove Wazuh directories and files
rm -rf $WAZUH_HOME
find /etc/systemd/system -name "wazuh*" | xargs rm -f
systemctl daemon-reload

# Remove Wazuh user and group
if id -u wazuh >/dev/null 2>&1; then
    userdel -r wazuh
else
    echo "User 'wazuh' does not exist."
fi
if getent group wazuh >/dev/null 2>&1; then
    groupdel wazuh
else
    echo "Group 'wazuh' does not exist."
fi
