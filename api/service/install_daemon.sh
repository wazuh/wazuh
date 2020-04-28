#!/bin/bash

# Copyright (C) 2015-2020 Wazuh, Inc. All rights reserved.
# Wazuh.com
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Installer for Wazuh API daemon
# Wazuh Inc.


I_OWNER="root"
I_GROUP="root"
I_XMODE="755"
I_FMODE="644"
I_SYSTEMD="/etc/systemd/system"
I_SYSVINIT="/etc/init.d"

OSSEC_CONF="/etc/ossec-init.conf"
DEF_WAZUH_PATH="/var/ossec"

# Test root permissions

if [ "$EUID" -ne 0 ]; then
    echo "Warning: Please run this script with root permissions."
fi

if [ "X${WAZUH_PATH}" = "X" ]; then
        WAZUH_PATH=${DEF_WAZUH_PATH}
    fi

APP_PATH="${WAZUH_PATH}/bin/wazuh-apid"
SERVICE_PATH="${WAZUH_PATH}/api/service"

if ! [ -f $APP_PATH ]; then
    echo "Can't find $APP_PATH. Is Wazuh API installed?"
    exit 1
fi

# Install for systemd

if command -v systemctl > /dev/null 2>&1 && systemctl > /dev/null 2>&1; then
    echo "Installing for systemd"

    sed "s:^Environment=.*:Environment=\"APP_PATH=$APP_PATH\":g" $SERVICE_PATH/wazuh-api.service > $SERVICE_PATH/wazuh-api.service.tmp
    install -m $I_FMODE -o $I_OWNER -g $I_GROUP $SERVICE_PATH/wazuh-api.service.tmp $I_SYSTEMD/wazuh-api.service
    rm $SERVICE_PATH/wazuh-api.service.tmp
    systemctl daemon-reload
    systemctl enable wazuh-api
#    systemctl restart wazuh-api


# Install for SysVinit / Upstart

elif command -v service > /dev/null 2>&1; then
    echo "Installing for SysVinit"
    cat $SERVICE_PATH/wazuh-api > $SERVICE_PATH/wazuh-api.tmp
    sed -i "s:^APP_PATH=.*:APP_PATH=\"$APP_PATH\":g" $SERVICE_PATH/wazuh-api.tmp
    sed -i "s:^OSSEC_PATH=.*:OSSEC_PATH=\"${WAZUH_PATH}\":g" $SERVICE_PATH/wazuh-api.tmp
    install -m $I_XMODE -o $I_OWNER -g $I_GROUP $SERVICE_PATH/wazuh-api.tmp $I_SYSVINIT/wazuh-api
    rm $SERVICE_PATH/wazuh-api.tmp

    enabled=true
    if command -v chkconfig > /dev/null 2>&1; then
        /sbin/chkconfig --add wazuh-api > /dev/null 2>&1
    elif [ -f "/usr/sbin/update-rc.d" ] || [ -n "$(ps -e | egrep upstart)" ]; then
        update-rc.d wazuh-api defaults
    elif [ -r "/etc/gentoo-release" ]; then
        rc-update add wazuh-api default
    else
        echo "init script installed in $I_SYSVINIT/wazuh-api"
        echo "We could not enable it. Please enable the service manually."
        enabled=false
    fi

#    if [ "$enabled" = true ]; then
#        service wazuh-api restart
#    fi
else
    echo "Warning: Unknown init system. Please run the API with:"
    echo "$APP_PATH"
fi
