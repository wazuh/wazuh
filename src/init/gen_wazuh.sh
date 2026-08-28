#!/bin/sh

# Wazuh Configuration & Init Files Generator
# Copyright (C) 2015, Wazuh Inc.
# November 24, 2016.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Looking up for the execution directory
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# Change to the parent directory of src/init so relative paths work
cd "${SCRIPT_DIR}/../.."

Use()
{
  echo " USE: ./gen_wazuh.sh conf install_type distribution version [installation_path]"
  echo "   - install_type: manager, agent"
  echo "   - distribution: rhel, debian, ubuntu, ..."
  echo "   - version: 6, 7, 16.04, ..."
  echo "   - installation_path (optional): changes the default path '/var/wazuh-manager' for server and '/var/ossec' for agent"
  echo "   - yaml_output (optional, manager only): also write the YAML configuration (etc/wazuh-manager.yml) to this file"
}

# Read script values
if [ "$1" = "conf" ] && [ "$#" -ge "4" ]; then

  . ${SCRIPT_DIR}/shared.sh
  . ${SCRIPT_DIR}/inst-functions.sh

  INSTYPE=$(echo $2 | tr '[:upper:]' '[:lower:]')
  if [ "$INSTYPE" = "manager" ]; then
      INSTYPE="server"
  fi
  DIST_NAME=$(echo $3 | tr '[:upper:]' '[:lower:]')
  if [ $(echo $4 | grep "\.") ]; then
    DIST_VER=$(echo $4 | cut -d\. -f1)
    DIST_SUBVER=$(echo $4 | cut -d\. -f2)
  else
    DIST_VER="$4"
    DIST_SUBVER="0"
  fi
  if [ "$#" -ge "5" ]; then
    INSTALLDIR="$5"
  fi
  YAML_OUT=""
  if [ "$#" -ge "6" ]; then
    YAML_OUT="$6"
  fi

  # Default values definition
  SERVER_IP="MANAGER_IP"
  NEWCONFIG="./wazuh.conf.temp"
  NEWCONFIG_YML="./wazuh.yml.temp"
  SYSCHECK="yes"
  ROOTCHECK="yes"
  SYSCOLLECTOR="yes"
  SECURITY_CONFIGURATION_ASSESSMENT="yes"
  ACTIVERESPONSE="yes"
  AUTHD="yes"
  SSL_CERT="yes"

  if [ -r "$NEWCONFIG" ]; then
      rm "$NEWCONFIG"
  fi
  if [ -r "$NEWCONFIG_YML" ]; then
      rm "$NEWCONFIG_YML"
  fi

  if [ "$INSTYPE" = "server" ]; then
    WriteManager "no_localfiles"
  elif [ "$INSTYPE" = "agent" ]; then
    WriteAgent "no_localfiles"
  else
    Use
    exit 1
  fi

  cat "$NEWCONFIG"
  rm "$NEWCONFIG"

  # The manager also produces its YAML twin (same cluster key); copy it where the caller asked.
  if [ -n "$YAML_OUT" ] && [ -f "$NEWCONFIG_YML" ]; then
    cp "$NEWCONFIG_YML" "$YAML_OUT"
  fi
  rm -f "$NEWCONFIG_YML"

  exit 0
else
  echo ""
  echo "Wazuh Configuration Generator"
  echo ""
  Use
  echo ""
  exit 1
fi
