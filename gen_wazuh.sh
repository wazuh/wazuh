#!/bin/sh

# Wazuh Configuration & Init Files Generator
# Copyright (C) 2015-2021, Wazuh Inc.
# November 24, 2016.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Looking up for the execution directory
cd `dirname $0`

Use()
{
  echo " USE: ./gen_wazuh.sh conf install_type distribution version [installation_path]"
  echo "   - install_type: manager, agent, local, agent-server"
  echo "   - distribution: rhel, debian, ubuntu, ..."
  echo "   - version: 6, 7, 16.04, ..."
  echo "   - installation_path (optional): changes the default path '/var/ossec' "
}

# Read script values
if [ "$1" = "conf" ] && [ "$#" -ge "4" ]; then

  . ./src/init/shared.sh
  . ./src/init/inst-functions.sh

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
  if [ "$#" = "5" ]; then
    INSTALLDIR="$5"
  fi

  # Default values definition
  SERVER_IP="MANAGER_IP"
  NEWCONFIG_AGENT="./agent.conf.temp"
  NEWCONFIG_MANAGER="./manager.conf.temp"
  SYSCHECK="yes"
  ROOTCHECK="yes"
  SYSCOLLECTOR="yes"
  SECURITY_CONFIGURATION_ASSESSMENT="yes"
  ACTIVERESPONSE="yes"
  AUTHD="yes"
  SSL_CERT="yes"
  RLOG="no" # syslog
  SLOG="yes" # remote

  if [ -r "$NEWCONFIG_AGENT" ]; then
      rm "$NEWCONFIG_AGENT"
  fi

  if [ -r "$NEWCONFIG_MANAGER" ]; then
    rm "$NEWCONFIG_MANAGER"
  fi

  if [ "$INSTYPE" = "server" ]; then
    WriteManager "no_localfiles"
    cat "$NEWCONFIG_MANAGER"
  elif [ "$INSTYPE" = "agent" ]; then
    WriteAgent "no_localfiles"
    cat "$NEWCONFIG_AGENT"
  elif [ "$INSTYPE" = "local" ]; then
    WriteLocal "no_localfiles"
    cat "$NEWCONFIG_MANAGER"
  elif [ "$INSTYPE" = "agent-server" ]; then
    WriteAgentConfServer "no_localfiles"
    cat "$NEWCONFIG_AGENT"
  else
    Use
    exit 1
  fi

  if [ -r "$NEWCONFIG_AGENT" ]; then
      rm "$NEWCONFIG_AGENT"
  fi

  if [ -r "$NEWCONFIG_MANAGER" ]; then
      rm "$NEWCONFIG_MANAGER"
  fi

  exit 0
else
  echo ""
  echo "Wazuh Configuration Generator"
  echo ""
  Use
  echo ""
  exit 1
fi
