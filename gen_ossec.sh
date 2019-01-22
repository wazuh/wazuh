#!/bin/sh

# Wazuh Configuration & Init Files Generator
# Copyright (C) 2015-2019, Wazuh Inc.
# November 24, 2016.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# File dependencies:
# ./src/init/shared.sh
# ./src/init/inst-functions.sh
# ./src/init/template-select.sh
# ./src/init/dist-detect.sh
# ./src/VERSION
# ./src/LOCATION
# ./etc/templates/config


# Looking up for the execution directory
cd `dirname $0`

Conf_Use()
{
  echo " USE: ./gen_ossec.sh conf install_type distribution version [installation_path]"
  echo "   - install_type: manager, agent, local"
  echo "   - distribution: rhel, debian, ubuntu, ..."
  echo "   - version: 6, 7, 16.04, ..."
  echo "   - installation_path (optional): changes the default path '/var/ossec' "
}

Init_Use()
{
  echo " USE: ./gen_ossec.sh init install_type [installation_path]"
  echo "   - install_type: manager, agent, local"
  echo "   - installation_path (optional): changes the default path '/var/ossec' "
}

# Read script values
if [ "$1" = "conf" ]; then

  . ./src/init/shared.sh
  . ./src/init/inst-functions.sh

  if [ "$#" -ge "4" ]; then
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
  else
    Conf_Use
    exit 1
  fi

  # Default values definition
  SERVER_IP="MANAGER_IP"
  NEWCONFIG="./ossec.conf.temp"
  SYSCHECK="yes"
  ROOTCHECK="yes"
  OPENSCAP="yes"
  SYSCOLLECTOR="yes"
  ACTIVERESPONSE="yes"
  AUTHD="yes"
  SSL_CERT="yes"
  RLOG="no" # syslog
  SLOG="yes" # remote

  if [ -r "$NEWCONFIG" ]; then
      rm "$NEWCONFIG"
  fi

  if [ "$INSTYPE" = "server" ]; then
    WriteManager "no_localfiles"
  elif [ "$INSTYPE" = "agent" ]; then
    WriteAgent "no_localfiles"
elif [ "$INSTYPE" = "local" ]; then
    WriteLocal "no_localfiles"
  else
    Conf_Use
    exit 1
  fi

  cat "$NEWCONFIG"
  rm "$NEWCONFIG"

  exit 0

elif [ "$1" = "init" ]; then

  . ./src/init/inst-functions.sh
  . ./src/init/shared.sh

  # Read script values
  if [ "$#" -ge "2" ]; then
    INSTYPE=$(echo $2 | tr '[:upper:]' '[:lower:]')
    if [ "$INSTYPE" = "manager" ]; then
        INSTYPE="server"
    fi
    if [ "$#" = "3" ]; then
      INSTALLDIR="$3"
    fi
  else
    Init_Use
    exit 1
  fi

  GenerateInitConf

  exit 0

else
  echo ""
  echo "Wazuh Configuration & Init Files Generator"
  echo ""
  echo " Generate a default ossec.conf file."
  Conf_Use
  echo ""
  echo " Generate a default ossec-init.conf file."
  Init_Use
  echo ""
  exit 1
fi
