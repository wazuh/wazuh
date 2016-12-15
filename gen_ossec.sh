#!/bin/sh

# Wazuh Configuration & Init Files Generator
# Copyright (C) 2016 Wazuh Inc.
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

# Read script values
if [ "$1" = "conf" ]; then

  if [ "$#" = "4" ]; then
    INSTYPE="$2"
    DIST_NAME=$(echo $3 | tr '[:upper:]' '[:lower:]')
    DIST_VER="$4"
  elif [ "$#" = "3" ]; then
    INSTYPE="$2"
    DIST_NAME=$(echo $3 | tr '[:upper:]' '[:lower:]')
    DIST_VER="0"
  else
    echo " USE: ./gen_ossec.sh conf install_type distribution [version]"
    echo "   - install_type: manager, agent"
    echo "   - distribution: redhat, debian, ..."
    exit 1
  fi

  # Default values definition
  SERVER_IP="MANAGER_IP"
  NEWCONFIG="./ossec.conf.temp"
  INSTALLDIR="/var/ossec"
  SYSCHECK="yes"
  ROOTCHECK="yes"
  OPENSCAP="yes"
  ACTIVERESPONSE="yes"
  RLOG="no" # syslog
  SLOG="yes" # remote

  . ./src/init/inst-functions.sh

  if [ -r "$NEWCONFIG" ]; then
      rm "$NEWCONFIG"
  fi

  if [ "$INSTYPE" = "manager" ]; then
    WriteManager "no_localfiles"
  elif [ "$INSTYPE" = "agent" ]; then
    WriteAgent "no_localfiles"
  else
    echo " USE: ./gen_ossec.sh conf install_type distribution [version]"
    echo "   - install_type: manager, agent"
    echo "   - distribution: redhat, debian, ..."
    exit 1
  fi

  cat "$NEWCONFIG"
  rm "$NEWCONFIG"

  exit 0

elif [ "$1" = "init" ]; then

  . ./src/init/inst-functions.sh
  . ./src/init/shared.sh

  # Read script values
  if [ "$#" = "2" ]; then
    INSTYPE=$(echo $2 | tr '[:upper:]' '[:lower:]')
    if [ "$INSTYPE" = "manager" ]; then
        INSTYPE="server"
    fi
  else
    echo " USE: ./gen_ossec.sh install_type"
    echo "   - install_type: manager, agent"
    exit 1
  fi

  GenerateInitConf

  exit 0

else
  echo ""
  echo "Wazuh Configuration & Init Files Generator"
  echo ""
  echo "  Generate a default ossec.conf file."
  echo "  USE: ./gen_ossec.sh conf install_type distribution [version]"
  echo "   - install_type: manager, agent"
  echo "   - distribution: redhat, debian, ..."
  echo ""
  echo "  Generate a default ossec-init.conf file."
  echo "  USE: ./gen_ossec.sh init install_type"
  echo "   - install_type: manager, agent"
  echo ""
  exit 1
fi
