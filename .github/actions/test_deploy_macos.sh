#!/bin/bash

# Copyright (C) 2015, Wazuh Inc.
# March 6, 2019.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Global variables
VERSION="$(cat src/VERSION | sed 's/v//')"
MAJOR=$(echo ${VERSION} | cut -dv -f2 | cut -d. -f1)
MINOR=$(echo ${VERSION} | cut -d. -f2)
SHA="$(git rev-parse --short HEAD)"


WAZUH_MANAGER="1.1.1.1"
WAZUH_MANAGER_PORT="7777"
WAZUH_PROTOCOL="udp"
WAZUH_REGISTRATION_SERVER="2.2.2.2"
WAZUH_REGISTRATION_PORT="8888"
WAZUH_REGISTRATION_PASSWORD="password"
WAZUH_KEEP_ALIVE_INTERVAL="10"
WAZUH_TIME_RECONNECT="10"
WAZUH_REGISTRATION_CA="/var/ossec/etc/testsslmanager.cert"
WAZUH_REGISTRATION_CERTIFICATE="/var/ossec/etc/testsslmanager.cert"
WAZUH_REGISTRATION_KEY="/var/ossec/etc/testsslmanager.key"
WAZUH_AGENT_NAME="test-agent"
WAZUH_AGENT_GROUP="test-group"
ENROLLMENT_DELAY="10"

WAZUH_REGISTRATION_PASSWORD_PATH="etc/authd.pass"
    
function install_wazuh(){
  echo "Testing the following variables $@"
  eval "launchctl setenv ${@} && installer -pkg wazuh-agent-4.3.8-1.pkg -target / > /dev/null 2>&1"
}

function remove_wazuh () {
  /bin/rm -r /Library/Ossec
  /bin/launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist
  /bin/rm -f /Library/LaunchDaemons/com.wazuh.agent.plist
  /bin/rm -rf /Library/StartupItems/WAZUH
  /usr/bin/dscl . -delete "/Users/wazuh"
  /usr/bin/dscl . -delete "/Groups/wazuh"
  /usr/sbin/pkgutil --forget com.wazuh.pkg.wazuh-agent
}

function test() {

  if [ -n "$(echo "${@}"| grep -w "WAZUH_MANAGER" )" ]; then
    ADDRESSES=( $(echo ${WAZUH_MANAGER} | sed "s#,# #g") )
    for i in ${!ADDRESSES[@]}; do
      if [ -n "$(cat /var/ossec/etc/ossec.conf | grep "<address>${ADDRESSES[i]}</address>")" ]; then
        echo "WAZUH_MANAGER is correct"
      else
        echo "WAZUH_MANAGER is not correct"
        exit 1
      fi
    done
  fi

  if [ -n "$(echo "${@}"| grep -w "WAZUH_MANAGER_PORT")" ]; then
    if [ -n "$(cat /var/ossec/etc/ossec.conf | grep "<port>${WAZUH_MANAGER_PORT}</port>")" ]; then
      echo "WAZUH_MANAGER_PORT is correct"
    else
      echo "WAZUH_MANAGER_PORT is not correct"
      exit 1
    fi
  fi

  if [ -n "$(echo "${@}"| grep -w "WAZUH_PROTOCOL")" ]; then
    PROTOCOLS=( $(echo ${WAZUH_PROTOCOL} | sed "s#,# #g") )
    for i in ${!PROTOCOLS[@]}; do
      if [ -n "$(cat /var/ossec/etc/ossec.conf | grep "<protocol>${PROTOCOLS[i]}</protocol>")" ]; then
        echo "WAZUH_PROTOCOL is correct"
      else
        echo "WAZUH_PROTOCOL is not correct"
        exit 1
      fi
    done
  fi

  if [ -n "$(echo "${@}"| grep -w "WAZUH_REGISTRATION_SERVER")" ]; then
    if [ -n "$(cat /var/ossec/etc/ossec.conf | grep "<manager_address>${WAZUH_REGISTRATION_SERVER}</manager_address>")" ]; then
      echo "WAZUH_REGISTRATION_SERVER is correct"
    else
      echo "WAZUH_REGISTRATION_SERVER is not correct"
      exit 1
    fi
  fi

  if [ -n "$(echo "${@}"| grep -w "WAZUH_REGISTRATION_PORT")" ]; then
    if [ -n "$(cat /var/ossec/etc/ossec.conf | grep "<port>${WAZUH_REGISTRATION_PORT}</port>")" ]; then
      echo "WAZUH_REGISTRATION_PORT is correct"
    else
      echo "WAZUH_REGISTRATION_PORT is not correct"
      exit 1
    fi
  fi

  if [ -n "$(echo "${@}"| grep -w "WAZUH_REGISTRATION_PASSWORD")" ]; then
    if [ -n "cat /var/ossec/${WAZUH_REGISTRATION_PASSWORD_PATH} | grep ${WAZUH_REGISTRATION_PASSWORD})" ]; then
      echo "WAZUH_REGISTRATION_PASSWORD is correct"
    else
      echo "WAZUH_REGISTRATION_PASSWORD is not correct"
      exit 1
    fi
  fi

  if [ -n "$(echo "${@}"| grep -w "WAZUH_KEEP_ALIVE_INTERVAL")" ]; then
    if [ -n "$(cat /var/ossec/etc/ossec.conf | grep "<notify_time>${WAZUH_KEEP_ALIVE_INTERVAL}</notify_time>")" ]; then
      echo "WAZUH_KEEP_ALIVE_INTERVAL is correct"
    else
      echo "WAZUH_KEEP_ALIVE_INTERVAL is not correct"
      exit 1
    fi
  fi

  if [ -n "$(echo "${@}"| grep -w "WAZUH_TIME_RECONNECT")" ]; then
    if [ -n "$(cat /var/ossec/etc/ossec.conf | grep "<time-reconnect>${WAZUH_TIME_RECONNECT}</time-reconnect>")" ]; then
      echo "WAZUH_TIME_RECONNECT is correct"
    else
      echo "WAZUH_TIME_RECONNECT is not correct"
      exit 1
    fi
  fi

  if [ -n "$(echo "${@}"| grep -w "WAZUH_REGISTRATION_CA")" ]; then
    if [ -n "$(cat /var/ossec/etc/ossec.conf | grep "<server_ca_path>${WAZUH_REGISTRATION_CA}</server_ca_path>")" ]; then
      echo "WAZUH_REGISTRATION_CA is correct"
    else
      echo "WAZUH_REGISTRATION_CA is not correct"
      exit 1
    fi
  fi

  if [ -n "$(echo "${@}"| grep -w "WAZUH_REGISTRATION_CERTIFICATE")" ]; then
    if [ -n "$(cat /var/ossec/etc/ossec.conf | grep "<agent_certificate_path>${WAZUH_REGISTRATION_CERTIFICATE}</agent_certificate_path>")" ]; then
      echo "WAZUH_REGISTRATION_CERTIFICATE is correct"
    else
      echo "WAZUH_REGISTRATION_CERTIFICATE is not correct"
      exit 1
    fi
  fi

  if [ -n "$(echo "${@}"| grep -w "WAZUH_REGISTRATION_KEY")" ]; then
    if [ -n "$(cat /var/ossec/etc/ossec.conf | grep "<agent_key_path>${WAZUH_REGISTRATION_KEY}</agent_key_path>")" ]; then
      echo "WAZUH_REGISTRATION_KEY is correct"
    else
      echo "WAZUH_REGISTRATION_KEY is not correct"
      exit 1
    fi
  fi

  if [ -n "$(echo "${@}"| grep -w "WAZUH_AGENT_NAME")" ]; then
    if [ -n "$(cat /var/ossec/etc/ossec.conf | grep "<agent_name>${WAZUH_AGENT_NAME}</agent_name>")" ]; then
      echo "WAZUH_AGENT_NAME is correct"
    else
      echo "WAZUH_AGENT_NAME is not correct"
      exit 1
    fi
  fi

  if [ -n "$(echo "${@}"| grep -w "WAZUH_AGENT_GROUP")" ]; then
    if [ -n "$(cat /var/ossec/etc/ossec.conf | grep "<groups>${WAZUH_AGENT_GROUP}</groups>")" ]; then
      echo "WAZUH_AGENT_GROUP is correct"
    else
      echo "WAZUH_AGENT_GROUP is not correct"
      exit 1
    fi
  fi
  
  if [ -n "$(echo "${@}"| grep -w "ENROLLMENT_DELAY")" ]; then
    if [ -n "$(cat /var/ossec/etc/ossec.conf | grep "<delay_after_enrollment>${ENROLLMENT_DELAY}</delay_after_enrollment>")" ]; then
      echo "ENROLLMENT_DELAY is correct"
    else
      echo "ENROLLMENT_DELAY is not correct"
      exit 1
    fi
  fi

}

wget https://s3.us-west-1.amazonaws.com/packages-dev.wazuh.com/warehouse/pullrequests/${MAJOR}.${MINOR}/deb/var/wazuh-agent_${VERSION}-commit${SHA}_amd64.deb > /dev/null 2>&1


install_wazuh "WAZUH_MANAGER=1.1.1.1 WAZUH_MANAGER_PORT=7777 WAZUH_PROTOCOL=udp WAZUH_REGISTRATION_SERVER=2.2.2.2 WAZUH_REGISTRATION_PORT=8888 WAZUH_REGISTRATION_PASSWORD=password WAZUH_KEEP_ALIVE_INTERVAL=10 WAZUH_TIME_RECONNECT=10 WAZUH_REGISTRATION_CA=/var/ossec/etc/testsslmanager.cert WAZUH_REGISTRATION_CERTIFICATE=/var/ossec/etc/testsslmanager.cert WAZUH_REGISTRATION_KEY=/var/ossec/etc/testsslmanager.key WAZUH_AGENT_NAME=test-agent WAZUH_AGENT_GROUP=test-group ENROLLMENT_DELAY=10" 
test "WAZUH_MANAGER WAZUH_MANAGER_PORT WAZUH_PROTOCOL WAZUH_REGISTRATION_SERVER WAZUH_REGISTRATION_PORT WAZUH_REGISTRATION_PASSWORD WAZUH_KEEP_ALIVE_INTERVAL WAZUH_TIME_RECONNECT WAZUH_REGISTRATION_CA WAZUH_REGISTRATION_CERTIFICATE WAZUH_REGISTRATION_KEY WAZUH_AGENT_NAME WAZUH_AGENT_GROUP ENROLLMENT_DELAY" 
remove_wazuh

install_wazuh "WAZUH_MANAGER=1.1.1.1"
test "WAZUH_MANAGER"
remove_wazuh

install_wazuh "WAZUH_MANAGER_PORT=7777"
test "WAZUH_MANAGER_PORT"
remove_wazuh

install_wazuh "WAZUH_PROTOCOL=udp"
test "WAZUH_PROTOCOL"
remove_wazuh

install_wazuh "WAZUH_REGISTRATION_SERVER=2.2.2.2"
test "WAZUH_REGISTRATION_SERVER"
remove_wazuh

install_wazuh "WAZUH_REGISTRATION_PORT=8888"
test "WAZUH_REGISTRATION_PORT"
remove_wazuh

install_wazuh "WAZUH_REGISTRATION_PASSWORD=password"
test "WAZUH_REGISTRATION_PASSWORD"
remove_wazuh

install_wazuh "WAZUH_KEEP_ALIVE_INTERVAL=10"
test "WAZUH_KEEP_ALIVE_INTERVAL"
remove_wazuh

install_wazuh "WAZUH_TIME_RECONNECT=10"
test "WAZUH_TIME_RECONNECT"
remove_wazuh

install_wazuh "WAZUH_REGISTRATION_CA=/var/ossec/etc/testsslmanager.cert"
test "WAZUH_REGISTRATION_CA"
remove_wazuh

install_wazuh "WAZUH_REGISTRATION_CERTIFICATE=/var/ossec/etc/testsslmanager.cert"
test "WAZUH_REGISTRATION_CERTIFICATE"
remove_wazuh

install_wazuh "WAZUH_REGISTRATION_KEY=/var/ossec/etc/testsslmanager.key"
test "WAZUH_REGISTRATION_KEY"
remove_wazuh

install_wazuh "WAZUH_AGENT_NAME=test-agent"
test "WAZUH_AGENT_NAME"
remove_wazuh

install_wazuh "WAZUH_AGENT_GROUP=test-group"
test "WAZUH_AGENT_GROUP"
remove_wazuh

install_wazuh "ENROLLMENT_DELAY=10"
test "ENROLLMENT_DELAY"
remove_wazuh

