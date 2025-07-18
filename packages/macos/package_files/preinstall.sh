#! /bin/bash
# By Spransy, Derek" <DSPRANS () emory ! edu> and Charlie Scott
# Modified by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

#####
# This checks for an error and exits with a custom message
# Returns zero on success
# $1 is the message
# $2 is the error code

DIR="/Library/Ossec"
ARCH="PACKAGE_ARCH"

function check_errm
{
    if  [[ ${?} != "0" ]]
        then
        echo "${1}";
        exit ${2};
        fi
}

function check_arch
{
    local system_arch=$(uname -m)

    if [ "$ARCH" = "intel64" ] && [ "$system_arch" = "arm64" ]; then
        if ! arch -x86_64 zsh -c '' &> /dev/null; then
            >&2 echo "ERROR: Rosetta is not installed. Please install it and try again."
            exit 1
        fi
    elif [ "$ARCH" = "arm64" ] && [ "$system_arch" = "x86_64" ]; then
        >&2 echo "ERROR: Incompatible architecture. Please use the Intel package on this system."
        exit 1
    fi
}

check_arch

if [ -d "${DIR}" ]; then
    echo "A Wazuh agent installation was found in ${DIR}. Will perform an upgrade."
    upgrade="true"
    touch "${DIR}/WAZUH_PKG_UPGRADE"

    if [ -f "${DIR}/WAZUH_RESTART" ]; then
        rm -f "${DIR}/WAZUH_RESTART"
    fi

    # Stops the agent before upgrading it
    if ${DIR}/bin/wazuh-control status | grep "is running" > /dev/null 2>&1; then
        touch "${DIR}/WAZUH_RESTART"
        ${DIR}/bin/wazuh-control stop
        restart="true"
    elif ${DIR}/bin/ossec-control status | grep "is running" > /dev/null 2>&1; then
        touch "${DIR}/WAZUH_RESTART"
        ${DIR}/bin/ossec-control stop
        restart="true"
    fi

    echo "Backing up configuration files to ${DIR}/config_files/"
    mkdir -p ${DIR}/config_files/
    cp -r ${DIR}/etc/{ossec.conf,client.keys,local_internal_options.conf,shared} ${DIR}/config_files/

    if [ -d ${DIR}/logs/ossec ]; then
        echo "Renaming ${DIR}/logs/ossec to ${DIR}/logs/wazuh"
        mv ${DIR}/logs/ossec ${DIR}/logs/wazuh
    fi

    if [ -d ${DIR}/queue/ossec ]; then
        echo "Renaming ${DIR}/queue/ossec to ${DIR}/queue/sockets"
        mv ${DIR}/queue/ossec ${DIR}/queue/sockets
    fi

    if pkgutil --pkgs | grep -i wazuh-agent-etc > /dev/null 2>&1 ; then
        echo "Removing previous package receipt for wazuh-agent-etc"
        pkgutil --forget com.Wazuh.pkg.wazuh-agent-etc
    fi
fi

DSCL="/usr/bin/dscl";
if [[ ! -f "$DSCL" ]]
    then
    echo "Error: I couldn't find dscl, dying here";
    exit
fi


# get unique id numbers (uid, gid) that are greater than 100
echo "Getting unique id numbers (uid, gid)"
unset -v i new_uid new_gid idvar;
declare -i new_uid=0 new_gid=0 i=100 idvar=0;
while [[ $idvar -eq 0 ]]; do
    i=$[i+1]
    if [[ -z "$(${DSCL} . -search /Users uid ${i})" ]] && [[ -z "$(${DSCL} . -search /Groups gid ${i})" ]];
        then
        echo "Found available UID and GID: $i"
        new_uid=$i
        new_gid=$i
        idvar=1
   fi
done

echo "UID available for wazuh user is:";
echo ${new_uid}

# Verify that the uid and gid exist and match
if [[ $new_uid -eq 0 ]] || [[ $new_gid -eq 0 ]];
    then
    echo "Getting unique id numbers (uid, gid) failed!";
    exit 1;
fi
if [[ ${new_uid} != ${new_gid} ]]
    then
    echo "I failed to find matching free uid and gid!";
    exit 5;
fi

# Creating the group
echo "Checking group..."
if [[ $(dscl . -read /Groups/wazuh) ]]
    then
    echo "wazuh group already exists.";
else
    sudo ${DSCL} localhost -create /Local/Default/Groups/wazuh
    check_errm "Error creating group wazuh" "67"
    sudo ${DSCL} localhost -createprop /Local/Default/Groups/wazuh PrimaryGroupID ${new_gid}
    sudo ${DSCL} localhost -createprop /Local/Default/Groups/wazuh RealName wazuh
    sudo ${DSCL} localhost -createprop /Local/Default/Groups/wazuh RecordName wazuh
    sudo ${DSCL} localhost -createprop /Local/Default/Groups/wazuh RecordType: dsRecTypeStandard:Groups
    sudo ${DSCL} localhost -createprop /Local/Default/Groups/wazuh Password "*"
fi

# Creating the user
echo "Checking user..."
if [[ $(dscl . -read /Users/wazuh) ]]
    then
    echo "wazuh user already exists.";
else
    sudo ${DSCL} localhost -create /Local/Default/Users/wazuh
    check_errm "Error creating user wazuh" "77"
    sudo ${DSCL} localhost -createprop /Local/Default/Users/wazuh RecordName wazuh
    sudo ${DSCL} localhost -createprop /Local/Default/Users/wazuh RealName wazuh
    sudo ${DSCL} localhost -createprop /Local/Default/Users/wazuh UserShell /usr/bin/false
    sudo ${DSCL} localhost -createprop /Local/Default/Users/wazuh NFSHomeDirectory /var/wazuh
    sudo ${DSCL} localhost -createprop /Local/Default/Users/wazuh UniqueID ${new_uid}
    sudo ${DSCL} localhost -createprop /Local/Default/Users/wazuh PrimaryGroupID ${new_gid}
    sudo ${DSCL} localhost -append /Local/Default/Groups/wazuh GroupMembership wazuh
    sudo ${DSCL} localhost -createprop /Local/Default/Users/wazuh Password "*"
fi

#Hide the fixed users
echo "Hiding the fixed wazuh user"
dscl . create /Users/wazuh IsHidden 1
