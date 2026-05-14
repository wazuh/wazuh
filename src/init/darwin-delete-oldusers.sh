#! /bin/bash

# Copyright (C) 2015, Wazuh Inc.

#####
# This checks for an error and exits with a custom message
# Returns zero on success
# $1 is the message
# $2 is the error code

function check_errm
{
   if  [[ ${?} != "0" ]]; then
      echo "${1}";
      exit ${2};
   fi
}

USER=ossec
USER_MAIL=ossecm
USER_REM=ossecr
GROUP=$1

if ! [ $# -eq 1 ]; then
   echo $#
   echo "Usage: ${0} GROUPNAME.";
   exit 1;
fi

if [[ ! -f "/usr/bin/dscl" ]]; then
   echo "Unable to find dscl. Exiting.";
   exit
fi

DSCL="/usr/bin/dscl";

# Removing the users.
OSSECUSERS="${USER_REM} ${USER_MAIL} ${USER}"

for U in ${OSSECUSERS}; do
   if [[ $(dscl . -read /Users/${U} 2>/dev/null) ]]; then
      sudo ${DSCL} localhost -delete /Local/Default/Users/${U}
      check_errm "Error removing user ${U}" "87"
   else
      echo "${U} doesn't exist";
   fi
done

# Removing the group.
sudo ${DSCL} localhost -delete /Local/Default/Groups/${GROUP}
check_errm "Error removing group $GROUP" "67"
