#! /bin/bash

# Copyright (C) 2015-2020, Wazuh Inc.

#####
# This checks for an error and exits with a custom message
# Returns zero on success
# $1 is the message
# $2 is the error code

function check_errm
{
   if  [[ ${?} != "0" ]]
      then
      echo "${1}";
      exit ${2};
      fi
}

USER=$1
USER_MAIL=$2
USER_REM=$3
GROUP=$4

if ! [ $# -eq 4 ]; then
    echo $#
    echo "Usage: ${0} USERNAME_DEFAULT USERNAME_MAIL USERNAME_REMOTE GROUPNAME.";
    exit 1;
fi

if [[ ! -f "/usr/bin/dscl" ]]
  then
  echo "Error, I have no dscl, dying here";
  exit
fi

DSCL="/usr/bin/dscl";

# Removing the users.

OSSECUSERS="${USER_REM} ${USER_MAIL} ${USER}"

for U in ${OSSECUSERS}; do
    if [[ $(dscl . -read /Users/${U} 2>/dev/null) ]]
       then
       sudo ${DSCL} localhost -delete /Local/Default/Users/${U}
       check_errm "Error removing user ${U}" "87"
    else
       echo "${U} don't exists";
    fi
done

# Removing the group.
sudo ${DSCL} localhost -delete /Local/Default/Groups/${GROUP}
check_errm "Error removing group $GROUP" "67"