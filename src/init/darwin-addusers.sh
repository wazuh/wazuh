#! /bin/bash

# Copyright (C) 2015, Wazuh Inc.
# By Spransy, Derek" <DSPRANS () emory ! edu> and Charlie Scott

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
GROUP=$2
DIR=$3

if ! [ $# -eq 3 ]; then
    echo $#
    echo "Usage: ${0} USERNAME_DEFAULT GROUPNAME DIRECTORY.";
    exit 1;
fi

if [[ ! -f "/usr/bin/dscl" ]]
  then
  echo "Error, I have no dscl, dying here";
  exit
fi

DSCL="/usr/bin/dscl";

# get unique id numbers (uid, gid) that are greater than 100
unset -v i new_uid new_gid idvar;
declare -i new_uid=0 new_gid=0 i=100 idvar=0;
while [[ $idvar -eq 0 ]]; do
   i=$[i+1]
   j=$[i+1]
   k=$[i+2]
   if [[ -z "$(/usr/bin/dscl . -search /Users uid ${i})" ]] && [[ -z "$(/usr/bin/dscl . -search /Groups gid ${i})" ]] && \
      [[ -z "$(/usr/bin/dscl . -search /Users uid ${j})" ]] && [[ -z "$(/usr/bin/dscl . -search /Groups gid ${j})" ]] && \
      [[ -z "$(/usr/bin/dscl . -search /Users uid ${k})" ]] && [[ -z "$(/usr/bin/dscl . -search /Groups gid ${k})" ]];
      then
      new_uid=$i
      new_gid=$i
      idvar=1
      #break
   fi
done

echo "UIDs available: $i $j $k";

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


# Creating the groups.
sudo ${DSCL} localhost -create /Local/Default/Groups/${GROUP}
check_errm "Error creating group $GROUP" "67"
sudo ${DSCL} localhost -createprop /Local/Default/Groups/${GROUP} PrimaryGroupID ${new_gid}
sudo ${DSCL} localhost -createprop /Local/Default/Groups/${GROUP} RealName ${GROUP}
sudo ${DSCL} localhost -createprop /Local/Default/Groups/${GROUP} RecordName ${GROUP}
sudo ${DSCL} localhost -createprop /Local/Default/Groups/${GROUP} RecordType: dsRecTypeStandard:Groups
sudo ${DSCL} localhost -createprop /Local/Default/Groups/${GROUP} Password "*"


# Creating the users.
if [[ $(dscl . -read /Users/${USER} 2>/dev/null) ]]
   then
   echo "${USER} already exists";
else
   sudo ${DSCL} localhost -create /Local/Default/Users/${USER}
   check_errm "Error creating user ${USER}" "87"
   sudo ${DSCL} localhost -createprop /Local/Default/Users/${USER} RecordName ${USER}
   sudo ${DSCL} localhost -createprop /Local/Default/Users/${USER} RealName "${USER}acct"
   sudo ${DSCL} localhost -createprop /Local/Default/Users/${USER} NFSHomeDirectory ${DIR}
   sudo ${DSCL} localhost -createprop /Local/Default/Users/${USER} UniqueID ${i}
   sudo ${DSCL} localhost -createprop /Local/Default/Users/${USER} PrimaryGroupID ${new_gid}
   sudo ${DSCL} localhost -append /Local/Default/Groups/${GROUP} GroupMembership ${USER}
   sudo ${DSCL} localhost -createprop /Local/Default/Users/${USER} Password "*"
fi

sudo ${DSCL} . create /Users/wazuh IsHidden 1
