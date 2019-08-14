#! /bin/bash

# Copyright (C) 2015-2019, Wazuh Inc.
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
USER_MAIL=$2
USER_REM=$3
GROUP=$4
INSTYPE=$5

if ! [ $# -eq 5 ]; then
    echo $#
    echo "Usage: ${0} USERNAME_DEFAULT USERNAME_MAIL USERNAME_REMOTE GROUPNAME INSTYPE.";
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

if [ "X$INSTYPE" = "Xserver" ]; then
    NEWUSERS="${USER} ${USER_MAIL} ${USER_REM}"
elif [ "X$INSTYPE" = "Xlocal" ]; then
    NEWUSERS="${USER} ${USER_MAIL}"
else
    NEWUSERS=${USER}
fi

for U in ${NEWUSERS}; do
    if [[ $(dscl . -read /Users/${U} 2>/dev/null) ]]
       then
       echo "${U} already exists";
    else
       sudo ${DSCL} localhost -create /Local/Default/Users/${U}
       check_errm "Error creating user ${U}" "87"
       sudo ${DSCL} localhost -createprop /Local/Default/Users/${U} RecordName ${U}
       sudo ${DSCL} localhost -createprop /Local/Default/Users/${U} RealName "${U}acct"
       sudo ${DSCL} localhost -createprop /Local/Default/Users/${U} NFSHomeDirectory /var/ossec
       sudo ${DSCL} localhost -createprop /Local/Default/Users/${U} UniqueID ${i}
       sudo ${DSCL} localhost -createprop /Local/Default/Users/${U} PrimaryGroupID ${new_gid}
       sudo ${DSCL} localhost -append /Local/Default/Groups/${GROUP} GroupMembership ${U}
       sudo ${DSCL} localhost -createprop /Local/Default/Users/${U} Password "*"
    fi

    i=$[i+1]
done

sudo ${DSCL} . create /Users/ossec IsHidden 1
sudo ${DSCL} . create /Users/ossecm IsHidden 1
sudo ${DSCL} . create /Users/ossecr IsHidden 1
