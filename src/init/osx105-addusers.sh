#! /bin/bash
# By Spransy, Derek" <DSPRANS () emory ! edu> and Charlie Scott

#####
# This checks for an error and exits with a custom message
# Returns zero on success
# $1 is the message
# $2 is the error code

if [[ ! -f "/usr/bin/dscl" ]]
  then
  echo "Error, I have no dscl, dying here";
  exit
fi

DSCL="/usr/bin/dscl";

function check_errm
{
   if  [[ ${?} != "0" ]]
      then
      echo "${1}";
      exit ${2};
      fi
}

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

echo "UIDs available are:";
echo ${new_uid}
echo ${j}
echo ${k}

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
sudo ${DSCL} localhost -create /Local/Default/Groups/ossec
check_errm "Error creating group ossec" "67"
sudo ${DSCL} localhost -createprop /Local/Default/Groups/ossec PrimaryGroupID ${new_gid}
sudo ${DSCL} localhost -createprop /Local/Default/Groups/ossec RealName ossec
sudo ${DSCL} localhost -createprop /Local/Default/Groups/ossec RecordName ossec
sudo ${DSCL} localhost -createprop /Local/Default/Groups/ossec RecordType: dsRecTypeStandard:Groups
sudo ${DSCL} localhost -createprop /Local/Default/Groups/ossec Password "*"


# Creating the users.

if [[ $(dscl . -read /Users/ossecm) ]]
   then
   echo "ossecm already exists";
else
   sudo ${DSCL} localhost -create /Local/Default/Users/ossecm
   check_errm "Error creating user ossecm" "87"
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossecm RecordName ossecm
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossecm RealName "ossecmacct"
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossecm NFSHomeDirectory /var/ossec
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossecm UniqueID ${j}
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossecm PrimaryGroupID ${new_gid}
   sudo ${DSCL} localhost -append /Local/Default/Groups/ossec GroupMembership ossecm
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossecm Password "*"
fi

if [[ $(dscl . -read /Users/ossecr) ]]
   then
   echo "ossecr already exists";
else
   sudo ${DSCL} localhost -create /Local/Default/Users/ossecr
   check_errm "Error creating user ossecr" "97"
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossecr RecordName ossecr
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossecr RealName "ossecracct"
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossecr NFSHomeDirectory /var/ossec
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossecr UniqueID ${k}
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossecr PrimaryGroupID ${new_gid}
   sudo ${DSCL} localhost -append /Local/Default/Groups/ossec GroupMembership ossecr
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossecr Password "*"
fi

if [[ $(dscl . -read /Users/ossec) ]]
   then
   echo "ossec already exists";
else
   sudo ${DSCL} localhost -create /Local/Default/Users/ossec
   check_errm "Error creating user ossec" "77"
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossec RecordName ossec
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossec RealName "ossecacct"
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossec NFSHomeDirectory /var/ossec
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossec UniqueID ${new_uid}
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossec PrimaryGroupID ${new_gid}
   sudo ${DSCL} localhost -append /Local/Default/Groups/ossec GroupMembership ossec
   sudo ${DSCL} localhost -createprop /Local/Default/Users/ossec Password "*"
fi

