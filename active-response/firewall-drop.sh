#!/bin/sh
# Adds an IP to the iptables drop list (if linux)
# Adds an IP to the ipfilter drop list (if solaris, freebsd or netbsd)
# Requirements: Linux with iptables or Solaris/FreeBSD/NetBSD with ipfilter
# Expect: srcip
# Author: Daniel B. Cid
# Author: Ahmet Ozturk
# Last modified: Feb 01, 2006

UNAME=`uname`
ECHO="/bin/echo"
IPTABLES="/sbin/iptables"
IPFILTER="/sbin/ipf"
ARG1=""
ARG2=""
ACTION=$1
USER=$2
IP=$3


echo "`date` $0 $1 $2 $3" >> /tmp/ossec-hids-responses.log


# Checking for an IP
if [ "x${IP}" = "x" ]; then
   echo "$0: <action> <username> <ip>" 
   exit 1;
fi



# Blocking IP
if [ "x${ACTION}" != "xadd" -a "x${ACTION}" != "xdelete" ]; then
   echo "$0: invalid action: ${ACTION}"
fi



# We should run on linux
if [ "X${UNAME}" = "XLinux" ]; then
   if [ "x${ACTION}" = "xadd" ]; then
      ARG1="-I INPUT -s ${IP} -j DROP"
      ARG2="-I FORWARD -s ${IP} -j DROP"
   else
      ARG1="-D INPUT -s ${IP} -j DROP"
      ARG2="-D FORWARD -s ${IP} -j DROP"
   fi
   
   # Checking if iptables is present
   ls ${IPTABLES} >> /dev/null 2>&1
   if [ $? != 0 ]; then
      IPTABLES="/usr"${IPTABLES}
      ls ${IPTABLES} >> /dev/null 2>&1
      if [ $? != 0 ]; then
         exit 0;
      fi
   fi

   # Executing and exiting
   ${IPTABLES} ${ARG1}
   ${IPTABLES} ${ARG2}                             

   exit 0;
   
# FreeBSD, SunOS or NetBSD with ipfilter
elif [ "X${UNAME}" = "XFreeBSD" -o "X${UNAME}" = "XSunOS" -o "X${UNAME}" = "XNetBSD" ]; then
   
   # Checking if ipfilter is present
   ls ${IPFILTER} >> /dev/null 2>&1
   if [ $? != 0 ]; then
      exit 0;
   fi    

   # Checking if echo is present
   ls ${ECHO} >> /dev/null 2>&1
   if [ $? != 0 ]; then
       exit 0;
   fi    
   
   if [ "x${ACTION}" = "xadd" ]; then
      ARG1="\"@1 block out quick from any to ${IP}\""
      ARG2="\"@1 block in quick from ${IP} to any\""
      IPFARG="${IPFILTER} -f -"
   else
      ARG1="\"@1 block out quick from any to ${IP}\""
      ARG2="\"@1 block in quick from ${IP} to any\""
      IPFARG="${IPFILTER} -rf -"
   fi
  
   # Executing it 
   eval ${ECHO} ${ARG1}| ${IPFARG}       
   eval ${ECHO} ${ARG2}| ${IPFARG}
   
   exit 0;
         
else
    exit 0;
fi
