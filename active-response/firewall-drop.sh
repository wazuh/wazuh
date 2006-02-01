#!/bin/sh
# Adds an IP to the iptables drop list (if linux)
# Adds an IP to the ipfilter drop list (if solaris or freebsd)
# Requirements: Linux with iptables or Solaris/FreeBSD/NetBSD with ipfilter
# Expect: srcip
# Author: Daniel B. Cid
# Last modified: Jan 30, 2006

UNAME=`uname`
ECHO="/bin/echo"
IPTABLES="/sbin/iptables"
IPFILTER="/sbin/ipf"
COMMAND=""
ARG1=""
ARG2=""
ACTION=$1
USER=$2
IP=$3

echo "`date` $0 $1 $2 $3" >> /tmp/ossec-hids-responses.log

# Checking for an IP
if [ "x${IP}" = "x" ]; then
   echo "$0: <username> <ip>" 
   exit 1;
fi

# Blocking IP
if [ "x${ACTION}" != "xadd" -a "x${ACTION}" != "xdelete" ]; then
   echo "$0: invalid action: ${ACTION}"
fi


# We should only run on linux
if [ "X${UNAME}" = "XLinux" ]; then
   COMMAND=${IPTABLES}
   if [ "x${ACTION}" = "xadd" ]; then
      ARG1="-I INPUT -s ${IP} -j DROP"
      ARG2="-I FORWARD -s ${IP} -j DROP"
   else
      ARG1="-D INPUT -s ${IP} -j DROP"
      ARG2="-D FORWARD -s ${IP} -j DROP"
   fi
# FreeBSD or SunON with ipfilter
elif [ "X${UNAME}" = "XFreeBSD" -o "X${UNAME}" = "XSunOS" ]; then
   
   COMMAND=${IPFILTER}
   
   # Checking if ipfilter is present
   ls ${IPFILTER} >> /dev/null 2>&1
   if [ $? != 0 ]; then
      exit 0;
   fi    
   
   if [ "x${ACTION}" = "xadd" ]; then
      ARG1="\"@1 block out quick on any from any to ${IP}\"|${COMMAND} -f -"
      ARG1="\"@1 block in quick on any from ${IP} to any\"|${COMMAND} -f -"
   else
      ARG1="\"@1 block out quick on any from any to ${IP}\"|${COMMAND} -rf -"
      ARG1="\"@1 block in quick on any from ${IP} to any\"|${COMMAND} -rf -"
   fi
  
   # Setting command to echo 
   COMMAND=${ECHO}        
else
    exit 0;
fi


# Checking if COMMAND is present (also at /usr)
ls ${COMMAND} >> /dev/null 2>&1
if [ $? != 0 ]; then
   COMMAND="/usr"${COMMAND}
   ls ${COMMAND} >> /dev/null 2>&1
   if [ $? != 0 ]; then
      exit 0;
   fi
fi    


# Issuing the commands
${COMMAND} ${ARG1}
${COMMAND} ${ARG2}

       
exit 0;
