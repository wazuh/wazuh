#!/bin/sh
# Simple utilities
# Add a new file
# Add a new remote host to be monitored via lynx
# Add a new remote host to be monitored (DNS)
# Add a new command to be monitored
# by Daniel B. Cid - dcid ( at ) ossec.net

ACTION=$1
FILE=$2
FORMAT=$3

if ! [ -e /etc/ossec-init.conf ]; then
    echo OSSEC Manager not found. Exiting...
    exit 1
fi

. /etc/ossec-init.conf

if [ "X$FILE" = "X" ]; then
    echo "$0: addfile <filename> [<format>]"
    echo "$0: addsite <domain>"
    echo "$0: adddns  <domain>"
    #echo "$0: addcommand <command>"
    echo ""
    #echo "Example: $0 addcommand 'netstat -tan |grep LISTEN| grep -v 127.0.0.1'"
    echo "Example: $0 adddns ossec.net"
    echo "Example: $0 addsite dcid.me"
    exit 1;
fi

if [ "X$FORMAT" = "X" ]; then
    FORMAT="syslog"
fi

# Adding a new file
if [ $ACTION = "addfile" ]; then
    # Checking if file is already configured
    grep "$FILE" ${DIRECTORY}/etc/ossec.conf > /dev/null 2>&1
    if [ $? = 0 ]; then
        echo "$0: File $FILE already configured at ossec."
        exit 1;
    fi

    # Checking if file exist
    ls -la $FILE > /dev/null 2>&1
    if [ ! $? = 0 ]; then
        echo "$0: File $FILE does not exist."
        exit 1;
    fi     
    
    echo "
    <ossec_config>
      <localfile>
      <log_format>$FORMAT</log_format>
      <location>$FILE</location>
     </localfile>
   </ossec_config>  
   " >> ${DIRECTORY}/etc/ossec.conf

   echo "$0: File $FILE added.";
   exit 0;            
fi


# Adding a new DNS check
if [ $ACTION = "adddns" ]; then
   COMMAND="host -W 5 -t NS $FILE; host -W 5 -t A $FILE | sort"
   echo $FILE | grep -E '^[a-z0-9A-Z.-]+$' >/dev/null 2>&1
   if [ $? = 1 ]; then
      echo "$0: Invalid domain: $FILE"
      exit 1;
   fi

   grep "host -W 5 -t NS $FILE" ${DIRECTORY}/etc/ossec.conf >/dev/null 2>&1
   if [ $? = 0 ]; then
       echo "$0: Already configured for $FILE"
       exit 1;
   fi

   MYERR=0
   echo "
   <ossec_config>
   <localfile>
     <log_format>full_command</log_format>
     <command>$COMMAND</command>
   </localfile>
   </ossec_config>
   " >> ${DIRECTORY}/etc/ossec.conf || MYERR=1;

   if [ $MYERR = 1 ]; then
       echo "$0: Unable to modify the configuration file."; 
       exit 1;
   fi

   FIRSTRULE="150010"
   while [ 1 ]; do
       grep "\"$FIRSTRULE\"" ${DIRECTORY}/rules/local_rules.xml > /dev/null 2>&1
       if [ $? = 0 ]; then
           FIRSTRULE=`expr $FIRSTRULE + 1`
       else
           break;
       fi
   done


   echo "
   <group name=\"local,dnschanges,\">
   <rule id=\"$FIRSTRULE\" level=\"0\">
     <if_sid>530</if_sid>
     <check_diff />
     <match>^ossec: output: 'host -W 5 -t NS $FILE</match>
     <description>DNS Changed for $FILE</description>
   </rule>
   </group>
   " >> ${DIRECTORY}/rules/local_rules.xml || MYERR=1;

   if [ $MYERR = 1 ]; then
       echo "$0: Unable to modify the local rules file.";
       exit 1;
   fi

   echo "Domain $FILE added to be monitored."
   exit 0;
fi


# Adding a new lynx check
if [ $ACTION = "addsite" ]; then
   COMMAND="lynx --connect_timeout 10 --dump $FILE | head -n 10"
   echo $FILE | grep -E '^[a-z0-9A-Z.-]+$' >/dev/null 2>&1
   if [ $? = 1 ]; then
      echo "$0: Invalid domain: $FILE"
      exit 1;
   fi

   grep "lynx --connect_timeout 10 --dump $FILE" ${DIRECTORY}/etc/ossec.conf >/dev/null 2>&1
   if [ $? = 0 ]; then
       echo "$0: Already configured for $FILE"
       exit 1;
   fi

   MYERR=0
   echo "
   <ossec_config>
   <localfile>
     <log_format>full_command</log_format>
     <command>$COMMAND</command>
   </localfile>
   </ossec_config>
   " >> ${DIRECTORY}/etc/ossec.conf || MYERR=1;

   if [ $MYERR = 1 ]; then
       echo "$0: Unable to modify the configuration file."; 
       exit 1;
   fi

   FIRSTRULE="150010"
   while [ 1 ]; do
       grep "\"$FIRSTRULE\"" ${DIRECTORY}/rules/local_rules.xml > /dev/null 2>&1
       if [ $? = 0 ]; then
           FIRSTRULE=`expr $FIRSTRULE + 1`
       else
           break;
       fi
   done


   echo "
   <group name=\"local,sitechange,\">
   <rule id=\"$FIRSTRULE\" level=\"0\">
     <if_sid>530</if_sid>
     <check_diff />
     <match>^ossec: output: 'lynx --connect_timeout 10 --dump $FILE</match>
     <description>DNS Changed for $FILE</description>
   </rule>
   </group>
   " >> ${DIRECTORY}/rules/local_rules.xml || MYERR=1;

   if [ $MYERR = 1 ]; then
       echo "$0: Unable to modify the local rules file.";
       exit 1;
   fi

   echo "Domain $FILE added to be monitored."
   exit 0;
fi


