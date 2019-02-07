#!/bin/sh
# Add a localfile to ossec.
# Copyright (C) 2015-2019, Wazuh Inc.
# by Daniel B. Cid - dcid ( at ) ossec.net

FILE=$1
FORMAT=$2

if [ "X$FILE" = "X" ]; then
    echo "$0: <filename> [<format>]"
    exit 1;
fi

if [ "X$FORMAT" = "X" ]; then
    FORMAT="syslog"
fi

# Checking if file is already configured
grep "$FILE" /var/ossec/etc/ossec.conf > /dev/null 2>&1
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
" >> /var/ossec/etc/ossec.conf

echo "$0: File $FILE added.";
exit 0;            
