#!/bin/sh
# Tweeter an alert - copy at /var/ossec/active-response/bin/ossec-tweeter.sh
# Copyright (C) 2015-2019, Wazuh Inc.
# Author: Daniel Cid


# Change these values!
TWITTERUSER=""
TWITTERPASS=''
DIRECTMSGUSER=""
SOURCE="ossec2tweeter"



# Checking user arguments
if [ "x$1" = "xdelete" ]; then
    exit 0;
fi    
ALERTID=$4
RULEID=$5
LOCAL=`dirname $0`;
ALERTTIME=`echo "$ALERTID" | cut -d  "." -f 1`
ALERTLAST=`echo "$ALERTID" | cut -d  "." -f 2`



# Logging
cd $LOCAL
cd ../
PWD=`pwd`
echo "`date` $0 $1 $2 $3 $4 $5 $6 $7 $8" >> ${PWD}/../logs/active-responses.log
ALERTFULL=`grep -A 10 "$ALERTTIME" ${PWD}/../logs/alerts/alerts.log | grep -v "\.$ALERTLAST: " -A 10 | grep -v "Src IP: " | grep -v "User: " |grep "Rule: " -A 4 | cut -c -139`



# Checking if we are sending direct message or not.
if [ "x" = "x$DIRECTMSGUSER" ]; then
    SITE="http://twitter.com/statuses/update.xml"
    REQUESTUSER=""
    REQUESTMSG="status=$ALERTFULL"
else
    SITE="http://twitter.com/direct_messages/new.xml"
    REQUESTUSER="user=$DIRECTMSGUSER&"
    REQUESTMSG="text=$ALERTFULL"
fi    


ls "`which curl`" > /dev/null 2>&1
if [ ! $? = 0 ]; then
    ls "`which wget`" > /dev/null 2>&1
    if [ $? = 0 ]; then
        wget --keep-session-cookies --http-user=$TWITTERUSER --http-password=$TWITTERPASS --post-data="source=$SOURCE&$REQUESTUSER$REQUESTMSG" $SITE 2>>${PWD}/../logs/active-responses.log
        exit 0;
    fi    
else
    curl -u "$TWITTERUSER:$TWITTERPASS" -d "source=$SOURCE&$REQUESTUSER$REQUESTMSG" $SITE 2>>${PWD}/../logs/active-responses.log    
    exit 0;
fi    

echo "`date` $0: Unable to find curl or wget." >> ${PWD}/../logs/active-responses.log
exit 1;
