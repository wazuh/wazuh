#!/bin/sh

# Change these values!
# SLACKUSER user who posts notifications
# CHANNEL witch channel it should be posted
# SITE is the URL provided by the Slack's WebHook, something like:
# https://hooks.slack.com/services/TOKEN"
SLACKUSER=""
CHANNEL=""
SITE=""
SOURCE="ossec2slack"

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
ALERTFULL=`grep -A 10 "$ALERTTIME" ${PWD}/../logs/alerts/alerts.log | grep -v ".$ALERTLAST: " -A 10 | grep -v "Src IP: " | grep -v "User: " |grep "Rule: " -A 4 | cut -c -139 | sed 's/\"//g'`

PAYLOAD='{"channel": "'"$CHANNEL"'", "username": "'"$SLACKUSER"'", "text": "'"${ALERTFULL}"'"}'

ls "`which curl`" > /dev/null 2>&1
if [ ! $? = 0 ]; then
    ls "`which wget`" > /dev/null 2>&1
    if [ $? = 0 ]; then
        wget --keep-session-cookies --post-data="${PAYLOAD}" ${SITE} 2>>${PWD}/../logs/active-responses.log
        exit 0;
    fi
else
    curl -X POST --data-urlencode "payload=${PAYLOAD}" ${SITE} 2>>${PWD}/../logs/active-responses.log
    exit 0;
fi

echo "`date` $0: Unable to find curl or wget." >> ${PWD}/../logs/active-responses.log
exit 1;
