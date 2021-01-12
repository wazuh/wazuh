#!/bin/sh
# Calculate OSSEC events per second
# Author Michael Starks ossec [at] michaelstarks [dot] com
# License: GPLv3

WAZUH_HOME=${1}

#Check syntax
if [ "X${WAZUH_HOME}" = "X" ]; then
  echo "Usage: $0 WAZUH_HOME"
  exit 1
fi

eval $(${WAZUH_HOME}/bin/wazuh-control info 2>/dev/null)

#Check if Wazuh is installed
if [ "X${WAZUH_TYPE}" = "X" ]; then
  echo "Wazuh does not appear to be installed on this system."
  exit 1
fi

#Check if it is Wazuh Manager
if [ "${WAZUH_TYPE}" = "agent" ]; then
  echo "This script can only be run on the manager."
  exit 1
fi

#Reset counters
COUNT=0
EPSSUM=0
EPSAVG=0

for i in $(grep 'Total events for day' ${WAZUH_HOME}/stats/totals/*/*/ossec-totals-*.log | cut -d: -f3); do
  COUNT=$((COUNT+1))
  DAILYEVENTS=$i
  EPSSUM=$(($DAILYEVENTS+$EPSSUM))
done

EPSAVG=$(($EPSSUM/$COUNT/(86400)))

echo Your total lifetime number of events collected is: $EPSSUM
echo Your total daily number of events average is: $(($EPSSUM/$COUNT))
echo Your daily events per second average is: $EPSAVG
