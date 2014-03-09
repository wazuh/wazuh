#!/bin/sh
# Calculate OSSEC events per second
# Author Michael Starks ossec [at] michaelstarks [dot] com
# License: GPLv3

if [ ! -e /etc/ossec-init.conf ]; then
  echo OSSEC does not appear to be installed on this system. Goodbye.
  exit 1
else
  grep -q agent /etc/ossec-init.conf && echo This script can only be run on the manager. Goodbye. && exit 1
fi

#Reset counters
COUNT=0
EPSSUM=0
EPSAVG=0
#Source OSSEC Dir
. /etc/ossec-init.conf

for i in $(grep 'Total events for day' ${DIRECTORY}/stats/totals/*/*/ossec-totals-*.log | cut -d: -f3); do
  COUNT=$((COUNT+1))
  DAILYEVENTS=$i
  EPSSUM=$(($DAILYEVENTS+$EPSSUM))
done

EPSAVG=$(($EPSSUM/$COUNT/(86400)))

echo Your total lifetime number of events colected is: $EPSSUM
echo Your total daily number of events average is: $(($EPSSUM/$COUNT))
echo Your daily events per second average is: $EPSAVG
