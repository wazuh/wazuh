#!/bin/sh

# Wazuh Configuration File Generator
# Copyright (C) 2015, Wazuh Inc.
# November 24, 2016.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Looking up for the execution directory
cd `dirname $0`

. ./src/init/shared.sh
. ./src/init/inst-functions.sh

NEWCONFIG="./localfiles.temp"

if [ -r "$NEWCONFIG" ]; then
    rm "$NEWCONFIG"
fi

if [ "$#" = "1" ]; then
  INSTALLDIR="$1"
fi

echo "" >> $NEWCONFIG

if [ "X${INSTYPE}" = "Xagent" ]; then
  echo "<ossec_config>" >> $NEWCONFIG
else
  echo "<wazuh_config>" >> $NEWCONFIG
fi

WriteLogs "add"

if [ "X${INSTYPE}" = "Xagent" ]; then
  echo "</ossec_config>" >> $NEWCONFIG
else
  echo "</wazuh_config>" >> $NEWCONFIG
fi

cat "$NEWCONFIG"

rm "$NEWCONFIG"

exit 0
