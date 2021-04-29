#!/bin/sh

# Wazuh Configuration File Generator
# Copyright (C) 2015-2021, Wazuh Inc.
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

NEWCONFIG_AGENT="./localfiles.temp"

if [ -r "$NEWCONFIG_AGENT" ]; then
    rm "$NEWCONFIG_AGENT"
fi

if [ "$#" = "1" ]; then
  INSTALLDIR="$1"
fi

echo "" >> $NEWCONFIG_AGENT
echo "<wazuh_config>" >> $NEWCONFIG_AGENT
WriteLogs "add"
echo "</wazuh_config>" >> $NEWCONFIG_AGENT

cat "$NEWCONFIG_AGENT"

rm "$NEWCONFIG_AGENT"

exit 0
