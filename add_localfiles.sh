#!/bin/sh

# Wazuh Configuration File Generator
# Copyright (C) 2016 Wazuh Inc.
# November 24, 2016.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Looking up for the execution directory
cd `dirname $0`

. ./src/init/inst-functions.sh

INSTALLDIR="/var/ossec"
NEWCONFIG="./localfiles.temp"

if [ -r "$NEWCONFIG" ]; then
    rm "$NEWCONFIG"
fi

echo "" >> $NEWCONFIG
echo "<ossec_config>" >> $NEWCONFIG
WriteLogs "add"
echo "</ossec_config>" >> $NEWCONFIG

cat "$NEWCONFIG" # >> "$INSTALLDIR/etc/ossec.conf"

rm "$NEWCONFIG"

exit 0
