#!/bin/bash

###
# Integration of Wazuh agent with Kaspersky endpoint security for Linux
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
##


. /etc/ossec-init.conf 2> /dev/null || exit 1

python2="/usr/bin/python"
python3="/usr/bin/python3"

if [ -f "$python2" ]
then
        python $DIRECTORY/active-response/bin/kaspersky.py "$@"
elif [ -f "$python3" ]
then
        python3 $DIRECTORY/active-response/bin/kaspersky.py "$@"
else
        echo "Python binary not found"
fi

