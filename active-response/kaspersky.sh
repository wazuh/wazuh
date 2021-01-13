#!/bin/sh

###
# Integration of Wazuh agent with Kaspersky endpoint security for Linux
# Copyright (C) 2015-2020, Wazuh Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
##

SCRIPT=$(readlink -f "$0")
S_PATH=$(dirname "$SCRIPT")
python2="/usr/bin/python"
python3="/usr/bin/python3"

if [ -f "$python2" ]
then
        python ${S_PATH}/kaspersky.py "$@"
elif [ -f "$python3" ]
then
        python3 ${S_PATH}/kaspersky.py "$@"
else
        echo "Python binary not found"
fi

