#!/bin/bash

# Copyright (C) 2015-2016 Wazuh, Inc.All rights reserved.
# Wazuh.com

# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Just for agents
# Prints the current ossec.conf with <server-ip|hostname> of ossec.conf specified as first argument.
# Example: ./replace_manager_ip.sh /var/ossec/etc/ossec.conf.rpmorig

get_value_tag () {  # tag file
    line=$(grep "^ *<$1>.*</$1> *\$" $2 2> /dev/null)

    if [ $? = 0 ]
    then
        regex="<$1>(.+)</$1>"

        if [[ $line =~ $regex ]]; then
            echo "${BASH_REMATCH[1]}"
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

edit_value_tag() {  # tag file value
    sed -ri "s#<$1>.+</$1>#<$1>$3</$1>#g" $2 2> /dev/null
    return $?
}

main() {
    old_config="$1"
    new_config="$2"

    protocol=$(get_value_tag "protocol" $old_config)

    if [ $? = 0 ]
    then
        edit_value_tag "protocol" $new_config $protocol
        return $?
    fi

    exit 0
}

# Main
if [ "$#" = "2" ]; then
    main $1 $2
else
      echo " USE: ./replace_protocol.sh previous_ossec.conf new_ossec.conf"
      exit 2
fi
