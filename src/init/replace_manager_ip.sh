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

# Aux functions
check_tag_in_file() {  # tag file
    match=`cat $2 2> /dev/null | grep -P "^\s*<$1>"`

    if [ "x$match" != "x" ]; then
        echo "1"
    else
        echo "0"
    fi
}

get_value_tag () {  # tag file
    line=`cat $2 2> /dev/null | grep -P "^\s*<$1>"`
    regex="<$1>(.+)</$1>"

    if [[ $line =~ $regex ]]; then
        echo "${BASH_REMATCH[1]}"
    else
        echo "0"
    fi
}

edit_value_tag() {  # tag file value overwrite=NO
    if [ "$#" == "4" ]; then  # overwrite
        sed -ri "s#<$1>.+</$1>#<$1>$3</$1>#g" $2 2> /dev/null
    else
        sed -r "s#<$1>.+</$1>#<$1>$3</$1>#g" $2 2> /dev/null
    fi

    if [ "$?" != "0" ]; then
        echo "Error updating $2."
        exit 1
    fi
}

# Functions
replace(){  # tag olf_file new_file
    manager_ip=$(get_value_tag $1 $2)

    if [ "$manager_ip" == "0" ]; then
        echo "Error updating ossec.conf with previous IP or host: IP or hostname not found."
        exit 1
    fi

    edit_value_tag $1 $3 $manager_ip
}

main() {
    old_config="$1"
    new_config="/var/ossec/etc/ossec.conf"
    status="1"
    tag_serverip="server-ip"
    tag_serverhostname="server-hostname"

    line_ip=$(check_tag_in_file $tag_serverip $old_config)
    line_host=$(check_tag_in_file $tag_serverhostname $old_config)

    if [ "$line_ip" == "1" ]; then
        replace $tag_serverip $old_config $new_config
        status="0"
    fi

    if [ "$line_host" == "1" ]; then
        replace $tag_serverhostname $old_config $new_config
        status="0"
    fi

    if [ "$status" == "1" ]; then
        echo "Error updating ossec.conf with previous IP or host."
        exit 1
    fi

    exit 0
}

# Main
if [ "$#" = "1" ]; then
    main $1
else
      echo " USE: ./replace_manager_ip.sh previous_ossec.conf"
      exit 2
fi
