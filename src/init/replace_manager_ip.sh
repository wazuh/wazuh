#!/bin/bash

# Copyright (C) 2015-2019, Wazuh Inc.All rights reserved.
# Wazuh.com

# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Just for agents
# Prints the current ossec.conf with <address> of ossec.conf specified as first argument.
# Example: ./replace_manager_ip.sh /var/ossec/etc/ossec.conf.rpmorig

# Aux functions
check_tag_in_file() {  # tag file
    match=$(grep "^ *<$1>.*</$1> *\$" $2 2> /dev/null)

    if [ "x$match" != "x" ]; then
        echo "1"
    else
        echo "0"
    fi
}

get_value_tag () {  # tag file
    line=$(grep "^ *<$1>.*</$1> *\$" $2 2> /dev/null)
    regex="<$1>(.+)</$1>"

    if [[ $line =~ $regex ]]; then
        echo "${BASH_REMATCH[1]}"
    else
        echo "0"
    fi
}

edit_value_tag() {  # tag file value
    if [ "$#" == "3" ]; then
        sed -ri "s#<address>.+</address>#<$1>$3</$1>#g" $2 > /dev/null
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
    new_config="$2"
    status="1"
    tag_server="address"

    line_server=$(check_tag_in_file $tag_server $old_config)

    if [ "$line_server" == "1" ]; then
        replace $tag_server $old_config $new_config
        status="0"
    fi

    if [ "$status" == "1" ]; then
        echo "Error updating ossec.conf with previous IP or host."
        exit 1
    fi

    exit 0
}

# Main
if [ "$#" = "2" ]; then
    main $1 $2
else
      echo " USE: ./replace_manager_ip.sh previous_ossec.conf new_ossec.conf"
      exit 2
fi
