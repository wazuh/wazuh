#!/bin/bash

# Copyright (C) 2015, Wazuh Inc.
# All rights reserved.
# Wazuh.com

# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Just for agents
# Copies the manager target from the ossec.conf given first into the <endpoint> of the second.
# Example: ./replace_manager_ip.sh /var/wazuh-manager/etc/ossec.conf.rpmorig

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

edit_endpoint_tag() {  # file value
    sed -ri "s#<endpoint>.*</endpoint>#<endpoint>$2</endpoint>#g" $1 > /dev/null

    if [ "$?" != "0" ]; then
        echo "Error updating $1."
        exit 1
    fi
}

# Read the manager target out of the previous configuration. Since #38624 the generated
# configuration carries it as one <endpoint>, so that is what gets written; the older
# spellings are still read here because an upgrade meets whatever the operator had.
previous_endpoint() {  # old_file
    if [ "$(check_tag_in_file endpoint $1)" == "1" ]; then
        # Already the whole target -- carry it across verbatim, port and prefix included.
        get_value_tag endpoint $1
        return
    fi

    # Deprecated <agent><manager><address>, or a 4.x <client><server><address>.
    address=$(get_value_tag address $1)

    if [ "$address" == "0" ]; then
        echo "0"
        return
    fi

    # An IPv6 literal has to be bracketed, or its trailing group reads as the port.
    case "$address" in
        *:*) address="[$address]" ;;
    esac

    # <port> is only carried from an <agent><manager> block. A 4.x <client><server><port>
    # is the old TCP remoted port (1514) that the agent itself ignores, so taking it would
    # move the agent to a port nothing serves; leaving it out selects the 1517 default,
    # which is exactly what the agent does with that configuration.
    if grep -q "<manager>" $1 2> /dev/null; then
        port=$(get_value_tag port $1)

        if [ "$port" != "0" ]; then
            address="$address:$port"
        fi
    fi

    echo "$address"
}

main() {
    old_config="$1"
    new_config="$2"

    endpoint=$(previous_endpoint $old_config)

    if [ "$endpoint" == "0" ] || [ "x$endpoint" == "x" ]; then
        echo "Error updating ossec.conf with previous IP or host."
        exit 1
    fi

    if [ "$(check_tag_in_file endpoint $new_config)" != "1" ]; then
        echo "Error updating $new_config: no <endpoint> to replace."
        exit 1
    fi

    edit_endpoint_tag $new_config "$endpoint"

    exit 0
}

# Main
if [ "$#" = "2" ]; then
    main $1 $2
else
      echo " USE: ./replace_manager_ip.sh previous_ossec.conf new_ossec.conf"
      exit 2
fi
