#!/usr/bin/env bash

# Restore alerts from Wazuh alerts folder to Elasticsearch cluster.
# Copyright (C) 2015-2019, Wazuh Inc.All rights reserved.
# Wazuh.com
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

## Examples of use
# ./restore_alerts.sh
# ./restore_alerts.sh 2017-03-06 2017-03-06 192.168.1.11 local
# ./restore_alerts.sh 2017-03-06 2017-03-06 192.168.1.11 remote root 192.168.1.50

ELS2ELS="""
input {
  # Read all documents from Elasticsearch matching the given query
  elasticsearch {
    hosts => \"ELASTICSEARCH_IP\"
    index => \"wazuh-alerts-DATE\"
    size => \"10000\"
    scroll => \"1m\"
  }
}

"""

WM2ELS="""
input {
  stdin {
    codec => \"json\"
  }
}

"""

## Variables
declare -A MONTHS
MONTHS[01]=Jan
MONTHS[02]=Feb
MONTHS[03]=Mar
MONTHS[04]=Apr
MONTHS[05]=May
MONTHS[06]=Jun
MONTHS[07]=Jul
MONTHS[08]=Aug
MONTHS[09]=Sep
MONTHS[10]=Oct
MONTHS[11]=Nov
MONTHS[12]=Dec

# Aux functions
print() {
    echo -e $1
}
error_and_exit() {
    echo "Error executing command: '$1'."
    echo 'Exiting.'
    exit 1
}
exec_cmd_bash() {
    bash -c "$1" || error_and_exit "$1"
}

install_logstash () {
    # Check package manager
    YUM_CMD=$(which yum)
    APT_GET_CMD=$(which apt-get)

    # Add Elastic Stack repository
    if [[ ! -z $YUM_CMD ]]; then
        # Import the ElasticsearchPGP Key
        rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
        
        echo -e "[elasticsearch-6.x]\nname=Elasticsearch repository for 6.x packages\nbaseurl=https://artifacts.elastic.co/packages/6.x/yum\ngpgcheck=1\ngpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch\nenabled=1\nautorefresh=1\ntype=rpm-md" | \
        tee -a /etc/yum.repos.d/elasticsearch.repo

        yum install logstash-$LOGSTASH_VERSION -y

    elif [[ ! -z $APT_GET_CMD ]]; then
        # Import the Elasticsearch PGP Key
        wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
        apt-get install apt-transport-https
        echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-6.x.list
        apt-get update

        apt-get install logstash=$LOGSTASH_VERSION -y
    fi
}

# END Aux functions
previous_checks() {
    # Test root permissions
    if [ "$EUID" -ne 0 ]; then
        print "Please run this script with root permissions.\nExiting."
        exit 1
    fi

    ps aux | grep logstash | grep java > /dev/null 2>&1

    if [[ $? == 0 ]]; then
        print "An instance of Logstash is running. Please stop it before running this script."
        print "Exiting."
        exit 1
    fi

    # Paths
    LOGSTASH_CONF="restore_alerts.conf"
    OSSEC_DIRECTORY="/var/ossec"
    LOGSTASH_BIN="/usr/share/logstash/bin/logstash"
    ALERTS_PATH="${OSSEC_DIRECTORY}/logs/alerts"
    
    if ! [ -f $LOGSTASH_CONF ]; then
        print "Can't find Logstash ($LOGSTASH_CONF) configuration. \nExiting."
        exit 1
    fi
    
    if ! [ -f $LOGSTASH_BIN ]; then
        print "----------------------------------------------------"
        print "  Can't find $LOGSTASH_BIN. Installing Logstash..."
        print "----------------------------------------------------"
        
        print ""
        print "In order to avoid problems with Elasticsearch and"
        print "Logstash, both of them must have the same version."

        read -p "Which version of Elasticsearch are you using? (>= 6.0.0) " LOGSTASH_VERSION

        if [[ ! $LOGSTASH_VERSION =~ "6" ]]; then
            print "Not a valid version."
            exit -1
        else
            install_logstash
        fi

    fi
}

wizard () {

    print ""
    echo "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
    echo "%                                                                  %"
    echo "%------------------------------ NOTE ------------------------------%"
    echo "%                                                                  %"
    echo "% The process of restoring yor alerts from Wazuh 2.x to Wazuh 3.x  %"
    echo "%   may take some time, depending on the amount of alerts stored   %"
    echo "%              in Elasticsearch or your manager.                   %"
    echo "%                                                                  %"
    echo "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"

    print ""

    print "This tool can restore your alerts in two different ways: "
    print "\t1) Restore your alerts stored in Elasticsearch."
    print "\t2) Restore your alerts stored in your wazuh-manager."

    read -p "Which option do you need? (1/2): " reindex_type
    if [ "X${reindex_type,,}" == "X" ] || [ "X${reindex_type,,}" == "X1" ]; then
        reindex_type="ELS2ELS"
        print "\nPerforming a reindex from Elasticsearch to Elasticsearch."
    else
        reindex_type="WM2ELS"
        print "\nPerforming a reindex from wazuh-manager to Elasticsearch."
    fi

    # Elastic IP
    read -p "Elasticsearch IP [localhost]: " elastic_ip
    elastic_ip=${elastic_ip:-localhost}
    print "Using Elasticsearch IP: $elastic_ip"
    print ""

    # Date from - restore the alerts
    read -p "Date from (yyyy-mm-dd): " dateFrom
    print "Date from: $dateFrom"

    # Date to - restore alerts
    read -p "Date to (yyyy-mm-dd): " dateTo
    print "Date to: $dateTo"
}

setup_conf () {
    if [[ "$reindex_type" == "ELS2ELS" ]]; then
        echo -e "$ELS2ELS $(tail -n 47 $LOGSTASH_CONF)" > $LOGSTASH_CONF
    else
        echo -e "$WM2ELS $(tail -n 47 $LOGSTASH_CONF)" > $LOGSTASH_CONF
    fi
}

end_and_exit () {
    
    rm /tmp/$LOGSTASH_CONF

    print "\n### [Restoration ended] ###"
    print "\nNow, you can uninstall Logstash if you don't need it anymore."
    exit 0
}

edit_conf () {
    cp $LOGSTASH_CONF /tmp
    dateFromAuxPoint=$(echo -e $dateFromAux | sed "s/\-/\./g")
    sed -i "s/DATE/$dateFromAuxPoint/g" /tmp/$LOGSTASH_CONF
    sed -i "s/ELASTICSEARCH_IP/$elastic_ip/g" /tmp/$LOGSTASH_CONF
}

ELS2ELS_restore () {

    setup_conf

    dateFromAux=$dateFrom

    echo "##### Starting, reindexing alerts from $dateFrom to $dateTo"
    while : ; do

        edit_conf

        exec_cmd_bash "/usr/share/logstash/bin/logstash -f /tmp/$LOGSTASH_CONF --path.settings=/etc/logstash"

        [ "$dateFromAux" != $dateTo ] || break
        dateFromAux=$(date -I -d "$dateFromAux + 1 day")
    done

    end_and_exit
}

WM2ELS_restore () {
    ## Date to array
    setup_conf
    echo "##### Starting, reindexing alerts from $dateFrom to $dateTo"
    
    dateFromAux=$dateFrom
    
    while : ; do
        edit_conf
        IFS='-' read -r -a current_date <<< "$dateFromAux"
        file=ossec-alerts-${current_date[2]}.json.gz
        file_path="$ALERTS_PATH/${current_date[0]}/${MONTHS[${current_date[1]}]}/$file"
        echo "###### Procesing: $file_path"

        exec_cmd_bash "zcat $file_path | /usr/share/logstash/bin/logstash -f /tmp/$LOGSTASH_CONF --path.settings=/etc/logstash"

        [ "$dateFromAux" != $dateTo ] || break
        dateFromAux=$(date -I -d "$dateFromAux + 1 day")
    done

    end_and_exit
}

main () {
    if [[ "$reindex_type" == "ELS2ELS" ]]; then
        ELS2ELS_restore
    else
        WM2ELS_restore
    fi
}

if [ $# -ne 0 ] && [ $# -ne 4 ] && [ $# -ne 6 ]
  then
    echo "Usage arguments: restore_alerts.sh date_from(yyyy-mm-dd) date_to(yyyy-mm-dd) elasticsearch_ip ELS2ELS|WM2ELS"
    exit
fi

print ""
print "### Wazuh - Alerts restoration ###"

if [ $# -eq 0 ]; then
    previous_checks
    wizard
    main
else
    dateFrom=$1
    dateTo=$2
    elastic_ip=$3
    reindex_type=$4
    previous_checks
    main
fi