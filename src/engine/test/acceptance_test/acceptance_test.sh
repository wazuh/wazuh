#!/bin/bash

# Copyright (C) 2015-2022, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Save the working directory and change to the directory where the script is
OLD_PWD=`pwd`
SCRIPT_DIR=$(dirname $(readlink -f $0))
cd $SCRIPT_DIR

# ------------------------ Tests configuration section ------------------------

DO_TEST_ANALYSISD=false
DO_TEST_ENGINE=true

# Useful variables
STATS_MONITOR_POLL_TIME_SECS=0.1

# Benchmark configuration
BT_TIME=60
BT_RATE=0
BT_INPUT=./utils/zz_test.log
BT_OUTPUT=/tmp/filepath.txt

# Engine Configurations
ENGINE_BUILD_ABSOLUTE_PATH=$(realpath ../../build)
ENGINE_N_THREADS=16

# Constants for the test
CONFIG_SRC_DIR=./analysisd/config
CONFIG_DST_DIR=/var/ossec/etc
CONFIG_BACKUP_DIR=/var/ossec/backup/etc
LOGS_DIR=/var/ossec/logs
LOGS_BACKUP_DIR=/var/ossec/backup/logs
RULES_SRC_DIR=./analysisd/ruleset/rules
DECODERS_SRC_DIR=./analysisd/ruleset/decoders
RULES_DST_DIR=/var/ossec/etc/test/rules
DECODERS_DST_DIR=/var/ossec/etc/test/decoders

# ---------------------------- Tests set-up section ----------------------------

if ! $DO_TEST_ANALYSISD;
then
    if ! $DO_TEST_ENGINE;
    then
        echo "No test selected"
        exit 0
    fi
fi


# --------------------------- Analysisd test section ---------------------------

if $DO_TEST_ANALYSISD;
then
    echo "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX  9"

    TEST_NAME="analysisd-test-${RANDOM}"

    # Stop Wazuh manager

    systemctl stop wazuh-manager.service

    # Backup Wazuh files

    mkdir -p $CONFIG_BACKUP_DIR
    # mkdir -p $LOGS_BACKUP_DIR
    mv $CONFIG_DST_DIR/ossec.conf $CONFIG_BACKUP_DIR
    mv $CONFIG_DST_DIR/local_internal_options.conf $CONFIG_BACKUP_DIR
    # cp -rp $LOGS_DIR/* $LOGS_BACKUP_DIR

    # Copy test files

    cp $CONFIG_SRC_DIR/* $CONFIG_DST_DIR
    chgrp wazuh $CONFIG_DST_DIR/ossec.conf
    chgrp wazuh $CONFIG_DST_DIR/local_internal_options.conf

    mkdir -p $RULES_DST_DIR
    mkdir -p $DECODERS_DST_DIR
    cp $RULES_SRC_DIR/* $RULES_DST_DIR
    cp $DECODERS_SRC_DIR/* $DECODERS_DST_DIR
    chown -R root:wazuh $RULES_DST_DIR
    chown -R root:wazuh $DECODERS_DST_DIR

    # Start Wazuh

    systemctl start wazuh-manager.service

    # Sleep to wait for wazuh-analysisd to start up
    sleep 5

    # Run stats collector script

    python3 ./utils/monitor.py -s $STATS_MONITOR_POLL_TIME_SECS -b wazuh-analysisd -n $TEST_NAME &

    MONITOR_PID=$!

    # Test script

    # Run the benchmark
    # -t <Estimated benchmark duration>
    # -r <Events per seconds. Use 0 for maximum rate allowed>
    # -i <Source of logs>
    # -T Truncate the alerts.json file to calculate the processed events after benchark

    go run ./utils/benchmark_tool.go -t $BT_TIME -r $BT_RATE -i $BT_INPUT -T

    # Stop stats collector script

    kill -INT $MONITOR_PID

    # Stop Wazuh manager

    systemctl stop wazuh-manager.service

    # Restore Wazuh files

    mv $CONFIG_BACKUP_DIR/* $CONFIG_DST_DIR

    # Remove test ruleset

    rm -rf $RULES_DST_DIR
    rm -rf $DECODER_DST_DIR

    ANALYSISD_FILE="monitor-${TEST_NAME}.csv"
    echo "Output file: ${ANALYSISD_FILE}"
fi

# ---------------------------- Engine test section ----------------------------

if $DO_TEST_ENGINE;
then

    TEST_NAME="engine-bench-${ENGINE_N_THREADS}-threads-${RANDOM}"

    cd $ENGINE_BUILD_ABSOLUTE_PATH

    # Clear the alert file
    echo -n > $BT_OUTPUT
    ./main start --event_endpoint /var/ossec/queue/sockets/queue      \
                --api_endpoint /var/ossec/queue/sockets/engine-api    \
                --threads ${ENGINE_N_THREADS}                         \
                --file_storage ../ruleset/store                       \
                --kvdb_path /var/ossec/etc/kvdb/                      \
                --environment environment/wazuh/0 &

    ENGINE_PID=$!

    sleep 2

    cd $SCRIPT_DIR

    python3 ./utils/monitor.py -s $STATS_MONITOR_POLL_TIME_SECS -b main -n $TEST_NAME &

    MONITOR_PID=$!

    go run ./utils/benchmark_tool.go -o /tmp/filepath.txt -t $BT_TIME  -r $BT_RATE -i $BT_INPUT -f  | tee "engine-bench-${ENGINE_N_THREADS}-threads-${RANDOM}.log"

    kill -INT $MONITOR_PID
    kill -INT $ENGINE_PID

    ENGINE_FILE="monitor-${TEST_NAME}.csv"
    echo "Output file: ${ENGINE_FILE}"
fi

# ---------------------------- Test output section ----------------------------

sleep 1

args=""
if $DO_TEST_ANALYSISD;
then
    if $DO_TEST_ENGINE;
    then
        args="-a ${ANALYSISD_FILE} -e ${ENGINE_FILE}"
    else
        args="-a ${ANALYSISD_FILE}"
    fi
elif $DO_TEST_ENGINE;
then
    args="-e ${ENGINE_FILE}"
fi

python3 ./utils/process_stats.py $args

cd "${OLD_PWD}"
