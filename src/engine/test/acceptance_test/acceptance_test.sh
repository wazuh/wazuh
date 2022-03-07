# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# ------------------------ Tests configuration section ------------------------

# Useful variables

STATS_MONITOR_POLL_TIME_SECS=0.1

# Benchmark configuration
BT_TIME=360
BT_RATE=0
BT_INPUT=./utils/test_logs.txt

ENGINE_BUILD_ABSOLUTE_PATH=/root/repos/wazuh/src/engine/build
ENGINE_LISTEN_PORT=6000
ENGINE_N_THREADS=8

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

# Save the working directory and change to the directory where the script is
OLD_PWD=`pwd`
cd $(dirname $(readlink -f $0))
# echo "change working directory to... `pwd`"

# --------------------------- Analysisd test section ---------------------------

TEST_NAME=analysisd-test

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

python3 ./utils/monitor.py -s $STATS_MONITOR_POLL_TIME_SECS -b wazuh-analysisd -n $TEST_NAME&

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
# cp -rp $LOGS_BACKUP_DIR/* $LOGS_DIR

# Remove test ruleset

rm -rf $RULES_DST_DIR
rm -rf $DECODER_DST_DIR

# ---------------------------- Engine test section ----------------------------

TEST_NAME=engine-test

cd $ENGINE_BUILD_ABSOLUTE_PATH

GLOG_logtostderr=1 ./main --file_storage ../test/assets/ --endpoint tcp:localhost:$ENGINE_LISTEN_PORT --threads $ENGINE_N_THREADS&

ENGINE_PID=$!

sleep 1

python3 ./utils/monitor.py -s $STATS_MONITOR_POLL_TIME_SECS -b main -n $TEST_NAME&

MONITOR_PID=$!

go run ./utils/benchmark_tool.go -t $BT_TIME -r $BT_RATE -i $BT_INPUT -T -p tcp -s localhost:$ENGINE_LISTEN_PORT

kill -INT $MONITOR_PID
kill -INT $ENGINE_PID

# ---------------------------- Test output section ----------------------------

sleep 1

python3 ./utils/process_stats.py

cd "${OLD_PWD}"
