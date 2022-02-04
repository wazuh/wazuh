# ----------------------------- Analysisd section -----------------------------

# Useful variables

TEST_NAME=test

STATS_MONITOR_POLL_TIME_SECS=0.1

CONFIG_SRC_DIR=./analysisd/config
CONFIG_DST_DIR=/var/ossec/etc
CONFIG_BACKUP_DIR=/var/ossec/backup/etc
LOGS_DIR=/var/ossec/logs
LOGS_BACKUP_DIR=/var/ossec/backup/logs
RULES_SRC_DIR=./analysisd/ruleset/rules
DECODERS_SRC_DIR=./analysisd/ruleset/decoders
RULES_DST_DIR=/var/ossec/etc/test/rules
DECODERS_DST_DIR=/var/ossec/etc/test/decoders

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

go run ./utils/benchmark_analysisd.go -t 5 -r 50000 -f ./utils/test_logs.txt

# Stop stats collector script

kill -INT $MONITOR_PID

sleep 1

python3 ./utils/process_stats.py

# Stop Wazuh manager

systemctl stop wazuh-manager.service

# Restore Wazuh files

mv $CONFIG_BACKUP_DIR/* $CONFIG_DST_DIR
# cp -rp $LOGS_BACKUP_DIR/* $LOGS_DIR

# Remove test ruleset

rm -rf $RULES_DST_DIR
rm -rf $DECODER_DST_DIR
