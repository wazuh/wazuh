#!/bin/bash


# Save the working directory and change to the directory where the script is
SCRIPT_DIR=$(dirname $(readlink -f $0))
cd $SCRIPT_DIR

# ------------------------ Tests configuration section ------------------------

# Useful variables
STATS_MONITOR_POLL_TIME_SECS=0.1

# Benchmark configuration
BT_TIME=30
BT_RATE=0
BT_INPUT=./utils/test_logs.txt
BT_OUTPUT=/var/ossec/logs/alerts/alerts-ECS.json

# Engine Configurations
ENGINE_BUILD_ABSOLUTE_PATH=$(realpath ../../build)
ENGINE_N_THREADS=1

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

echo -n -e > "${BT_OUTPUT}"

# ---------------------------- Engine test section ----------------------------

TEST_NAME="engine-bench-${ENGINE_N_THREADS}-threads-${RANDOM}"

cd $ENGINE_BUILD_ABSOLUTE_PATH

# Clear the alert file
#TODO:  Check vs "-T" on benchmark
echo -n > $BT_OUTPUT

# check engine is running
if ! pgrep -x "wazuh-engine" > /dev/null; then
    echo "Error, wazuh-engine is not running."
    exit 1
fi

sleep 5

cd $SCRIPT_DIR

python3 ./utils/monitor.py -s $STATS_MONITOR_POLL_TIME_SECS -b wazuh-engine -n $TEST_NAME &

MONITOR_PID=$!

go run ./utils/benchmark_tool.go -o $BT_OUTPUT -t $BT_TIME  -r $BT_RATE -i $BT_INPUT -f  | tee "engine-bench-${ENGINE_N_THREADS}-threads-${RANDOM}.log"

kill -INT $MONITOR_PID

ENGINE_FILE="monitor-${TEST_NAME}.csv"
echo "Output file: ${ENGINE_FILE}"

# ---------------------------- Test output section ----------------------------

sleep 1

python3 ./utils/process_stats.py -e "${ENGINE_FILE}"
