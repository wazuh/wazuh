#!/bin/bash


# ------------------------ Tests configuration section ------------------------

# Useful variables
STATS_MONITOR_POLL_TIME_SECS=0.1

# Benchmark configuration
: "${BT_TIME:=10}"
BT_RATE=0
BT_INPUT=./utils/test_logs.txt
BT_OUTPUT=/var/ossec/logs/alerts/alerts-ECS.json

# Engine Configurations
: "${ORCHESTRATOR_THREADS:=1}"

# ---------------------------- Engine test section ----------------------------

TEST_NAME="engine-bench-${ORCHESTRATOR_THREADS}-threads-${RANDOM}"

# check engine is running
if pgrep -x "wazuh-engine" > /dev/null; then
    echo "Wazuh-engine will be restarted."
    pkill -f /var/ossec/bin/wazuh-engine
    sleep 1
fi

WAZUH_ORCHESTRATOR_THREADS="${ORCHESTRATOR_THREADS}" /var/ossec/bin/wazuh-engine &

sleep 5

python3 ./utils/monitor.py -s $STATS_MONITOR_POLL_TIME_SECS -b wazuh-engine -n $TEST_NAME &

MONITOR_PID=$!

go run ./utils/benchmark_tool.go -o $BT_OUTPUT -t $BT_TIME  -r $BT_RATE -i $BT_INPUT -T  | tee "engine-bench-${WAZUH_ORCHESTRATOR_THREADS}-threads-${RANDOM}.log"

kill -INT $MONITOR_PID

ENGINE_FILE="monitor-${TEST_NAME}.csv"
echo "Output file: ${ENGINE_FILE}"

# ---------------------------- Test output section ----------------------------

sleep 1

python3 ./utils/process_stats.py -e "${ENGINE_FILE}"
