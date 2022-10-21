#!/bin/bash

WAZUH_DIR=/var/ossec
ENGINE_DIR=$WAZUH_DIR/engine

OUTPUT_FILE_PATH=/tmp/engine.log

# wazuh-engine configuration parameters
LOG_LEVEL=0
KVDB_PATH=$WAZUH_DIR/etc/kvdb/
STORE_PATH=$ENGINE_DIR/store/
EVENTS_QUEUE_PATH=$WAZUH_DIR/queue/sockets/queue
API_QUEUE_PATH=$WAZUH_DIR/queue/sockets/engine-api

# TODO: improve the config testing section
if [ "$1" = "-t" ]; then
    exit 0
fi

# Start Engine daemon
nohup $ENGINE_DIR/wazuh-engine start -e $EVENTS_QUEUE_PATH -a $API_QUEUE_PATH -f $STORE_PATH -k $KVDB_PATH -l $LOG_LEVEL >> $OUTPUT_FILE_PATH 2>&1 &

# Control file for wazuh-control, this file contains the wazuh-engine pid
echo $! > $WAZUH_DIR/var/run/wazuh-engine-$!.pid

sleep 1 # Sleep to give time for the queues to be created

# Queues ownership setup
chown wazuh:wazuh $EVENTS_QUEUE_PATH
chown wazuh:wazuh $API_QUEUE_PATH

echo "" >> /tmp/engine.log
