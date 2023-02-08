#!/bin/bash

WAZUH_DIR=/var/ossec
ENGINE_DIR=$WAZUH_DIR/engine

OUTPUT_FILE_PATH=/tmp/engine.log

# wazuh-engine configuration parameters
export WZE_LOG_LEVEL=0
export WZE_KVDB_PATH=$WAZUH_DIR/etc/kvdb/
export WZE_STORE_PATH=$ENGINE_DIR/store/
export WZE_EVENT_SOCK=$WAZUH_DIR/queue/sockets/queue
export WZE_API_SOCK=$WAZUH_DIR/queue/sockets/engine-api
export WZE_FLOOD_FILE=/tmp/engine-flood.log

# Create flood file if it does not exist
if [ ! -e "$WZE_FLOOD_FILE" ] ; then
    touch "$WZE_FLOOD_FILE"
fi

# TODO: improve the config testing section
if [ "$1" = "-t" ]; then
    exit 0
fi

# Configure code dump
ulimit -S -c unlimited
sysctl -w kernel.core_pattern=/coredumps/core-%e-%E-%t-%s-%p

# Start Engine daemon
nohup $ENGINE_DIR/wazuh-engine server start >> $OUTPUT_FILE_PATH 2>&1 &

# Control file for wazuh-control, this file contains the wazuh-engine pid
echo $! > $WAZUH_DIR/var/run/wazuh-engine-$!.pid

sleep 1 # Sleep to give time for the queues to be created

# Queues ownership setup
chown wazuh:wazuh $WZE_EVENT_SOCK
chown wazuh:wazuh $WZE_API_SOCK

echo "" >> /tmp/engine.log
