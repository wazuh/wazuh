#!/usr/bin/env bash
# Script to enable, disable, or check the status of the Wazuh event-dumper via the local analysisd socket.
#
# Usage:
#   ./toggle_event_dumper.sh {enable|disable|status}
#
# Requirements:
#   - Must be run with sufficient permissions to access $ANALYSISD_SOCKET (usually as root or wazuh user).
#   - Requires 'curl' installed with support for --unix-socket.
#
# Example:
#   sudo ./toggle_event_dumper.sh enable

ANALYSISD_SOCKET="/var/wazuh-manager/queue/sockets/analysis"
ENDPOINT_ACTIVATE="http://localhost/_internal/event-dumper/activate"
ENDPOINT_STATUS="http://localhost/_internal/event-dumper/status"
ENDPOINT_DISABLE="http://localhost/_internal/event-dumper/deactivate"


if [ "$#" -ne 1 ]; then
    echo "Usage: $0 {enable|disable|status}"
    exit 1
fi


case $1 in
    enable)
        echo "Enabling event-dumper..."
        curl --unix-socket "$ANALYSISD_SOCKET" -X POST -H "Content-Type: application/json" -d '{}' "$ENDPOINT_ACTIVATE"
        ;;
    disable)
        echo "Disabling event-dumper..."
        curl --unix-socket "$ANALYSISD_SOCKET" -X POST -H "Content-Type: application/json" -d '{}' "$ENDPOINT_DISABLE"
        ;;
    status)
        echo "Getting event-dumper status..."
        curl --unix-socket "$ANALYSISD_SOCKET" -X POST -H "Content-Type: application/json" -d '{}' "$ENDPOINT_STATUS"
        ;;
    *)
        echo "Invalid option. Usage: $0 {enable|disable|status}"
        exit 1
        ;;
esac
