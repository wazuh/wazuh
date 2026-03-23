#!/usr/bin/env bash
# Script to enable, disable, or check the status of the Wazuh archiver via the local analysisd socket.
#
# Usage:
#   ./toggle_archive.sh {enable|disable|status}
#
# Requirements:
#   - Must be run with sufficient permissions to access $ANALYSISD_SOCKET (usually as root or wazuh user).
#   - Requires 'curl' installed with support for --unix-socket.
#
# Example:
#   sudo ./toggle_archive.sh enable

ANALYSISD_SOCKET="/var/wazuh-manager/queue/sockets/analysis"
ENDPOINT_ACTIVATE="http://localhost/archiver/activate"
ENDPOINT_STATUS="http://localhost/archiver/status"
ENDPOINT_DISABLE="http://localhost/archiver/deactivate"


if [ "$#" -ne 1 ]; then
    echo "Usage: $0 {enable|disable|status}"
    exit 1
fi


case $1 in
    enable)
        echo "Enabling archiver..."
        curl --unix-socket "$ANALYSISD_SOCKET" -X POST -H "Content-Type: application/json" -d '{}' "$ENDPOINT_ACTIVATE"
        ;;
    disable)
        echo "Disabling archiver..."
        curl --unix-socket "$ANALYSISD_SOCKET" -X POST -H "Content-Type: application/json" -d '{}' "$ENDPOINT_DISABLE"
        ;;
    status)
        echo "Getting archiver status..."
        curl --unix-socket "$ANALYSISD_SOCKET" -X POST -H "Content-Type: application/json" -d '{}' "$ENDPOINT_STATUS"
        ;;
    *)
        echo "Invalid option. Usage: $0 {enable|disable|status}"
        exit 1
        ;;
esac
