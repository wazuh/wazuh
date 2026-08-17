#!/usr/bin/env bash
# Wazuh agent HTTPS client — demo container entrypoint.
# Copyright (C) 2015, Wazuh Inc.
#
# Runs inside the demo image: generate a self-signed cert + shared key, start
# the python TLS mock, then run the demo driver (the real libhttps_client) at it.
set -euo pipefail

PORT=27860
KEY_HEX="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
WORK="/tmp/run"
mkdir -p "$WORK"

echo "== generating a self-signed manager cert (CN=127.0.0.1) =="
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$WORK/server.key" -out "$WORK/server.crt" -days 2 \
  -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1

echo "== starting the mock manager =="
python3 /demo/mock_manager.py --port "$PORT" \
  --cert "$WORK/server.crt" --key "$WORK/server.key" --key-hex "$KEY_HEX" &
MOCK_PID=$!
trap 'kill "$MOCK_PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
  if (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null; then exec 3>&-; break; fi
  sleep 0.1
done

echo
echo "########################################################################"
echo "# The real https_client module talking to the mock over HTTPS.         #"
echo "#   [client:N] = module log    >> = callbacks    [mock] = manager       #"
echo "########################################################################"
echo
# Run the driver in the background and relay INT/TERM to it (bash as PID 1
# does not forward signals to a foreground child), so Ctrl-C / docker stop
# reach the driver's handler and end sustained mode with the clean drain.
LD_LIBRARY_PATH=/demo /demo/demo_driver 127.0.0.1 "$PORT" "$KEY_HEX" /tmp/hc_demo_sync.sock &
DRIVER_PID=$!
trap 'kill -TERM "$DRIVER_PID" 2>/dev/null || true' INT TERM
rc=0
wait "$DRIVER_PID" || rc=$?
echo
echo "== demo done =="
exit "$rc" # Surface driver failures instead of always reporting success.
