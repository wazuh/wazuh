#!/usr/bin/env bash
# Wazuh agent HTTPS client — demo runner.
# Copyright (C) 2015, Wazuh Inc.
#
# Watches the REAL https_client module talk to a local mock manager over HTTPS:
# generates a self-signed cert + a shared AES key, starts the Python mock,
# compiles the demo driver against the already-built libhttps_client, runs it,
# and tears everything down. Requires the module to be built first:
#
#   cd src && make TARGET=agent  (or the cmake+make flow used in development)
#
#   DEMO_SECONDS=60 ./run.sh   keeps the client running for ~60 s after the
#                              scripted walkthrough (Ctrl-C stops it cleanly).
#
# Needs: cc, python3, the openssl CLI.
set -euo pipefail
cd "$(dirname "$0")"

PORT=27860
KEY_HEX="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" # 32-byte AES-256 key (a real client.keys length)
WORK=".demo_run"
SRC_ROOT="$(cd ../../.. && pwd)"              # .../src
BUILD_LIB="${SRC_ROOT}/build/lib"

if [ ! -f "${BUILD_LIB}/libhttps_client.dylib" ] && [ ! -f "${BUILD_LIB}/libhttps_client.so" ]; then
  echo "error: libhttps_client not found in ${BUILD_LIB} — build the agent target first." >&2
  exit 1
fi

mkdir -p "$WORK"

echo "== generating a self-signed manager cert (CN=127.0.0.1) =="
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$WORK/server.key" -out "$WORK/server.crt" -days 2 \
  -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1

echo "== compiling the demo driver against libhttps_client =="
cc -std=c11 -Wall demo_driver.c \
  -I ../include \
  -I "${SRC_ROOT}/shared_modules/common" \
  -I "${SRC_ROOT}/external/cJSON" \
  -L "${BUILD_LIB}" -lhttps_client \
  -Wl,-rpath,"${BUILD_LIB}" \
  -o "$WORK/demo_driver"

start_mock() {
  python3 mock_manager.py --port "$PORT" \
    --cert "$WORK/server.crt" --key "$WORK/server.key" --key-hex "$KEY_HEX" &
  MOCK_PID=$!
  for _ in $(seq 1 50); do
    if (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null; then exec 3>&-; break; fi
    sleep 0.1
  done
}
stop_mock() { kill "${MOCK_PID:-0}" 2>/dev/null || true; wait "${MOCK_PID:-0}" 2>/dev/null || true; }
trap stop_mock EXIT

echo "== starting the mock manager =="
start_mock

echo
echo "########################################################################"
echo "# The real https_client module talking to the mock over HTTPS.         #"
echo "#   [client:N] = module log    >> = callbacks    [mock] = manager       #"
echo "########################################################################"
echo
SYNC_SOCK="/tmp/hc_demo_sync_$$.sock"
rc=0
DYLD_LIBRARY_PATH="${BUILD_LIB}" "$WORK/demo_driver" 127.0.0.1 "$PORT" "$KEY_HEX" "$SYNC_SOCK" || rc=$?
rm -f "$SYNC_SOCK"

echo
echo "== demo done (artifacts in $WORK/, nothing installed) =="
exit "$rc" # Surface driver failures instead of always reporting success.
