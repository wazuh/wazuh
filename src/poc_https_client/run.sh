#!/usr/bin/env bash
# SPIKE #37738 PoC runner. Generates a self-signed cert + a client key, starts
# the mock manager, builds the C client, and runs the scenarios. Self-contained;
# nothing here touches the agent build or any daemon.
set -euo pipefail
cd "$(dirname "$0")"

PORT=27840
WORK=".poc_run"
mkdir -p "$WORK"

echo "== generating a self-signed manager cert (CN=127.0.0.1) =="
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$WORK/server.key" -out "$WORK/server.crt" -days 2 \
  -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1

echo "== creating a pre-shared agent key (client.keys-style) =="
# 16-byte AES-128 key as 32 hex chars (stands in for the client.keys secret)
KEY_HEX="$(openssl rand -hex 16)"
echo "001 $KEY_HEX" > "$WORK/agent.keys"

echo "== building the C client (libcurl + libcrypto) =="
make -s clean >/dev/null 2>&1 || true
make -s

start_mock() {
  local extra="${1:-}"
  python3 mock_manager/mock_manager.py --port "$PORT" \
    --cert "$WORK/server.crt" --key "$WORK/server.key" \
    --keys "$WORK/agent.keys" $extra &
  MOCK_PID=$!
  # wait for the port
  for _ in $(seq 1 50); do
    if (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null; then exec 3>&- ; break; fi
    sleep 0.1
  done
}
stop_mock() { kill "${MOCK_PID:-0}" 2>/dev/null || true; wait "${MOCK_PID:-0}" 2>/dev/null || true; }
trap stop_mock EXIT

BASE="https://127.0.0.1:$PORT"

echo
echo "########################################################################"
echo "# SCENARIO 1 — happy path (startup, stateless, stateful+dedup, notify) #"
echo "########################################################################"
start_mock ""
./hc_poc "$BASE" 001 "$KEY_HEX" "$WORK/server.crt" happy || true
stop_mock

echo
echo "########################################################################"
echo "# SCENARIO 2 — tampered auth (wrong key) must be refused with 401      #"
echo "########################################################################"
start_mock ""
./hc_poc "$BASE" 001 "$KEY_HEX" "$WORK/server.crt" tamper || true
stop_mock

echo
echo "########################################################################"
echo "# SCENARIO 3 — back-pressure (first /stateless -> 503 + Retry-After)   #"
echo "########################################################################"
start_mock "--backpressure"
./hc_poc "$BASE" 001 "$KEY_HEX" "$WORK/server.crt" happy || true
stop_mock

echo
echo "########################################################################"
echo "# SCENARIO 4 — large /stateful (3 MB) streamed from a spooled file     #"
echo "########################################################################"
start_mock ""
./hc_poc "$BASE" 001 "$KEY_HEX" "$WORK/server.crt" big || true
stop_mock

echo
echo "########################################################################"
echo "# SCENARIO 5 — multi-threaded: one thread per endpoint (D5 model).     #"
echo "#   A deliberately SLOW /stateful (manager holds it 4s) must NOT block  #"
echo "#   /stateless or /control. Watch the [+ms] timestamps interleave.      #"
echo "########################################################################"
start_mock "--slow-stateful 4"
./hc_poc_mt "$BASE" 001 "$KEY_HEX" "$WORK/server.crt" 8 || true
stop_mock

echo
echo "== all scenarios done =="
