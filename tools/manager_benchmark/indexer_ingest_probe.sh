#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# indexer_ingest_probe.sh — Sample what the indexer holds, from the indexer's side.
#
# The sender's latency for POST /stateless does not see the write that follows it, so an A/B of
# the manager's indexer sender needs a measure taken at the indexer: once per interval, for each
# index pattern, `GET <pattern>/_count` (documents: the MAIN metric, one number whatever the
# operations behind it) and `GET <pattern>/_stats/indexing` (index_total: operations, kept as a
# diagnostic -- the two builds can issue a different number of them per document).
#
# Output, one CSV row per pattern per sample:
#     epoch,pattern,count,index_total
# A request that fails leaves `count` and `index_total` EMPTY (never 0: a hole is not a drain).
# ab_report.py turns the series into docs/s during a drain and the time to drain.
#
# The two sides of an A/B must be probed with the SAME patterns, raw included in both or in
# neither.
#
# Usage:
#   indexer_ingest_probe.sh --out FILE [--patterns "wazuh-events*,wazuh-states-*"]
#                           [--interval 1] [--max-seconds N]    # sample until killed (or N)
#   indexer_ingest_probe.sh --once [--patterns ...]               # print the summed count and exit
#   indexer_ingest_probe.sh --dry-run ...                         # print the plan, touch nothing
#   indexer_ingest_probe.sh --print-url                           # print the indexer URL it would use
#
# Environment: INDEXER_URL (default: the first <host> of <indexer><hosts> in WAZUH_MANAGER_CONF,
#   /etc/wazuh-manager/wazuh-manager.conf, the address the manager itself writes to; without one,
#   https://127.0.0.1:9200 -- never `localhost`: the e2e node's certificate names IP:127.0.0.1 and
#   DNS:wazuh-indexer only, so a verified request to localhost fails). The credentials and the TLS
#   trust come from indexer_credentials.sh: INDEXER_USER + INDEXER_PASSWORD (or INDEXER_PASS), else
#   WAZUH_INDEXER_ADMIN_PASSWORD parsed from INDEXER_CREDENTIALS_FILE / the e2e .credentials.env /
#   /etc/wazuh-indexer/export/credentials.env -- NO default: without one the probe exits 1;
#   INDEXER_CACERT, else the manager config's indexer CA, else /etc/wazuh-manager/certs/indexer-ca.pem
#   (`-k` only with INDEXER_INSECURE=1).
# ---------------------------------------------------------------------------
set -uo pipefail

PYTHON="${PYTHON:-python3}"
DEFAULT_INDEXER_URL="https://127.0.0.1:9200"
# shellcheck source=indexer_credentials.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/indexer_credentials.sh"

if [[ -z "${INDEXER_URL:-}" ]]; then
    INDEXER_URL="$(indexer_conf_url)"
    INDEXER_URL="${INDEXER_URL:-$DEFAULT_INDEXER_URL}"
fi
INDEXER_URL="${INDEXER_URL%/}"
PATTERNS="wazuh-events*,wazuh-states-*"
OUT=""
INTERVAL=1
MAX_SECONDS=0
ONCE=false
DRY_RUN=false

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out)         OUT="$2"; shift 2 ;;
        --patterns)    PATTERNS="$2"; shift 2 ;;
        --interval)    INTERVAL="$2"; shift 2 ;;
        --max-seconds) MAX_SECONDS="$2"; shift 2 ;;
        --once)        ONCE=true; shift ;;
        --dry-run)     DRY_RUN=true; shift ;;
        --print-url)   echo "$INDEXER_URL"; exit 0 ;;
        -h|--help)     usage; exit 0 ;;
        *) echo "indexer_ingest_probe: unknown option $1" >&2; exit 1 ;;
    esac
done

if ! $ONCE && [[ -z "$OUT" ]]; then
    echo "indexer_ingest_probe: --out is required (or --once)" >&2
    exit 1
fi

IFS=',' read -r -a PATTERN_LIST <<<"$PATTERNS"

if $DRY_RUN; then
    echo "[dry-run] indexer_ingest_probe: $INDEXER_URL, patterns: ${PATTERN_LIST[*]}"
    if $ONCE; then
        echo "[dry-run]   one sample: print the summed _count and exit"
    else
        echo "[dry-run]   every ${INTERVAL}s -> $OUT (epoch,pattern,count,index_total), max ${MAX_SECONDS}s (0 = until killed)"
    fi
    exit 0
fi

indexer_resolve_credentials || exit 1
indexer_resolve_tls || exit 1
# The credentials go to curl on stdin (-K -), never in its argv (visible in /proc/*/cmdline).
curl_args=(-s -g --max-time 5 -K - "${INDEXER_TLS_ARGS[@]}")
curl_user="$(indexer_curl_user_line)"
probe_curl() { printf '%s\n' "$curl_user" | curl "${curl_args[@]}" "$@"; }

# json_field BODY EXPR -> the number at EXPR (a python expression on `d`), or nothing.
json_field() {
    "$PYTHON" -c '
import json, sys
try:
    d = json.loads(sys.argv[1])
    print(int(eval(sys.argv[2])))
except Exception:
    pass
' "$1" "$2"
}

sample_pattern() {  # pattern -> "count,index_total" (either may be empty)
    local pat="$1" body count total
    body="$(probe_curl "${INDEXER_URL}/${pat}/_count" 2>/dev/null)" || body=""
    count="$(json_field "$body" "d['count']")"
    body="$(probe_curl "${INDEXER_URL}/${pat}/_stats/indexing" 2>/dev/null)" || body=""
    total="$(json_field "$body" "d['_all']['total']['indexing']['index_total']")"
    printf '%s,%s\n' "$count" "$total"
}

if $ONCE; then
    sum=0
    for pat in "${PATTERN_LIST[@]}"; do
        c="$(sample_pattern "$pat")"; c="${c%%,*}"
        [[ -n "$c" ]] || { echo "indexer_ingest_probe: no answer for $pat" >&2; exit 1; }
        sum=$((sum + c))
    done
    echo "$sum"
    exit 0
fi

mkdir -p "$(dirname "$OUT")"
echo "epoch,pattern,count,index_total" > "$OUT"
trap 'exit 0' TERM INT
start=$SECONDS
while :; do
    now="$(date +%s.%N)"
    for pat in "${PATTERN_LIST[@]}"; do
        printf '%s,%s,%s\n' "$now" "$pat" "$(sample_pattern "$pat")" >> "$OUT"
    done
    if (( MAX_SECONDS > 0 && SECONDS - start >= MAX_SECONDS )); then break; fi
    sleep "$INTERVAL"
done
