#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PAYLOADS_DIR="${SCRIPT_DIR}/payloads"

INDEXER_URL="${INDEXER_URL:-https://localhost:9200}"
INDEXER_USER="${INDEXER_USER:-admin}"
INDEXER_PASS="${INDEXER_PASS:-admin}"
INDEX_NAME="${INDEX_NAME:-.cti-cves-smoke}"
INSECURE="${INSECURE:-true}"
ASSERT_VERIFY="${ASSERT_VERIFY:-true}"

EXPECTED_COUNT="${EXPECTED_COUNT:-3}"
EXPECTED_INCREMENTAL_TOTAL="${EXPECTED_INCREMENTAL_TOTAL:-2}"
EXPECTED_INCREMENTAL_IDS="${EXPECTED_INCREMENTAL_IDS:-CVE-2024-5678,CVE-2024-9999}"

DO_SEED=false
DO_VERIFY=false
DO_RESET=false
DO_CLEANUP=false

usage() {
  cat <<'EOF'
Safe smoke test for VD indexer feed fixtures.

Usage:
  vd_indexer_smoke.sh [--seed] [--verify] [--reset] [--cleanup] [--no-assert]

Flags:
  --seed     Create index if needed and upsert fixture CVEs.
  --verify   Run count + incremental query checks.
  --reset    Delete and recreate index before seeding (requires --seed).
  --cleanup  Delete smoke index at the end.
  --no-assert  Skip verification assertions during --verify.

Environment variables:
  INDEXER_URL    Default: https://localhost:9200
  INDEXER_USER   Default: admin
  INDEXER_PASS   Default: admin
  INDEX_NAME     Default: .cti-cves-smoke
  INSECURE       Default: true (uses curl -k when true)
  ASSERT_VERIFY  Default: true
  EXPECTED_COUNT Default: 3
  EXPECTED_INCREMENTAL_TOTAL Default: 2
  EXPECTED_INCREMENTAL_IDS Default: CVE-2024-5678,CVE-2024-9999

Examples:
  INDEXER_URL=https://localhost:9200 INDEXER_USER=admin INDEXER_PASS=admin \
    ./vd_indexer_smoke.sh --seed --verify

  ./vd_indexer_smoke.sh --seed --reset --verify --cleanup
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --seed) DO_SEED=true ;;
    --verify) DO_VERIFY=true ;;
    --reset) DO_RESET=true ;;
    --cleanup) DO_CLEANUP=true ;;
    --no-assert) ASSERT_VERIFY=false ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

if [[ "$DO_RESET" == true && "$DO_SEED" != true ]]; then
  echo "--reset requires --seed" >&2
  exit 1
fi

if [[ "$DO_SEED" != true && "$DO_VERIFY" != true && "$DO_CLEANUP" != true ]]; then
  echo "No action selected. Use --seed and/or --verify and/or --cleanup." >&2
  usage
  exit 1
fi

if [[ "$INSECURE" == true ]]; then
  CURL_BASE=(curl -sS -k -u "${INDEXER_USER}:${INDEXER_PASS}")
else
  CURL_BASE=(curl -sS -u "${INDEXER_USER}:${INDEXER_PASS}")
fi

json_pretty() {
  python3 -m json.tool
}

curl_json() {
  "${CURL_BASE[@]}" "$@"
}

check_connectivity() {
  echo "== Checking Indexer connectivity =="
  curl_json "${INDEXER_URL}/" | json_pretty
}

index_exists() {
  local code
  code=$("${CURL_BASE[@]}" -o /dev/null -w "%{http_code}" "${INDEXER_URL}/${INDEX_NAME}")
  [[ "$code" == "200" ]]
}

create_index() {
  echo "== Creating index ${INDEX_NAME} with mapping =="
  curl_json -X PUT "${INDEXER_URL}/${INDEX_NAME}" \
    -H "Content-Type: application/json" \
    --data-binary "@${PAYLOADS_DIR}/mapping.json" | json_pretty
}

delete_index() {
  echo "== Deleting index ${INDEX_NAME} =="
  curl_json -X DELETE "${INDEXER_URL}/${INDEX_NAME}" | json_pretty
}

upsert_doc() {
  local doc_id="$1"
  local file_name="$2"

  echo "== Upserting ${doc_id} from ${file_name} =="
  curl_json -X POST "${INDEXER_URL}/${INDEX_NAME}/_doc/${doc_id}" \
    -H "Content-Type: application/json" \
    --data-binary "@${PAYLOADS_DIR}/${file_name}" | json_pretty
}

refresh_index() {
  echo "== Refreshing index ${INDEX_NAME} =="
  curl_json -X POST "${INDEXER_URL}/${INDEX_NAME}/_refresh" | json_pretty
}

verify_count() {
  echo "== Verifying count in ${INDEX_NAME} =="
  local count_json
  count_json="$(curl_json "${INDEXER_URL}/${INDEX_NAME}/_count")"
  echo "${count_json}" | json_pretty

  if [[ "${ASSERT_VERIFY}" == true ]]; then
    echo "== Assert count == ${EXPECTED_COUNT} =="
    python3 - "${EXPECTED_COUNT}" "${count_json}" <<'PY'
import json
import sys

expected_count = int(sys.argv[1])
payload = json.loads(sys.argv[2])
actual_count = int(payload.get("count", -1))

if actual_count != expected_count:
    raise SystemExit(f"Count assertion failed: expected={expected_count}, actual={actual_count}")

print(f"Count assertion passed: {actual_count}")
PY
  fi
}

verify_incremental_query() {
  echo "== Verifying incremental query offset > 1001 =="
  local search_json
  search_json="$(curl_json -X GET "${INDEXER_URL}/${INDEX_NAME}/_search" \
    -H "Content-Type: application/json" \
    --data-binary "@${PAYLOADS_DIR}/query_incremental_offset_gt_1001.json")"
  echo "${search_json}" | json_pretty

  if [[ "${ASSERT_VERIFY}" == true ]]; then
    echo "== Assert incremental total == ${EXPECTED_INCREMENTAL_TOTAL} and IDs == ${EXPECTED_INCREMENTAL_IDS} =="
    python3 - "${EXPECTED_INCREMENTAL_TOTAL}" "${EXPECTED_INCREMENTAL_IDS}" "${search_json}" <<'PY'
import json
import sys

expected_total = int(sys.argv[1])
expected_ids = [item.strip() for item in sys.argv[2].split(",") if item.strip()]

payload = json.loads(sys.argv[3])
hits_block = payload.get("hits", {})
actual_total = int(hits_block.get("total", {}).get("value", -1))
actual_ids = [entry.get("_id", "") for entry in hits_block.get("hits", [])]

if actual_total != expected_total:
    raise SystemExit(f"Incremental total assertion failed: expected={expected_total}, actual={actual_total}")

if actual_ids != expected_ids:
    raise SystemExit(f"Incremental IDs assertion failed: expected={expected_ids}, actual={actual_ids}")

print(f"Incremental assertions passed: total={actual_total}, ids={actual_ids}")
PY
  fi
}

check_connectivity

if [[ "$DO_SEED" == true ]]; then
  if [[ "$DO_RESET" == true ]]; then
    if index_exists; then
      delete_index
    fi
    create_index
  else
    if index_exists; then
      echo "== Index ${INDEX_NAME} already exists. Keeping it (safe mode) =="
    else
      create_index
    fi
  fi

  upsert_doc "CVE-2024-1234" "cve_2024_1234_published.json"
  upsert_doc "CVE-2024-5678" "cve_2024_5678_published.json"
  upsert_doc "CVE-2024-9999" "cve_2024_9999_rejected.json"
  refresh_index
fi

if [[ "$DO_VERIFY" == true ]]; then
  verify_count
  verify_incremental_query
fi

if [[ "$DO_CLEANUP" == true ]]; then
  if index_exists; then
    delete_index
  else
    echo "== Cleanup skipped: ${INDEX_NAME} does not exist =="
  fi
fi

echo "== Smoke test workflow completed =="
