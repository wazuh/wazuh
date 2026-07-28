#!/usr/bin/env bash
#
# verify_case.sh — check whether case.* survived on the enriched docs after a run.
#   feature build  -> expect PRESENT (the preserving merge kept case.*)
#   baseline build -> expect ABSENT  (full-replace wiped case.*)
#
# Reads the _id list produced by enrich_docs.sh. Same env vars as enrich_docs.sh.
# Usage:
#   ./verify_case.sh [ids_file] [present|absent]     # defaults: enriched_ids.txt present
#
set -euo pipefail

IDX="${IDX:-wazuh-states-inventory-processes}"
INDEXER_HOST="${INDEXER_HOST:-localhost}"
INDEXER_PORT="${INDEXER_PORT:-9200}"
INDEXER_USER="${INDEXER_USER:-admin}"
INDEXER_PASS="${INDEXER_PASS:-admin}"
IDS="${1:-enriched_ids.txt}"
EXPECT="${2:-present}"

BASE="https://${INDEXER_HOST}:${INDEXER_PORT}"
CURL=(curl -sk -u "${INDEXER_USER}:${INDEXER_PASS}")
[[ -s "${IDS}" ]] || { echo "no ids file (or empty): ${IDS}"; exit 1; }

present=0; absent=0
while read -r id; do
  [[ -z "${id}" ]] && continue
  v=$("${CURL[@]}" "${BASE}/${IDX}/_doc/${id}" | python3 -c \
    'import sys,json;d=json.load(sys.stdin);print(d.get("_source",{}).get("case",{}).get("classification","<none>"))')
  if [[ "${v}" == "under_investigation" ]]; then present=$((present+1)); else absent=$((absent+1)); fi
done < "${IDS}"

total=$((present+absent))
echo "case.classification present=${present} absent=${absent} of ${total} (expected all ${EXPECT})"
if [[ "${EXPECT}" == "present" && "${absent}" -eq 0 && "${present}" -gt 0 ]]; then
  echo "PASS — feature: enrichment survived the delta merge"
elif [[ "${EXPECT}" == "absent" && "${present}" -eq 0 && "${absent}" -gt 0 ]]; then
  echo "PASS — baseline: enrichment wiped by full-replace (expected old behavior)"
else
  echo "UNEXPECTED — check: right build live? did a syscollector delta re-hit these ids yet?"
  exit 2
fi
