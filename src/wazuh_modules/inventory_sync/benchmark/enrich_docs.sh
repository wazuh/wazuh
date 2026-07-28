#!/usr/bin/env bash
#
# enrich_docs.sh — enrich a sample of inventory-sync state docs with case.* triage
# fields (as a Dashboard/Indexer user would), so a later syscollector delta can prove
# fetch-merge-reindex keeps them (feature) or full replacement wipes them (baseline).
#
# Run this WHILE the benchmark scenario is active: after the first syncs have landed
# (docs exist) and with syscollector delta repeats still pending, so a subsequent
# repeat re-hits the enriched _ids. Then run verify_case.sh once the run finishes.
#
# Targets wazuh-states-inventory-processes by default (present in both OS dumps and the
# only lane whose deltas deterministically revisit the same _ids). The merge script is
# shared across all state types, so proving it here proves the mechanism for all of them.
#
# Indexer connection is taken from env (same names as indexer_control.sh):
#   INDEXER_HOST (localhost)  INDEXER_PORT (9200)  INDEXER_USER (admin)  INDEXER_PASS (admin)
# Other knobs:
#   IDX (wazuh-states-inventory-processes)  SAMPLE (20)  DEADLINE_S (180)
# Usage:
#   ./enrich_docs.sh [output_jsonl_file]       # default: enriched_docs.jsonl
#
set -euo pipefail

IDX="${IDX:-wazuh-states-inventory-processes}"
INDEXER_HOST="${INDEXER_HOST:-localhost}"
INDEXER_PORT="${INDEXER_PORT:-9200}"
INDEXER_USER="${INDEXER_USER:-admin}"
INDEXER_PASS="${INDEXER_PASS:-admin}"
SAMPLE="${SAMPLE:-20}"
DEADLINE_S="${DEADLINE_S:-180}"
OUT="${1:-enriched_docs.jsonl}"

BASE="https://${INDEXER_HOST}:${INDEXER_PORT}"
CURL=(curl -sSk --fail-with-body -u "${INDEXER_USER}:${INDEXER_PASS}")

count_of() {
  local response
  response=$("${CURL[@]}" "${BASE}/${IDX}/_count" 2>/dev/null) || { echo 0; return; }
  python3 -c 'import sys,json;print(json.load(sys.stdin).get("count",0))' <<<"${response}"
}

echo "[enrich] waiting for docs in ${IDX} (deadline ${DEADLINE_S}s)..."
start=$SECONDS; prev=-1; cur=0
while (( SECONDS - start < DEADLINE_S )); do
  cur=$(count_of)
  echo "  [$((SECONDS-start))s] ${IDX} count=${cur}"
  if [[ "${cur}" -gt 0 && "${cur}" == "${prev}" ]]; then break; fi
  prev="${cur}"; sleep 5
done
[[ "${cur}" -gt 0 ]] || { echo "[enrich] ERROR: no docs in ${IDX} — is the scenario running?"; exit 1; }

echo "[enrich] adding case mapping to ${IDX} (mappings are dynamic:strict, so this is required)..."
"${CURL[@]}" -X PUT "${BASE}/${IDX}/_mapping" -H 'Content-Type: application/json' -d '{
  "properties":{"case":{"properties":{
    "classification":{"type":"keyword"},
    "notes":{"type":"match_only_text"}}}}}' >/dev/null

echo "[enrich] selecting up to ${SAMPLE} docs and enriching..."
: > "${OUT}"
TMP_IDS=$(mktemp)
trap 'rm -f "$TMP_IDS"' EXIT
"${CURL[@]}" "${BASE}/${IDX}/_search?size=${SAMPLE}&_source=false" \
  -H 'Content-Type: application/json' -d '{"query":{"match_all":{}}}' \
  | python3 -c 'import sys,json;[print(h["_id"]) for h in json.load(sys.stdin)["hits"]["hits"]]' > "${TMP_IDS}"

n=0
while read -r id; do
  [[ -z "${id}" ]] && continue
  "${CURL[@]}" -X POST "${BASE}/${IDX}/_update/${id}?refresh=wait_for" -H 'Content-Type: application/json' -d '{
    "doc":{"case":{"classification":"under_investigation","notes":"bench triage note"}}}' >/dev/null
  "${CURL[@]}" "${BASE}/${IDX}/_doc/${id}" | python3 -c '
import json, sys
d = json.load(sys.stdin)
s = d.get("_source", {}).get("case", {})
print(json.dumps({
    "id": d.get("_id", ""),
    "seq_no": d.get("_seq_no", -1),
    "classification": s.get("classification"),
    "notes": s.get("notes"),
}, separators=(",", ":")))
' >> "${OUT}"
  n=$((n+1))
done < "${TMP_IDS}"

[[ "$n" -gt 0 ]] || { echo "[enrich] ERROR: search returned no document IDs"; exit 1; }
echo "[enrich] enriched ${n} docs in ${IDX}; snapshots recorded -> ${OUT}"
echo "[enrich] keep the scenario running so a later syscollector delta re-hits these _ids,"
echo "[enrich] then after the run: ./verify_case.sh ${OUT} present   (feature)"
echo "[enrich]                     ./verify_case.sh ${OUT} absent    (baseline)"
