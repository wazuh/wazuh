#!/usr/bin/env bash
#
# verify_case.sh — check whether case.* survived on the enriched docs after a run.
#   feature build  -> expect PRESENT (the preserving merge kept case.*)
#   baseline build -> expect ABSENT  (full-replace wiped case.*)
#
# Reads the JSONL snapshots produced by enrich_docs.sh. Same env vars as enrich_docs.sh.
# Usage:
#   ./verify_case.sh [snapshots_file] [present|absent]
#
set -euo pipefail

IDX="${IDX:-wazuh-states-inventory-processes}"
INDEXER_HOST="${INDEXER_HOST:-localhost}"
INDEXER_PORT="${INDEXER_PORT:-9200}"
INDEXER_USER="${INDEXER_USER:-admin}"
INDEXER_PASS="${INDEXER_PASS:-admin}"
SNAPSHOTS="${1:-enriched_docs.jsonl}"
EXPECT="${2:-present}"

BASE="https://${INDEXER_HOST}:${INDEXER_PORT}"
CURL=(curl -sSk --fail-with-body -u "${INDEXER_USER}:${INDEXER_PASS}")
[[ -s "${SNAPSHOTS}" ]] || { echo "no snapshots file (or empty): ${SNAPSHOTS}"; exit 1; }

present=0; absent=0; advanced=0; failures=0
while IFS= read -r snapshot; do
  [[ -z "${snapshot}" ]] && continue
  read -r id old_seq expected_classification expected_notes < <(
    python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(d["id"], d["seq_no"], d["classification"], d["notes"])' "$snapshot"
  )
  response=$("${CURL[@]}" "${BASE}/${IDX}/_doc/${id}")
  read -r found new_seq classification notes < <(
    python3 -c 'import json,sys; d=json.load(sys.stdin); c=d.get("_source",{}).get("case",{}); print(int(d.get("found",False)), d.get("_seq_no",-1), c.get("classification","<none>"), c.get("notes","<none>"))' <<<"$response"
  )

  if [[ "$found" -ne 1 ]]; then
    echo "FAIL id=${id}: document not found"
    failures=$((failures+1))
    continue
  fi
  if (( new_seq > old_seq )); then
    advanced=$((advanced+1))
  else
    echo "FAIL id=${id}: _seq_no did not advance (${old_seq} -> ${new_seq})"
    failures=$((failures+1))
  fi

  if [[ "$classification" == "$expected_classification" && "$notes" == "$expected_notes" ]]; then
    present=$((present+1))
  else
    absent=$((absent+1))
  fi
done < "${SNAPSHOTS}"

total=$((present+absent))
echo "case fields present=${present} absent_or_changed=${absent} seq_advanced=${advanced} of ${total}"
if [[ "$EXPECT" == "present" && "$failures" -eq 0 && "$absent" -eq 0 && "$present" -gt 0 ]]; then
  echo "PASS — enrichment survived fetch-merge-reindex and every document was rewritten"
elif [[ "$EXPECT" == "absent" && "$failures" -eq 0 && "$present" -eq 0 && "$absent" -gt 0 ]]; then
  echo "PASS — enrichment wiped by full replacement and every document was rewritten"
else
  echo "FAIL — preservation or post-enrichment rewrite could not be proven"
  exit 2
fi
