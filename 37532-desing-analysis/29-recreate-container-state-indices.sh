#!/usr/bin/env bash
# Recreates the wazuh-states-* indices whose `container` field is an OpenSearch
# object with "enabled": false, so they pick up the real container mapping from
# the template 28-apply-container-templates.sh installed.
#
# Why recreation and not a mapping update: `enabled` cannot be changed on a live
# mapping. OpenSearch answers a PUT _mapping with
#   mapper_exception: the [enabled] parameter can't be updated for the object
#   mapping [container]
# An index created from a template that declared `container` as a disabled object
# therefore keeps it for the index's whole life. The subtree still INGESTS -- a
# disabled object is not parsed, so dynamic:strict never reaches inside it -- it
# is simply not searchable, which in a dashboard is indistinguishable from the
# data not arriving at all.
#
# DESTRUCTIVE. Deleting a state index discards every document in it, for every
# agent reporting to this manager, not only the container-scoped ones. They come
# back only as agents re-sync. Reports and changes nothing unless --apply is given.
#
# Deletion and recreation must both happen here: the `wazuh_manager` security role
# has no indices:admin/create (the indices are created by the setup plugin running
# as the internal admin), so an index deleted and not recreated cannot be brought
# back by the manager, and its sync then fails every cycle.
#
# Usage:
#   29-recreate-container-state-indices.sh --url https://127.0.0.1:9200 --user admin --password <pw>
#   29-recreate-container-state-indices.sh ... --apply
#   29-recreate-container-state-indices.sh ... --apply --only inventory-processes

set -euo pipefail

URL=""
USER=""
PASSWORD=""
APPLY=0
ONLY=""

while [ $# -gt 0 ]; do
    case "$1" in
        --url) URL="$2"; shift 2 ;;
        --user) USER="$2"; shift 2 ;;
        --password) PASSWORD="$2"; shift 2 ;;
        --only) ONLY="$2"; shift 2 ;;
        --apply) APPLY=1; shift ;;
        -h|--help) sed -n '2,32p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -n "$URL" ] || { echo "--url is required" >&2; exit 2; }
[ -n "$USER" ] || { echo "--user is required" >&2; exit 2; }
[ -n "$PASSWORD" ] || { echo "--password is required" >&2; exit 2; }

# The same 12 the patch touches. A state index outside this list has no container
# producer writing to it, so recreating it would cost data for nothing.
NAMES="fim-files inventory-groups inventory-hardware inventory-interfaces \
inventory-networks inventory-packages inventory-ports inventory-processes \
inventory-protocols inventory-services inventory-system inventory-users"

if [ -n "$ONLY" ]; then
    NAMES="$ONLY"
fi

CURL=(curl -sS -k -u "${USER}:${PASSWORD}" -H "Content-Type: application/json")

# OK | DISABLED | ABSENT, read from an index's live mapping.
classify_index() {
    "${CURL[@]}" "${URL}/${1}/_mapping" 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    print("UNREADABLE"); raise SystemExit
m = list(d.values())[0]["mappings"].get("properties", {})
c = m.get("container")
if c is None:
    print("ABSENT")
elif c.get("enabled") is False:
    print("DISABLED")
elif "properties" in c:
    print("OK")
else:
    print("UNEXPECTED:" + json.dumps(c)[:80])
'
}

# Guard: recreating against a template that has no container mapping just
# reproduces the problem, and costs the index's documents to do it.
template_has_container() {
    "${CURL[@]}" "${URL}/_index_template/states-${1}" 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    t = d["index_templates"][0]["index_template"]["template"]["mappings"]["properties"]
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if "container" in t else 1)
'
}

doc_count() {
    "${CURL[@]}" "${URL}/${1}/_count" 2>/dev/null | python3 -c '
import json, sys
try:
    print(json.load(sys.stdin)["count"])
except Exception:
    print("?")
'
}

recreated=0
skipped=0
failed=0

for name in $NAMES; do
    index="wazuh-states-${name}"
    printf '%-40s ' "$index"

    code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' "${URL}/${index}" || true)
    if [ "$code" != "200" ]; then
        echo "does not exist; the template covers it when it is created"
        skipped=$((skipped + 1))
        continue
    fi

    state=$(classify_index "$index")
    case "$state" in
        OK)
            echo "already carries the container mapping"
            skipped=$((skipped + 1))
            continue
            ;;
        DISABLED|ABSENT) ;;
        *)
            echo "unexpected mapping (${state}); left alone"
            failed=$((failed + 1))
            continue
            ;;
    esac

    if ! template_has_container "$name"; then
        echo "REFUSED: template states-${name} has no container mapping; run 28-apply-container-templates.sh first"
        failed=$((failed + 1))
        continue
    fi

    docs=$(doc_count "$index")

    if [ "$APPLY" -eq 0 ]; then
        echo "${state}; would delete and recreate, discarding ${docs} document(s)"
        continue
    fi

    echo "${state}; deleting and recreating, discarding ${docs} document(s)"

    if ! "${CURL[@]}" -o /dev/null -w '' -X DELETE "${URL}/${index}"; then
        echo "    DELETE failed; index left as it was" >&2
        failed=$((failed + 1))
        continue
    fi

    if ! "${CURL[@]}" -o /dev/null -w '' -X PUT "${URL}/${index}"; then
        echo "    PUT failed; ${index} NO LONGER EXISTS and the manager cannot create it." >&2
        echo "    Recreate it by hand: curl -k -u <admin> -X PUT '${URL}/${index}'" >&2
        failed=$((failed + 1))
        continue
    fi

    after=$(classify_index "$index")
    if [ "$after" = "OK" ]; then
        echo "    recreated with the container mapping"
        recreated=$((recreated + 1))
    else
        echo "    WARNING: recreated but mapping is ${after}; the setup plugin may have re-PUT its own template" >&2
        failed=$((failed + 1))
    fi
done

echo
if [ "$APPLY" -eq 0 ]; then
    echo "Report only. Re-run with --apply to delete and recreate the indices listed above."
else
    echo "Recreated ${recreated}, skipped ${skipped}, failed ${failed}."
    echo "The dashboard still needs its index-pattern field list refreshed."
fi

[ "$failed" -eq 0 ]
