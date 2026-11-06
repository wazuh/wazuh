#!/usr/bin/env bash
# Applies the container mapping to a LIVE wazuh-indexer, for local end-to-end
# validation without publishing anything to wazuh-indexer-plugins.
#
# The setup plugin installs one composable index template per state index, named
# after its resource path with "templates/" dropped and slashes turned into
# hyphens (SetupPlugin.java / Index.getTemplateName), so templates/states/fim-files
# becomes the template "states-fim-files" for the index "wazuh-states-fim-files".
# Each template JSON file is already a valid _index_template body, so it is PUT
# verbatim.
#
# A template only governs indices created after it, so every concrete index that
# already exists is additionally given the container subtree through _mapping and
# the new search fields through _settings. Both are additive.
#
# Usage:
#   28-apply-container-templates.sh --url https://127.0.0.1:9200 --user admin --password <pw> [--dry-run]
#   28-apply-container-templates.sh ... --templates /path/to/templates/states

set -euo pipefail

URL=""
USER=""
PASSWORD=""
DRY_RUN=0
TEMPLATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/src/external/indexer-plugins"

while [ $# -gt 0 ]; do
    case "$1" in
        --url) URL="$2"; shift 2 ;;
        --user) USER="$2"; shift 2 ;;
        --password) PASSWORD="$2"; shift 2 ;;
        --templates) TEMPLATE_DIR="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -n "$URL" ] || { echo "--url is required" >&2; exit 2; }
[ -n "$USER" ] || { echo "--user is required" >&2; exit 2; }
[ -n "$PASSWORD" ] || { echo "--password is required" >&2; exit 2; }
[ -d "$TEMPLATE_DIR" ] || { echo "no such directory: $TEMPLATE_DIR" >&2; exit 2; }

# Exactly the templates the patch touches. Any other file in TEMPLATE_DIR is
# left alone, so a stray download cannot widen what this script changes.
TEMPLATES="fim-files inventory-groups inventory-hardware inventory-interfaces \
inventory-networks inventory-packages inventory-ports inventory-processes \
inventory-protocols inventory-services inventory-system inventory-users"

CURL=(curl -sS --fail-with-body -k -u "${USER}:${PASSWORD}" -H "Content-Type: application/json")

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "DRY-RUN: $1 $2"
        return 0
    fi
    shift 2
    "$@"
}

for name in $TEMPLATES; do
    file="${TEMPLATE_DIR}/${name}.json"
    [ -f "$file" ] || { echo "missing template: $file" >&2; exit 1; }

    python3 -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if 'container' in d['template']['mappings']['properties'] else 1)" "$file" \
        || { echo "ERROR: ${file} carries no container mapping; stage the patch first" >&2; exit 1; }

    echo "==> states-${name}"
    run PUT "_index_template/states-${name}" \
        "${CURL[@]}" -X PUT "${URL}/_index_template/states-${name}" --data-binary "@${file}" -o /dev/null -w '    template: HTTP %{http_code}\n'

    index="wazuh-states-${name}"
    if [ "$DRY_RUN" -eq 0 ]; then
        code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X HEAD "${URL}/${index}" || true)
        if [ "$code" != "200" ]; then
            echo "    index ${index} does not exist yet; the template covers it when it is created"
            continue
        fi
    fi

    # Additive mapping update for the already-created index.
    mapping=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
print(json.dumps({'properties': {'container': d['template']['mappings']['properties']['container']}}))
" "$file")
    run PUT "${index}/_mapping" \
        "${CURL[@]}" -X PUT "${URL}/${index}/_mapping" --data-binary "$mapping" -o /dev/null -w '    mapping:  HTTP %{http_code}\n'

    settings=$(python3 -c "
import json,sys
d=json.load(open(sys.argv[1]))
print(json.dumps({'index': {'query': {'default_field': d['template']['settings']['index']['query.default_field']}}}))
" "$file")
    run PUT "${index}/_settings" \
        "${CURL[@]}" -X PUT "${URL}/${index}/_settings" --data-binary "$settings" -o /dev/null -w '    settings: HTTP %{http_code}\n'
done

echo
echo "Done. The dashboard still needs its index-pattern field list refreshed before"
echo "the new container fields appear in Discover."
