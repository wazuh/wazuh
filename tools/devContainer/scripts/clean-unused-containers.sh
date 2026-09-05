#!/usr/bin/env bash
# clean-unused-containers.sh
#
# Lists all containers (stopped by default, or all with --all) showing:
#   - Container ID
#   - Name
#   - Image
#   - Status
#   - Last used date (FinishedAt, or CreatedAt if never finished)
#   - Size on disk
#
# Then prompts the user to choose which containers to delete and
# asks for an explicit confirmation before removing them.
#
# Usage:
#   clean-unused-containers.sh           # only stopped/exited containers
#   clean-unused-containers.sh --all     # list every container (including running)
#   clean-unused-containers.sh -h        # show help

set -euo pipefail

SHOW_ALL=0
for arg in "$@"; do
    case "$arg" in
        -a|--all)
            SHOW_ALL=1
            ;;
        -h|--help)
            sed -n '2,18p' "$0"
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg" >&2
            exit 1
            ;;
    esac
done

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker CLI not found in PATH." >&2
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "Error: cannot talk to the Docker daemon (is it running?)." >&2
    exit 1
fi

# Build the list of candidate container IDs.
if [[ "$SHOW_ALL" -eq 1 ]]; then
    mapfile -t CONTAINER_IDS < <(docker ps -a --format '{{.ID}}')
else
    mapfile -t CONTAINER_IDS < <(docker ps -a --filter "status=exited" --filter "status=created" --filter "status=dead" --format '{{.ID}}')
fi

if [[ "${#CONTAINER_IDS[@]}" -eq 0 ]]; then
    if [[ "$SHOW_ALL" -eq 1 ]]; then
        echo "No containers found."
    else
        echo "No stopped containers to clean."
    fi
    exit 0
fi

# Pretty-print the table with sizes (docker ps -s is required to expose Size).
echo
printf "  %-4s %-14s %-28s %-30s %-12s %-22s %-14s\n" \
    "IDX" "CONTAINER ID" "NAME" "IMAGE" "STATUS" "LAST USED (UTC)" "SIZE"
printf "  %-4s %-14s %-28s %-30s %-12s %-22s %-14s\n" \
    "----" "------------" "----" "-----" "------" "----------------" "----"

declare -a INDEX_TO_ID=()
idx=1
for cid in "${CONTAINER_IDS[@]}"; do
    # Use docker inspect for accurate fields.
    read -r name image status finished_at created_at <<<"$(docker inspect \
        --format '{{.Name}} {{.Config.Image}} {{.State.Status}} {{.State.FinishedAt}} {{.Created}}' \
        "$cid")"

    name="${name#/}"

    # Pick the most meaningful "last used" timestamp.
    last_used="$finished_at"
    if [[ -z "$last_used" || "$last_used" == "0001-01-01T00:00:00Z" ]]; then
        last_used="$created_at"
    fi
    last_used="${last_used%.*}"        # drop nanoseconds
    last_used="${last_used//T/ }"      # nicer formatting
    last_used="${last_used%Z}"

    # Size comes from `docker ps -s` only.
    size="$(docker ps -a -s --filter "id=$cid" --format '{{.Size}}' | head -n1)"
    [[ -z "$size" ]] && size="n/a"

    printf "  %-4s %-14s %-28s %-30s %-12s %-22s %-14s\n" \
        "$idx" "${cid:0:12}" "${name:0:28}" "${image:0:30}" "${status:0:12}" "${last_used:0:22}" "${size:0:14}"

    INDEX_TO_ID[$idx]="$cid"
    idx=$((idx + 1))
done
echo

cat <<'EOF'
Select what to delete:
  - A list of indexes or container IDs separated by spaces (e.g. "1 3 5")
  - "all" to delete every listed container
  - empty / "q" / "n" to cancel
EOF
read -r -p "Your choice: " selection

if [[ -z "${selection// /}" || "$selection" =~ ^([qQ]|[nN]|cancel|exit)$ ]]; then
    echo "Cancelled. No containers were removed."
    exit 0
fi

declare -a TO_DELETE=()
if [[ "$selection" =~ ^([aA][lL][lL])$ ]]; then
    TO_DELETE=("${CONTAINER_IDS[@]}")
else
    for token in $selection; do
        if [[ "$token" =~ ^[0-9]+$ ]] && [[ -n "${INDEX_TO_ID[$token]:-}" ]]; then
            TO_DELETE+=("${INDEX_TO_ID[$token]}")
        elif docker inspect "$token" >/dev/null 2>&1; then
            TO_DELETE+=("$token")
        else
            echo "  ! Ignoring invalid selection: '$token'"
        fi
    done
fi

if [[ "${#TO_DELETE[@]}" -eq 0 ]]; then
    echo "Nothing valid selected. Aborting."
    exit 0
fi

echo
echo "The following containers will be REMOVED:"
for cid in "${TO_DELETE[@]}"; do
    name="$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's|^/||')"
    echo "  - ${cid:0:12}  ${name}"
done
echo

read -r -p "Are you sure? Type 'yes' to confirm: " confirm
if [[ "$confirm" != "yes" ]]; then
    echo "Aborted. No containers were removed."
    exit 0
fi

# Stop running ones first (only relevant with --all).
for cid in "${TO_DELETE[@]}"; do
    state="$(docker inspect --format '{{.State.Running}}' "$cid" 2>/dev/null || echo false)"
    if [[ "$state" == "true" ]]; then
        echo "Stopping running container ${cid:0:12}..."
        docker stop "$cid" >/dev/null
    fi
done

echo "Removing containers..."
docker rm -v "${TO_DELETE[@]}"

echo "Done. Removed ${#TO_DELETE[@]} container(s)."
