#!/usr/bin/env bash
# Quick syscollector inventory count for Debian-based Wazuh agents.
#
# Counts the items that syscollector will emit on its next scan, broken down
# by category. Optionally tops up the total to a target by either:
#   - installing -doc packages (realistic but SLOW, 20-30 min/VM)
#   - creating fake system users (very fast, seconds/VM)
#
# Each fake user adds 1 user + 1 group to syscollector's inventory → +2 items
# per useradd call, so reaching the target is much cheaper than the package
# install path. Fake users are named "wazubench_NNNN" so they can be wiped
# with --cleanup-fake-users afterwards.
#
# Usage:
#   ./syscollector_inventory_count.sh                              # just print
#   ./syscollector_inventory_count.sh --top-up 2000                # default: packages
#   ./syscollector_inventory_count.sh --top-up 2000 --via users    # fast path
#   ./syscollector_inventory_count.sh --cleanup-fake-users         # undo users
#
# Run on each of the 4 real agents (this is per-agent state, not centralized).
# Idempotent: re-running --top-up never removes anything; it only adds if the
# current total is below the target.

set -euo pipefail

count_inventory() {
    local packages processes services users groups iface ports total

    packages=$(dpkg -l 2>/dev/null | grep -c '^ii' || true)
    processes=$(ps -e --no-headers 2>/dev/null | wc -l)
    services=$(systemctl list-units --type=service --no-legend 2>/dev/null | wc -l || true)
    users=$(getent passwd | wc -l)
    groups=$(getent group | wc -l)
    iface=$(ip -o link show 2>/dev/null | wc -l || true)
    ports=$(ss -tuln 2>/dev/null | tail -n +2 | wc -l || true)

    # +1 osinfo +1 hardware (syscollector always emits one of each).
    total=$((packages + processes + services + users + groups + iface + ports + 2))

    cat <<EOF
=== Syscollector inventory count (approx DataValues for next first-sync) ===
  packages    : ${packages}
  processes   : ${processes}
  services    : ${services}
  users       : ${users}
  groups      : ${groups}
  net_iface   : ${iface}
  ports       : ${ports}
  osinfo+hw   : 2
  -----------------
  TOTAL       : ${total}
EOF
    # Echo only the number on a stable handle so callers can capture it.
    printf '%s' "${total}" >/tmp/_syscollector_total
}

top_up() {
    local target="$1"
    local method="${2:-packages}"
    local current need
    current=$(cat /tmp/_syscollector_total)
    need=$(( target - current ))

    if (( need <= 0 )); then
        echo
        echo "Already at ${current} >= ${target}, nothing to add."
        return 0
    fi

    case "$method" in
        users)    top_up_via_users    "$need" ;;
        packages) top_up_via_packages "$need" ;;
        *)
            echo "Unknown --via method: $method (expected: users|packages)" >&2
            exit 1
            ;;
    esac
}

top_up_via_users() {
    local need="$1"
    # Each useradd creates one user and one private group → +2 inventory items.
    local users_to_create=$(( (need + 1) / 2 ))

    echo
    echo "Need ~${need} more items. Creating ${users_to_create} fake users."
    echo "(each useradd adds 1 user + 1 group = 2 syscollector items)"
    echo "Users are named 'wazubench_NNNN' → clean up with --cleanup-fake-users."
    echo

    local start_ts ok=0 fail=0 i name
    start_ts=$(date +%s)
    for ((i = 1; i <= users_to_create; i++)); do
        name=$(printf 'wazubench_%04d' "$i")
        if useradd -r -M -s /usr/sbin/nologin "$name" 2>/dev/null; then
            ok=$((ok + 1))
        else
            # Likely already exists from a previous run; skip silently and continue.
            fail=$((fail + 1))
        fi
    done
    local elapsed=$(( $(date +%s) - start_ts ))
    echo "Created ${ok} new users (${fail} skipped/existed) in ${elapsed}s."

    echo
    echo "=== After top-up ==="
    count_inventory
}

top_up_via_packages() {
    local need="$1"

    echo
    echo "Need ~${need} more items. Topping up via -doc packages (slow path)..."
    echo "(this can take 20-30 minutes per VM; use --via users for the fast path)"
    echo

    apt-get update -qq

    # Get a list of candidate -doc packages NOT already installed.
    # apt-cache search returns "name description" lines; we keep the name.
    # Then filter out any that dpkg already shows as installed.
    mapfile -t CANDIDATES < <(
        apt-cache search '\-doc$' 2>/dev/null \
            | awk '{print $1}' \
            | while read -r pkg; do
                  if ! dpkg -s "${pkg}" >/dev/null 2>&1; then
                      echo "${pkg}"
                  fi
              done
    )

    if (( ${#CANDIDATES[@]} == 0 )); then
        echo "No -doc candidates available. Falling back to library packages..."
        mapfile -t CANDIDATES < <(
            apt-cache search '^lib' 2>/dev/null \
                | awk '{print $1}' \
                | while read -r pkg; do
                      if ! dpkg -s "${pkg}" >/dev/null 2>&1; then
                          echo "${pkg}"
                      fi
                  done
        )
    fi

    if (( ${#CANDIDATES[@]} == 0 )); then
        echo "ERROR: no installable candidates found. Manual install required." >&2
        return 1
    fi

    # Cap to ~need * 1.5 (some packages pull deps that count too, others may
    # already be installed transitively, and batched installs leave some
    # broken — leave plenty of room for noise).
    local cap=$(( need + need / 2 + 50 ))
    if (( ${#CANDIDATES[@]} > cap )); then
        CANDIDATES=("${CANDIDATES[@]:0:cap}")
    fi

    # Install in batches. apt-get install with hundreds of packages at once
    # rolls back the entire transaction if a single dependency is broken,
    # leaving you with 0 progress. Smaller batches + --fix-missing let
    # broken ones be skipped while the rest proceed.
    local batch_size=50
    local total=${#CANDIDATES[@]}
    local installed_before installed_after
    installed_before=$(dpkg -l 2>/dev/null | grep -c '^ii' || true)

    echo "Installing up to ${total} packages in batches of ${batch_size}..."
    echo "Per-batch log goes to /tmp/_inventory_topup.log"
    : > /tmp/_inventory_topup.log

    local idx=0 batch_num=0 ok_batches=0 fail_batches=0
    while (( idx < total )); do
        batch_num=$(( batch_num + 1 ))
        local end=$(( idx + batch_size ))
        (( end > total )) && end=$total
        local batch=("${CANDIDATES[@]:idx:end-idx}")
        idx=$end

        {
            echo "=== batch $batch_num (${#batch[@]} pkgs, idx now $idx/$total) ==="
            DEBIAN_FRONTEND=noninteractive apt-get install -y \
                --no-install-recommends --fix-missing \
                "${batch[@]}" 2>&1
            echo "=== batch $batch_num rc=$? ==="
        } >>/tmp/_inventory_topup.log
        if (( $? == 0 )); then
            ok_batches=$(( ok_batches + 1 ))
        else
            fail_batches=$(( fail_batches + 1 ))
        fi

        # Brief progress every 5 batches so the user knows it's alive.
        if (( batch_num % 5 == 0 )) || (( idx >= total )); then
            local now
            now=$(dpkg -l 2>/dev/null | grep -c '^ii' || true)
            local gained=$(( now - installed_before ))
            echo "  batch ${batch_num}: progress idx=${idx}/${total} (+${gained} packages so far)"
        fi
    done

    installed_after=$(dpkg -l 2>/dev/null | grep -c '^ii' || true)
    echo
    echo "Batches: ${ok_batches} ok, ${fail_batches} with errors."
    echo "Packages installed by this top-up: $(( installed_after - installed_before ))"
    echo "=== After top-up ==="
    count_inventory
}

cleanup_fake_users() {
    echo "Removing all wazubench_* users created by --top-up --via users..."
    local removed=0
    while read -r u; do
        userdel -r "$u" 2>/dev/null || userdel "$u" 2>/dev/null || true
        removed=$((removed + 1))
    done < <(getent passwd | awk -F: '/^wazubench_/{print $1}')
    echo "Removed ${removed} users."
    echo
    echo "=== After cleanup ==="
    count_inventory
}

main() {
    local target="" method="packages" do_cleanup=false
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --top-up)
                if [[ -z "${2:-}" ]] || ! [[ "$2" =~ ^[0-9]+$ ]]; then
                    echo "Usage: $0 --top-up <target> [--via users|packages]" >&2
                    exit 1
                fi
                target="$2"; shift 2
                ;;
            --via)
                method="${2:-}"; shift 2
                ;;
            --cleanup-fake-users)
                do_cleanup=true; shift
                ;;
            -h|--help)
                sed -n '/^# /,/^$/p' "$0" | sed 's/^# \{0,1\}//' | head -25
                exit 0
                ;;
            *)
                echo "Unknown option: $1" >&2
                exit 1
                ;;
        esac
    done

    count_inventory

    if [[ "$do_cleanup" == true ]]; then
        echo
        cleanup_fake_users
        exit 0
    fi

    if [[ -n "$target" ]]; then
        top_up "$target" "$method"
    fi
}

main "$@"
