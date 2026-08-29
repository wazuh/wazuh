#!/usr/bin/env bash
set -euo pipefail
# ---------------------------------------------------------------------------
# prepare_manager.sh — Configure a local manager for agent-mode benchmarking.
#
# Agent-mode runs enroll a synthetic fleet against authd, so enrollment must be
# open and password-free. This script sets, in etc/wazuh-manager.yml:
#     auth:
#       disabled: false
#       remote_enrollment: true
#       use_password: false
# removes etc/authd.pass and, only when --max-agents is given, sets the internal
# option `authd.max_agents=N` in etc/wazuh-manager-internal-options.conf (it is
# not a configuration-file option).
#
# Why explicitly: the compiled default is use_password=0, but upstream #36705
# turned the shared password ON BY DEFAULT in the installer, so a fresh install
# rejects unauthenticated enrollment until this is undone.
#
# It is idempotent: re-running it converges to the same values. It edits the
# files in place (a .bak of each is written once; the rewritten YAML loses its
# comments, the .bak keeps them), validates the result with
# bin/wazuh-manager-conf (schema rules, not file existence) and restarts the
# manager unless --no-restart is given.
#
# Usage:
#   sudo ./prepare_manager.sh [--conf PATH] [--max-agents N] [--no-restart]
# ---------------------------------------------------------------------------

CONF="/var/wazuh-manager/etc/wazuh-manager.yml"
MAX_AGENTS=""
RESTART=true
CONTROL="/var/wazuh-manager/bin/wazuh-manager-control"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --conf)        CONF="$2"; shift 2 ;;
        --max-agents)  MAX_AGENTS="$2"; shift 2 ;;
        --no-restart)  RESTART=false; shift ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "prepare_manager: unknown option $1" >&2; exit 1 ;;
    esac
done

if [[ ! -f "$CONF" ]]; then
    echo "Error: config not found: $CONF" >&2
    echo "  Is the manager installed? Pass --conf to point at wazuh-manager.yml." >&2
    exit 1
fi

# The manager home is the parent of etc/: its own Python ships PyYAML and its CLI validates the file.
HOME_DIR="$(cd "$(dirname "$CONF")/.." && pwd)"
PYTHON="${PYTHON:-}"
if [[ -z "$PYTHON" ]]; then
    if [[ -x "$HOME_DIR/framework/python/bin/python3" ]]; then
        PYTHON="$HOME_DIR/framework/python/bin/python3"
    else
        PYTHON="python3"
    fi
fi
INTERNAL_OPTIONS="$(dirname "$CONF")/wazuh-manager-internal-options.conf"
MCONF="$HOME_DIR/bin/wazuh-manager-conf"

echo "Configuring open, password-free enrollment in $CONF ..."
"$PYTHON" - "$CONF" <<'PY'
import os, sys
import yaml

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    original = fh.read()
document = yaml.safe_load(original) or {}
if not isinstance(document, dict):
    sys.stderr.write(f"{path}: the document root must be a mapping; is this a manager config?\n")
    sys.exit(2)

auth = document.setdefault("auth", {})
if not isinstance(auth, dict):
    auth = document["auth"] = {}
wanted = {"disabled": False, "remote_enrollment": True, "use_password": False}
if any(auth.get(key) != value for key, value in wanted.items()):
    auth.update(wanted)
    bak = path + ".bak"
    if not os.path.exists(bak):
        with open(bak, "w", encoding="utf-8") as fh:
            fh.write(original)
    with open(path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(document, fh, sort_keys=False, default_flow_style=False)
    print("  auth section updated")
else:
    print("  auth section already set")
PY

if [[ -n "$MAX_AGENTS" ]]; then
    echo "Setting authd.max_agents=$MAX_AGENTS in $INTERNAL_OPTIONS ..."
    if [[ ! -f "$INTERNAL_OPTIONS" ]]; then
        echo "Error: internal options file not found: $INTERNAL_OPTIONS" >&2
        exit 1
    fi
    if ! grep -qx "authd.max_agents=$MAX_AGENTS" "$INTERNAL_OPTIONS"; then
        [[ -f "$INTERNAL_OPTIONS.bak" ]] || cp -p "$INTERNAL_OPTIONS" "$INTERNAL_OPTIONS.bak"
        if grep -q '^authd\.max_agents=' "$INTERNAL_OPTIONS"; then
            sed -i "s/^authd\.max_agents=.*/authd.max_agents=$MAX_AGENTS/" "$INTERNAL_OPTIONS"
        else
            printf '\n# Enrollment cap for agent-mode benchmarks (prepare_manager.sh)\nauthd.max_agents=%s\n' "$MAX_AGENTS" >> "$INTERNAL_OPTIONS"
        fi
        echo "  authd.max_agents updated"
    else
        echo "  authd.max_agents already set"
    fi
fi

# Syntax, schema and cross-field rules only: whether the certificates the file names exist is the
# manager's business at start-up, not this script's (it may run against a copy or a fresh install).
if [[ -x "$MCONF" ]]; then
    "$MCONF" -H "$HOME_DIR" -f "$CONF" --skip-file-checks validate
    echo "  $CONF validates"
else
    echo "Note: $MCONF not found; skipping validation." >&2
fi

PASS_FILE="$(dirname "$CONF")/authd.pass"
if [[ -f "$PASS_FILE" ]]; then
    rm -f "$PASS_FILE"
    echo "  removed $PASS_FILE"
fi

if $RESTART; then
    if [[ -x "$CONTROL" ]]; then
        echo "Restarting the manager..."
        "$CONTROL" restart
    else
        echo "Note: $CONTROL not found; restart the manager manually to apply." >&2
    fi
else
    echo "Not restarting (--no-restart). Restart the manager to apply."
fi
echo "Done."
