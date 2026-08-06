#!/usr/bin/env bash
set -euo pipefail
# ---------------------------------------------------------------------------
# prepare_manager.sh — Configure a local manager for agent-mode benchmarking.
#
# Agent-mode runs enroll a synthetic fleet against authd, so enrollment must be
# open and password-free. This script makes the <auth> block:
#     <disabled>no</disabled>
#     <remote_enrollment>yes</remote_enrollment>
#     <use_password>no</use_password>
#     <max_agents>N</max_agents>          (only when --max-agents is given)
# and removes etc/authd.pass.
#
# Why explicitly: the compiled default is use_password=0, but upstream #36705
# turned the shared password ON BY DEFAULT in the installer, so a fresh install
# rejects unauthenticated enrollment until this is undone.
#
# It is idempotent: re-running it converges to the same block. It edits the
# config in place (a .bak is written once) and restarts the manager unless
# --no-restart is given.
#
# Usage:
#   sudo ./prepare_manager.sh [--conf PATH] [--max-agents N] [--no-restart]
# ---------------------------------------------------------------------------

CONF="/var/wazuh-manager/etc/wazuh-manager.conf"
MAX_AGENTS=""
RESTART=true
CONTROL="/var/wazuh-manager/bin/wazuh-manager-control"
PYTHON="${PYTHON:-python3}"

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
    echo "  Is the manager installed? Pass --conf to point at wazuh-manager.conf." >&2
    exit 1
fi

echo "Configuring open, password-free enrollment in $CONF ..."
MAX_AGENTS="$MAX_AGENTS" "$PYTHON" - "$CONF" <<'PY'
import os, re, sys

path = sys.argv[1]
max_agents = os.environ.get("MAX_AGENTS", "").strip()
with open(path, "r", encoding="utf-8") as fh:
    original = fh.read()
text = original

def set_child(block, tag, value):
    """Set <tag>value</tag> inside an <auth> block string, adding it if absent."""
    pat = re.compile(rf"<{tag}>.*?</{tag}>", re.DOTALL)
    if pat.search(block):
        return pat.sub(f"<{tag}>{value}</{tag}>", block)
    # insert just before </auth>, preserving indentation of the closing tag
    return re.sub(r"([ \t]*)</auth>", rf"    <{tag}>{value}</{tag}>\n\1</auth>", block, count=1)

auth_pat = re.compile(r"<auth>.*?</auth>", re.DOTALL)
m = auth_pat.search(text)
if m:
    block = m.group(0)
else:
    # No <auth> block: create one before the closing root tag. The 5.x manager
    # config root is <wazuh_config>; older configs use <ossec_config>.
    block = ("<auth>\n"
             "    <disabled>no</disabled>\n"
             "    <remote_enrollment>yes</remote_enrollment>\n"
             "    <use_password>no</use_password>\n"
             "  </auth>")
    idx = -1
    for root_close in ("</wazuh_config>", "</ossec_config>"):
        idx = text.rfind(root_close)
        if idx != -1:
            break
    if idx == -1:
        sys.stderr.write("no </wazuh_config> or </ossec_config> found; is this a manager config?\n")
        sys.exit(2)
    text = text[:idx] + "  " + block + "\n" + text[idx:]
    m = auth_pat.search(text)
    block = m.group(0)

new_block = block
new_block = set_child(new_block, "disabled", "no")
new_block = set_child(new_block, "remote_enrollment", "yes")
new_block = set_child(new_block, "use_password", "no")
if max_agents:
    new_block = set_child(new_block, "max_agents", max_agents)

if new_block != block:
    text = text[:m.start()] + new_block + text[m.end():]

# One-time backup, then write.
bak = path + ".bak"
if not os.path.exists(bak):
    with open(bak, "w", encoding="utf-8") as fh:
        fh.write(original)
with open(path, "w", encoding="utf-8") as fh:
    fh.write(text)
print("  auth block updated")
PY

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
