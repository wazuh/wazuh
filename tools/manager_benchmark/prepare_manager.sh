#!/usr/bin/env bash
set -euo pipefail
# ---------------------------------------------------------------------------
# prepare_manager.sh — Configure a local manager for agent-mode benchmarking.
#
# Agent-mode runs enroll a synthetic fleet, and they do it the way a 5.x agent
# handed an enrollment token does: POST /enroll on 1517 with a `wazuh-enroll+jwt`
# bearer. So this script does two things and NEITHER of them weakens the
# manager's enrollment policy:
#
#   1. makes remote enrollment reachable:
#          <disabled>no</disabled>
#          <remote_enrollment>yes</remote_enrollment>
#          <max_agents>N</max_agents>          (only when --max-agents is given)
#      (remoted serves /enroll only while both of the first two hold)
#   2. mints ONE multi-use enrollment token for the fleet and writes it to
#      --token-file (default: .enrollment_token next to this script), which
#      run_benchmark.sh picks up by itself. authd's defaults apply: 30 days,
#      unlimited uses.
#
# <use_password> and etc/authd.pass are left exactly as installed: the token
# bearer is verified in every mode, so a benchmark now runs against the same
# enrollment policy a production manager has (issue #39054).
#
# --open-1515 additionally does the OLD flip -- <use_password>no</use_password>
# and removing etc/authd.pass -- which the legacy bootstrap needs, since the
# 1515 protocol carries no credential:
#   sudo ./prepare_manager.sh --open-1515
#   ./run_benchmark.sh --scenario ... --mode agent --bootstrap 1515
# That is for comparing the two first-contact paths on one manager. It opens
# unauthenticated enrollment to anything that can reach port 1515, and a later
# run WITHOUT the flag does not undo it: put <use_password> back by hand (the
# one-time .bak next to the config has the original) when done comparing.
#
# The mint is checked against the running listener certificate (authd 9025), so
# --address must be one of its SANs; the default is read from the certificate
# itself. --no-mint skips it (an --open-1515-only preparation, or a token you
# already have).
#
# It is idempotent: re-running it converges to the same block and mints a fresh
# token. It edits the config in place (a .bak is written once) and restarts the
# manager unless --no-restart is given.
#
# Usage:
#   sudo ./prepare_manager.sh [--conf PATH] [--max-agents N] [--address HOST]
#                             [--token-file PATH] [--no-mint] [--open-1515]
#                             [--no-restart]
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="/var/wazuh-manager/etc/wazuh-manager.conf"
MAX_AGENTS=""
RESTART=true
OPEN_1515=false
MINT=true
ADDRESS=""
TOKEN_FILE="$SCRIPT_DIR/.enrollment_token"
PYTHON="${PYTHON:-python3}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --conf)        CONF="$2"; shift 2 ;;
        --max-agents)  MAX_AGENTS="$2"; shift 2 ;;
        --address)     ADDRESS="$2"; shift 2 ;;
        --token-file)  TOKEN_FILE="$2"; shift 2 ;;
        --no-mint)     MINT=false; shift ;;
        --open-1515)   OPEN_1515=true; shift ;;
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

# The manager's home, and therefore its binaries, follow the config: --conf
# pointing into a sandbox install must not drive /var/wazuh-manager's daemons.
WAZUH_HOME="$(dirname "$(dirname "$CONF")")"
CONTROL="$WAZUH_HOME/bin/wazuh-manager-control"
AUTHD="$WAZUH_HOME/bin/wazuh-manager-authd"

echo "Configuring reachable remote enrollment in $CONF ..."
MAX_AGENTS="$MAX_AGENTS" OPEN_1515="$OPEN_1515" "$PYTHON" - "$CONF" <<'PY'
import os, re, sys

path = sys.argv[1]
max_agents = os.environ.get("MAX_AGENTS", "").strip()
open_1515 = os.environ.get("OPEN_1515", "") == "true"
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
if max_agents:
    new_block = set_child(new_block, "max_agents", max_agents)
# use_password is otherwise NOT touched: the enrollment-token bootstrap works
# whatever it says, and a benchmark should not soften the manager it measures.
if open_1515:
    new_block = set_child(new_block, "use_password", "no")

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

if $OPEN_1515; then
    echo "  --open-1515: use_password=no (unauthenticated enrollment on port 1515 is now open)"
    PASS_FILE="$(dirname "$CONF")/authd.pass"
    if [[ -f "$PASS_FILE" ]]; then
        rm -f "$PASS_FILE"
        echo "  removed $PASS_FILE"
    fi
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

# ---------------------------------------------------------------------------
# The fleet's enrollment token.
# ---------------------------------------------------------------------------
if ! $MINT; then
    echo "Not minting an enrollment token (--no-mint)."
    echo "Done."
    exit 0
fi

# <remote><https><certificate>, scoped to the <https> block, relative to the home.
listener_cert() {
    local cert
    cert="$(sed -n '/<https>/,/<\/https>/p' "$CONF" 2>/dev/null \
        | sed -n "s:.*<certificate>\(.*\)</certificate>.*:\1:p" | head -1)" || true
    [[ -n "$cert" ]] || cert="etc/certs/remoted.pem"
    [[ "$cert" == /* ]] || cert="$WAZUH_HOME/$cert"
    printf '%s\n' "$cert"
}

# A name the listener certificate actually carries: authd refuses to mint for an
# address that is not one of its SANs, because an agent has nothing else to
# verify the manager against. Prefer a DNS name over loopback, then any DNS
# name, then an IP literal (which authd accepts with a warning).
cert_san_address() {
    local cert="$1" sans found
    command -v openssl >/dev/null 2>&1 || return 0
    [[ -r "$cert" ]] || return 0
    sans="$(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null \
        | tr ',' '\n' | sed 's/^[[:space:]]*//')" || return 0
    found="$(printf '%s\n' "$sans" | sed -n 's/^DNS://p' | grep -vx 'localhost' | head -1)" || true
    [[ -n "$found" ]] || found="$(printf '%s\n' "$sans" | sed -n 's/^DNS://p' | head -1)" || true
    [[ -n "$found" ]] || found="$(printf '%s\n' "$sans" | sed -n 's/^IP Address://p' | head -1)" || true
    printf '%s\n' "$found"
}

CERT="$(listener_cert)"
if [[ -z "$ADDRESS" ]]; then
    ADDRESS="$(cert_san_address "$CERT")" || true
    if [[ -z "$ADDRESS" ]]; then
        echo "Error: could not read an address from the listener certificate $CERT." >&2
        echo "  Pass --address with one of its subject alternative names (authd refuses to mint" >&2
        echo "  a token for an address the certificate does not name), or --no-mint and supply" >&2
        echo "  the token yourself with run_benchmark.sh --enroll-token-file." >&2
        exit 1
    fi
    echo "Token address not given; using '$ADDRESS' from $CERT"
fi

if [[ ! -x "$AUTHD" ]]; then
    echo "Error: $AUTHD not found; cannot mint the fleet's enrollment token." >&2
    exit 1
fi

# The CLI prints the token alone on stdout and its id, endpoint and expiry on
# stderr, and it talks to the RUNNING daemon over its local socket -- so after a
# restart, wait for that socket instead of racing it. Without a restart there is
# nothing to wait for: if authd is not up, the mint should say so at once.
if $RESTART; then
    SOCK="$WAZUH_HOME/queue/sockets/auth.sock"
    for _ in $(seq 1 30); do
        [[ -S "$SOCK" ]] && break
        sleep 1
    done
fi

echo "Minting the fleet's enrollment token (--address $ADDRESS) ..."
MINT_ERR="$(mktemp)"
trap 'rm -f "$MINT_ERR"' EXIT
if ! TOKEN="$("$AUTHD" --create-enrollment-token --address "$ADDRESS" \
        --description "manager_benchmark" 2>"$MINT_ERR")"; then
    cat "$MINT_ERR" >&2
    echo "Error: could not mint an enrollment token." >&2
    echo "  A '9025' names the reason: --address must be a subject alternative name of" >&2
    echo "  $CERT, that certificate must name something other than loopback, and" >&2
    echo "  <remote><https><ca_certificate> must have signed it. Minting is master-only." >&2
    exit 1
fi
sed 's/^/  /' "$MINT_ERR"

umask 077
printf '%s\n' "$TOKEN" > "$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"
# Written as root, read by the (unprivileged) benchmark run.
if [[ -n "${SUDO_USER:-}" ]] && ! chown "$SUDO_USER" "$TOKEN_FILE"; then
    echo "  note: could not hand $TOKEN_FILE to $SUDO_USER; read it as root" >&2
fi
echo "  token written to $TOKEN_FILE (mode 600)"
echo ""
echo "run_benchmark.sh reads that file by itself. To use it elsewhere:"
echo "  export WAZUH_ENROLLMENT_TOKEN=\"\$(cat $TOKEN_FILE)\""
echo "Revoke it when done: $AUTHD --list-enrollment-tokens / --revoke-enrollment-token <id>"
echo "Done."
