# shellcheck shell=bash
# ---------------------------------------------------------------------------
# indexer_credentials.sh — how the benchmark scripts reach the indexer. Sourced, never run.
#
# There is no default credential (no admin:admin) and no silent `-k`: credentials are per package
# (docs/ref/getting-started/credentials.md), so a missing one is an error, not a guess.
#
# indexer_resolve_credentials -> sets INDEXER_USER / INDEXER_PASSWORD, or explains and returns 1:
#   1. INDEXER_USER + INDEXER_PASSWORD (or INDEXER_PASS) from the environment, both or neither;
#   2. else the admin password, key WAZUH_INDEXER_ADMIN_PASSWORD (user `admin`), parsed -- never
#      sourced -- from INDEXER_CREDENTIALS_FILE when set (and then from that file only), else from
#      the first readable of: the e2e stack's tools/devContainer/e2e/.credentials.env next to this
#      checkout and the indexer package's /etc/wazuh-indexer/export/credentials.env (root-only).
# indexer_resolve_tls -> sets INDEXER_TLS_ARGS (curl arguments), or explains and returns 1:
#   INDEXER_INSECURE=1 -> `-k` (only when the operator asks for it, with a warning);
#   else --cacert INDEXER_CACERT, else the <indexer><ssl><certificate_authorities><ca> of the
#   manager's config (WAZUH_MANAGER_CONF), else /etc/wazuh-manager/certs/indexer-ca.pem; the CA
#   must be readable.
# indexer_conf_url -> the first <indexer><hosts><host> of the manager's config, or nothing.
# Nothing here prints a password.
# ---------------------------------------------------------------------------

INDEXER_CRED_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INDEXER_DEFAULT_CACERT="/etc/wazuh-manager/certs/indexer-ca.pem"
INDEXER_PUBLISHED_ENV="/etc/wazuh-indexer/export/credentials.env"

# _indexer_conf_value url|ca: the first <hosts><host> or <ssl><certificate_authorities><ca> of <indexer>.
_indexer_conf_value() {
    local conf="${WAZUH_MANAGER_CONF:-/etc/wazuh-manager/wazuh-manager.conf}"
    [[ -r "$conf" ]] || return 0
    "${PYTHON:-python3}" -I -c '
import sys, xml.etree.ElementTree as ET
try:
    root = ET.parse(sys.argv[1]).getroot()
except Exception:
    sys.exit(0)
idx = root if root.tag == "indexer" else root.find(".//indexer")
if idx is None:
    sys.exit(0)
node = idx.find("./hosts/host") if sys.argv[2] == "url" else idx.find("./ssl/certificate_authorities/ca")
value = (node.text or "").strip() if node is not None else ""
if value and sys.argv[2] == "url" and "://" not in value:
    value = "https://" + value
if value:
    print(value)
' "$conf" "$1" 2>/dev/null
}

indexer_conf_url() { _indexer_conf_value url; }

indexer_resolve_credentials() {
    local pass="${INDEXER_PASSWORD:-${INDEXER_PASS:-}}" f v files=() unreadable=()
    if [[ -n "${INDEXER_USER:-}" || -n "$pass" ]]; then
        if [[ -z "${INDEXER_USER:-}" || -z "$pass" ]]; then
            echo "Error: set both INDEXER_USER and INDEXER_PASSWORD (or neither, to read a credentials file)." >&2
            return 1
        fi
        INDEXER_PASSWORD="$pass"
        return 0
    fi
    if [[ -n "${INDEXER_CREDENTIALS_FILE:-}" ]]; then
        files=("$INDEXER_CREDENTIALS_FILE")
    else
        files=("$INDEXER_CRED_LIB_DIR/../devContainer/e2e/.credentials.env" "$INDEXER_PUBLISHED_ENV")
    fi
    for f in "${files[@]}"; do
        [[ -e "$f" ]] || continue
        [[ -r "$f" ]] || { unreadable+=("$f"); continue; }
        # Parse the line (split at the first '='; the value may hold '='); the file is never sourced.
        v="$(sed -n 's/^WAZUH_INDEXER_ADMIN_PASSWORD=//p' "$f" | head -1)"
        v="${v%\"}"; v="${v#\"}"
        if [[ -n "$v" ]]; then
            INDEXER_USER="admin"
            INDEXER_PASSWORD="$v"
            return 0
        fi
    done
    echo "Error: no indexer credentials (there is no default)." >&2
    echo "  Set INDEXER_USER and INDEXER_PASSWORD, or INDEXER_CREDENTIALS_FILE to a file with a" >&2
    echo "  WAZUH_INDEXER_ADMIN_PASSWORD= line. Looked in: ${files[*]}" >&2
    [[ ${#unreadable[@]} -eq 0 ]] || echo "  Not readable by this user (root-only?): ${unreadable[*]}" >&2
    return 1
}

indexer_resolve_tls() {
    local ca
    case "${INDEXER_INSECURE:-}" in
        1|true|yes)
            echo "Warning: INDEXER_INSECURE set: the indexer's certificate is NOT verified (-k)." >&2
            INDEXER_TLS_ARGS=(-k)
            return 0 ;;
    esac
    ca="${INDEXER_CACERT:-}"
    [[ -n "$ca" ]] || ca="$(_indexer_conf_value ca)"
    [[ -n "$ca" ]] || ca="$INDEXER_DEFAULT_CACERT"
    if [[ ! -r "$ca" ]]; then
        echo "Error: the indexer CA $ca is not readable (set INDEXER_CACERT, or INDEXER_INSECURE=1 to skip" >&2
        echo "  the verification on purpose)." >&2
        return 1
    fi
    INDEXER_CACERT="$ca"
    INDEXER_TLS_ARGS=(--cacert "$ca")
}

# The curl config line carrying the credentials (for `curl -K -`: never in argv, /proc/*/cmdline).
indexer_curl_user_line() {
    local u="${INDEXER_USER}:${INDEXER_PASSWORD}"
    u="${u//\\/\\\\}"; u="${u//\"/\\\"}"
    printf 'user = "%s"\n' "$u"
}
