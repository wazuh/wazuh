#!/bin/bash
# Shared resolution of the manager files this lab writes into. Sourced, never executed.
#
# WHY THIS EXISTS: the default location of remoted's HTTPS certificate has already been renamed
# once (etc/https-manager.cert -> etc/certs/remoted.pem). Hardcoding either name breaks the lab
# the moment the manager uses the other one, and it breaks in the worst possible way: the
# certificates land where remoted does not look, the listener comes up with the certificate the
# installer generated instead, and every failure shows up one hop away from its cause -- 502 at
# the proxy (it cannot validate the backend), TLS alerts at the backend (it refuses the agent
# certificate). So the paths are read from the manager's own configuration, and the current
# defaults are used only when the option is absent.
#
# Sets these paths RELATIVE to the manager home, which is how remoted itself reads them (it
# chroots into that directory):
#   MANAGER_CERT_REL   remoted's server certificate
#   MANAGER_KEY_REL    its private key
#   LAB_CA_REL         the CA this lab installs (see the note below on why it is not root-ca.pem)

MANAGER_HOME="${MANAGER_HOME:-/var/wazuh-manager}"
MANAGER_CONF="$MANAGER_HOME/etc/wazuh-manager.yml"
MCONF="$MANAGER_HOME/bin/wazuh-manager-conf"

# Prints one remote.https option of the manager configuration (etc/wazuh-manager.yml) as the
# manager itself resolves it -- defaults applied -- through its own CLI; empty if unset or if the
# CLI/file is missing.
read_https_option() {
    local option="$1"
    [[ -f "$MANAGER_CONF" && -x "$MCONF" ]] || return 1
    "$MCONF" -H "$MANAGER_HOME" --skip-file-checks get "remote.https.${option}" 2>/dev/null || true
}

# The manager's own Python ships PyYAML; the system one may not.
manager_python() {
    if [[ -x "$MANAGER_HOME/framework/python/bin/python3" ]]; then
        echo "$MANAGER_HOME/framework/python/bin/python3"
    else
        echo python3
    fi
}

# set_https_options key=value [key=value ...]: sets (or, with the value '-', removes) options of
# remote.https in the manager configuration. Deliberately NOT validated: the lab writes invalid
# values on purpose to check that remoted refuses them at start-up ('wazuh-manager-conf validate'
# names the offending option with its JSON pointer).
set_https_options() {
    "$(manager_python)" - "$MANAGER_CONF" "$@" <<'PYTHON'
import sys
import yaml

path, assignments = sys.argv[1], sys.argv[2:]
with open(path) as handle:
    document = yaml.safe_load(handle) or {}
https = document.setdefault('remote', {}).setdefault('https', {})
for assignment in assignments:
    key, _, value = assignment.partition('=')
    if value == '-':
        https.pop(key, None)
    else:
        https[key] = value
with open(path, 'w') as handle:
    yaml.safe_dump(document, handle, sort_keys=False, default_flow_style=False)
PYTHON
}

# Prints the remote.https mapping as written in the file (not the effective one: the value may be
# invalid on purpose).
show_https() {
    "$(manager_python)" - "$MANAGER_CONF" <<'PYTHON'
import sys
import yaml

with open(sys.argv[1]) as handle:
    document = yaml.safe_load(handle) or {}
print(yaml.safe_dump({'https': document.get('remote', {}).get('https', {})}, sort_keys=False, default_flow_style=False), end='')
PYTHON
}

MANAGER_CERT_REL="$(read_https_option certificate || true)"
MANAGER_KEY_REL="$(read_https_option key || true)"
[[ -n "$MANAGER_CERT_REL" ]] || MANAGER_CERT_REL=etc/certs/remoted.pem
[[ -n "$MANAGER_KEY_REL"  ]] || MANAGER_KEY_REL=etc/certs/remoted-key.pem

# The CA is deliberately a file of the lab's own, NOT etc/certs/root-ca.pem, even though that is
# remoted's default ca_path: the same name is the indexer connector's CA in the shipped templates
# (etc/templates/config/generic/manager/indexer.yml.template), so overwriting it with this
# lab's throwaway CA would silently break the manager's connection to the indexer.
LAB_CA_REL=etc/certs/lab-ca.pem

# ensure_parent_dir <absolute file path>: creates the containing directory if it is missing,
# with the same owner and mode the installer gives etc/certs.
ensure_parent_dir() {
    local dir
    dir="$(dirname "$1")"
    [[ -d "$dir" ]] || install -d -m 1770 -o root -g wazuh-manager "$dir"
}
