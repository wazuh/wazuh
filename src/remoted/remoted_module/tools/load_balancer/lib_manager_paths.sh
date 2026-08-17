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

# Prints one <remote><https> option from the manager configuration, empty if unset.
read_https_option() {
    local option="$1" config="$MANAGER_HOME/etc/wazuh-manager.conf"
    [[ -f "$config" ]] || return 1
    sed -n "/<https>/,/<\/https>/{s|.*<${option}>\(.*\)</${option}>.*|\1|p;}" "$config" | head -1
}

MANAGER_CERT_REL="$(read_https_option certificate || true)"
MANAGER_KEY_REL="$(read_https_option key || true)"
[[ -n "$MANAGER_CERT_REL" ]] || MANAGER_CERT_REL=etc/certs/remoted.pem
[[ -n "$MANAGER_KEY_REL"  ]] || MANAGER_KEY_REL=etc/certs/remoted-key.pem

# The CA is deliberately a file of the lab's own, NOT etc/certs/root-ca.pem, even though that is
# remoted's default ca_path: the same name is the indexer connector's CA in the shipped templates
# (etc/templates/config/generic/wodle-indexer.manager.template), so overwriting it with this
# lab's throwaway CA would silently break the manager's connection to the indexer.
LAB_CA_REL=etc/certs/lab-ca.pem

# ensure_parent_dir <absolute file path>: creates the containing directory if it is missing,
# with the same owner and mode the installer gives etc/certs.
ensure_parent_dir() {
    local dir
    dir="$(dirname "$1")"
    [[ -d "$dir" ]] || install -d -m 1770 -o root -g wazuh-manager "$dir"
}
