#!/bin/bash
# Sets up the whole lab in one command, idempotently. Run it again any time; it is safe.
#
#   ./setup_lab.sh                 set up, reusing existing certificates
#   ./setup_lab.sh --regenerate    throw the certificates away and start a fresh CA
#
# WHY THIS EXISTS: the steps are individually simple but there is one trap that is easy to fall
# into twice. Regenerating the certificates creates a NEW CA, which silently invalidates the
# certificate already installed in the manager and the one baked into node 2. Everything then
# fails with 502 (NGINX refuses to validate the backend) and TLS alerts (the manager refuses the
# agent certificate), and the cause is nowhere near the symptom. This script always reinstalls
# every certificate from the current PKI, so that cannot happen.
#
# What it does:
#   1. certificates (generated only if missing, or always with --regenerate)
#   2. installs the node-1 certificate into the manager and restarts its remoted
#   3. makes sure a test agent exists in client.keys
#   4. builds node 2 (remoted only, ~3 MB) with the matching certificate
#   5. starts NGINX with the both_topologies scenario
#
# It does NOT start node 1's wazuh-db and engine: those belong to your installed manager and you
# may already be running them. It checks and tells you if they are missing.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
MANAGER=/var/wazuh-manager
# Resolves MANAGER_CERT_REL / MANAGER_KEY_REL / LAB_CA_REL from the manager's own configuration
# instead of hardcoding names that have already been renamed once. See the file for the details.
MANAGER_HOME="$MANAGER"
source "$HERE/lib_manager_paths.sh"
REGENERATE=no
[[ "${1:-}" == "--regenerate" ]] && REGENERATE=yes

echo "=== 1. certificates ==="
if [[ "$REGENERATE" == "yes" || ! -f "$HERE/certs/ca.crt" ]]; then
    "$HERE/generate_test_certificates.sh" >/dev/null
    echo "    fresh PKI generated in certs/"
else
    echo "    reusing the existing PKI in certs/  (use --regenerate for a fresh one)"
fi

echo "=== 2. backup of the manager files this lab modifies ==="
mkdir -p "$HERE/backup"
# The CA is included because a previous setup (manual or an older lab) may have left one that the
# config references: without a backup, cleanup.sh cannot know whether the CA was the lab's own or
# pre-existing, and restoring a config whose <ca> file is gone leaves remoted unable to start
# (load_verify_file). Backups are keyed by basename, so they follow whatever the config names.
for rel in "$MANAGER_CERT_REL" "$MANAGER_KEY_REL" "$LAB_CA_REL" etc/wazuh-manager.conf; do
    name="$(basename "$rel")"
    if [[ ! -f "$HERE/backup/$name" && -f "$MANAGER/$rel" ]]; then
        cp -a "$MANAGER/$rel" "$HERE/backup/$name"
        echo "    saved $rel"
    fi
done
[[ -z "$(ls -A "$HERE/backup" 2>/dev/null)" ]] || echo "    backup/ already populated, left untouched"

echo "=== 3. installing the node-1 certificate into the manager ==="
echo "    into $MANAGER_CERT_REL (as the manager's configuration names it)"
# Always reinstalled, so the manager can never be left on a stale CA.
for rel in "$MANAGER_CERT_REL" "$MANAGER_KEY_REL" "$LAB_CA_REL"; do
    ensure_parent_dir "$MANAGER/$rel"
done
cp "$HERE/certs/manager_node1.crt" "$MANAGER/$MANAGER_CERT_REL"
cp "$HERE/certs/manager_node1.key" "$MANAGER/$MANAGER_KEY_REL"
cp "$HERE/certs/ca.crt"            "$MANAGER/$LAB_CA_REL"
chown wazuh-manager:wazuh-manager "$MANAGER/$MANAGER_CERT_REL" \
      "$MANAGER/$MANAGER_KEY_REL" "$MANAGER/$LAB_CA_REL"
chmod 640 "$MANAGER/$MANAGER_CERT_REL" "$MANAGER/$MANAGER_KEY_REL" "$MANAGER/$LAB_CA_REL"
echo "    $(openssl x509 -in "$MANAGER/$MANAGER_CERT_REL" -noout -subject | sed 's/.*CN *= *//') installed"

echo "=== 4. test agent in client.keys ==="
if [[ ! -s "$MANAGER/etc/client.keys" ]]; then
    printf '1001 lab-agent any %s\n' "$(openssl rand -hex 32)" > "$MANAGER/etc/client.keys"
    chown root:wazuh-manager "$MANAGER/etc/client.keys"
    chmod 660 "$MANAGER/etc/client.keys"
    echo "    agent 1001 created"
else
    echo "    already has $(grep -c . "$MANAGER/etc/client.keys") agent(s), left untouched"
fi

echo "=== 5. node 1: are wazuh-db and the engine running? ==="
missing=()
for daemon in db analysisd; do
    pgrep -f "$MANAGER/bin/wazuh-manager-$daemon" >/dev/null || missing+=("$daemon")
done
if [[ ${#missing[@]} -gt 0 ]]; then
    echo "    !! not running: ${missing[*]}"
    echo "    !! start them (in this order) or /stateless will answer 503 instead of 202:"
    echo "         $MANAGER/bin/wazuh-manager-db"
    echo "         $MANAGER/bin/wazuh-manager-analysisd    # this IS the engine"
else
    echo "    wazuh-db and the engine (analysisd) are running"
fi

echo "=== 6. restarting node 1's remoted to pick up the certificate ==="
"$HERE/set_manager_verification_mode.sh" none | sed 's/^/    /' | tail -2

echo "=== 7. node 2 (remoted only, answers 503 when the signature is accepted) ==="
"$HERE/add_second_manager.sh" 2>&1 | tail -3 | sed 's/^/    /'

echo "=== 8. load balancer ==="
"$HERE/start_load_balancer.sh" both_topologies | sed 's/^/    /'

echo
echo "=== ready. Verify with: ==="
echo "    ./run_issue_checks.sh          runs every check and reports PASS/FAIL"
echo "    ./send_signed_request.py       one request straight to node 1 -> 202"
