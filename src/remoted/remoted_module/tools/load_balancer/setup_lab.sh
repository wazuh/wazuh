#!/usr/bin/env bash
# Brings the whole lab up in one command, idempotently.
#
#   ./setup_lab.sh --packages /path/to/debs     stage packages, build images, start everything
#   ./setup_lab.sh                              reuse already-staged packages
#   ./setup_lab.sh --regenerate                 throw the PKI away and issue a fresh one
#
# Expects three .deb files in the directory given to --packages:
#   wazuh-manager_*.deb   wazuh-agent_*.deb   wazuh-indexer_*.deb
#
# ALWAYS CHECK THE PACKAGE CARRIES WHAT YOU INTEND TO MEASURE. A build older than the
# feature under test answers as if the defect did not exist, which is worse than failing.
# This script performs that check and refuses to continue when it does not hold.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PKGDIR=""
REGENERATE=no

while [[ $# -gt 0 ]]; do
    case "$1" in
        --packages) PKGDIR="$2"; shift 2 ;;
        --regenerate) REGENERATE=yes; shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

stage_package() {
    local glob="$1" dest="$2"
    local found
    found="$(find "$PKGDIR" -maxdepth 1 -name "$glob" | sort | tail -1)"
    [[ -n "$found" ]] || { echo "!! no $glob in $PKGDIR" >&2; exit 1; }
    install -m 644 "$found" "$dest"
    echo "    $(basename "$found") -> ${dest#$HERE/}"
}

if [[ -n "$PKGDIR" ]]; then
    echo "==> staging packages from $PKGDIR"
    stage_package 'wazuh-manager_*.deb' "$HERE/base/manager/wazuh-manager.deb"
    stage_package 'wazuh-agent_*.deb'   "$HERE/base/agent5/wazuh-agent.deb"
    stage_package 'wazuh-indexer_*.deb' "$HERE/base/indexer/wazuh-indexer.deb"
fi

for p in base/manager/wazuh-manager.deb base/agent5/wazuh-agent.deb base/indexer/wazuh-indexer.deb; do
    [[ -f "$HERE/$p" ]] || { echo "!! missing $p; run with --packages <dir>" >&2; exit 1; }
done

echo "==> verifying the manager package carries the features under test"
TMPCHK="$(mktemp -d)"; trap 'rm -rf "$TMPCHK"' EXIT
dpkg -x "$HERE/base/manager/wazuh-manager.deb" "$TMPCHK"
fail=0
# grep -c, not grep -q: with `set -o pipefail` a -q that exits early SIGPIPEs the producer
# and the pipeline reports 141, so every valid package would be rejected.
if [[ "$(strings "$TMPCHK/var/wazuh-manager/lib/libremoted_module.so" 2>/dev/null |
         grep -c expectedSelectorFor || true)" -eq 0 ]]; then
    echo "    !! no /download registry authorization in this build" >&2; fail=1
fi
if [[ "$(grep -c '"ca_certificate"' \
         "$TMPCHK/var/wazuh-manager/etc/wazuh-manager.schema.json" 2>/dev/null || true)" -eq 0 ]]; then
    echo "    !! no remote.https.ca_certificate in this build's schema" >&2; fail=1
fi
[[ $fail -eq 0 ]] || { echo "    the package predates what this lab measures; use a newer one" >&2; exit 1; }
echo "    ok"

echo "==> PKI"
PKI_CHANGED=no
if [[ "$REGENERATE" == "yes" || ! -f "$HERE/certs/root-ca.pem" ]]; then
    "$HERE/generate_certs.sh"
    PKI_CHANGED=yes
else
    echo "    reusing certs/ (use --regenerate for a fresh CA)"
fi

echo "==> building images"
docker build -q -t lab-wazuh-manager:deb "$HERE/base/manager" >/dev/null
docker build -q -t lab-agent5:branch     "$HERE/base/agent5"  >/dev/null
docker build -q -t lab-agent4:4.14.1     "$HERE/base/agent4"  >/dev/null
docker build -q -t lab-indexer:5.0.0     "$HERE/base/indexer" >/dev/null
docker build -q -t lab-probe:1           "$HERE/base/probe"   >/dev/null
echo "    done"

echo "==> starting the cluster, the balancers and the agents"
docker compose --project-directory "$HERE" up -d >/dev/null

# HAProxy and NGINX read their TLS certificate ONCE, at startup, and the lab bind-mounts it.
# `docker compose up` leaves them running because neither image nor service definition changed,
# so a regenerated PKI would leave both balancers serving the PREVIOUS leaf while every file on
# disk says otherwise -- every terminating front end then fails verification and the cause is
# invisible. The managers do not need this: their entrypoint reinstalls from the mount on boot.
if [[ "$PKI_CHANGED" == "yes" ]]; then
    echo "    PKI changed: recreating the balancers so they load it"
    docker compose --project-directory "$HERE" up -d --force-recreate \
        wazuh-lb-haproxy wazuh-lb-nginx >/dev/null
fi

echo "==> waiting for the cluster to form"
until docker exec wazuh-master /var/wazuh-manager/bin/cluster_control -l 2>/dev/null | grep -q worker1; do
    sleep 5
done
docker exec wazuh-master /var/wazuh-manager/bin/cluster_control -l | sed 's/^/    /'

# The probe imports wire_jwt.py from the parent tools/ directory rather than carrying a copy,
# so the lab only works from its place in the repository. Say so instead of mounting an empty
# directory and failing later with an import error.
if [[ ! -f "$HERE/../wire_jwt.py" ]]; then
    echo "!! $HERE/../wire_jwt.py not found." >&2
    echo "   This lab must run from src/remoted/remoted_module/tools/load_balancer/, where the" >&2
    echo "   probe scripts import the repository's own signer from ../ instead of duplicating it." >&2
    exit 1
fi

echo "==> starting the probe (mounts the repository's own agent tools from ../)"
docker rm -f lab-probe >/dev/null 2>&1 || true
docker run -d --name lab-probe --network "$(basename "$HERE")_lab" --ip 172.28.0.50 \
    -v "$HERE/probe:/probe" -v "$HERE/../:/tools:ro" \
    -v "$HERE/certs:/certs:ro" -v "$HERE/results:/results" \
    lab-probe:1 >/dev/null
echo "    lab-probe ready"

echo
echo "=== ready. Verify with: ==="
echo "    ./run_issue_checks.sh          every check, PASS/FAIL"
