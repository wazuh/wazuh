#!/usr/bin/env bash
# Builds a WPK signed by THIS LAB's CA, and points an agent's trust anchor at it.
#
# This exercises the whole upgrade chain for real -- task delivery, download through the
# balancer, signature verification, unpacking, installer execution -- without needing the
# Wazuh release signing key. What it does NOT exercise is the production signature path.
#
#   ./build_wpk.sh                 build wpk/lab-upgrade.wpk
#   ./build_wpk.sh --install       also stage it on every node and retarget wazuh-agent5-term
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WPKPACK="$HERE/../../../../../packages/wpk/wpkpack.py"
OUT="$HERE/wpk"

[[ -f "$HERE/certs/root-ca.pem" ]] || { echo "run ./generate_certs.sh first" >&2; exit 1; }
[[ -f "$WPKPACK" ]] || { echo "wpkpack.py not found at $WPKPACK" >&2; exit 1; }

mkdir -p "$OUT"
if [[ ! -f "$OUT/wpk-cert.pem" ]]; then
    echo "==> issuing a signing pair from the lab CA"
    openssl req -newkey rsa:2048 -nodes -keyout "$OUT/wpk-key.pem" \
        -subj "/CN=lab-wpk-signer" -out "$OUT/wpk.csr" 2>/dev/null
    openssl x509 -req -in "$OUT/wpk.csr" -CA "$HERE/certs/root-ca.pem" \
        -CAkey "$HERE/certs/root-ca.key" -CAcreateserial -days 3650 \
        -out "$OUT/wpk-cert.pem" 2>/dev/null
fi

echo "==> packing (the installer must sit at the ROOT of the package)"
# A WPK whose upgrade.sh is nested under a directory fails on the agent with
# "(8134) Could not chmod 'var/upgrade/upgrade.sh'", which does not name the real cause.
( cd "$OUT" && python3 "$WPKPACK" lab-upgrade.wpk wpk-cert.pem wpk-key.pem upgrade.sh )
echo "    $OUT/lab-upgrade.wpk"

[[ "${1:-}" == "--install" ]] || exit 0

echo "==> staging on every manager node"
for n in wazuh-master wazuh-worker1 wazuh-worker2; do
    docker exec "$n" mkdir -p /var/wazuh-manager/var/upgrade
    docker cp "$OUT/lab-upgrade.wpk" "$n:/var/wazuh-manager/var/upgrade/lab-upgrade.wpk" >/dev/null
    docker exec "$n" chown -R wazuh-manager:wazuh-manager /var/wazuh-manager/var/upgrade
    echo "    $n"
done

echo "==> retargeting the agent's trust anchor at the lab CA"
docker cp "$HERE/certs/root-ca.pem" wazuh-agent5-term:/var/ossec/etc/wpk_root.pem >/dev/null
echo "    wazuh-agent5-term"
