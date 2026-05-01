#!/usr/bin/env sh
# fix-dind.sh — Reconfigures Docker-in-Docker (DinD) to work with nftables.
#
# Modern Linux kernels (5.x+) default to nftables for packet filtering, but the
# Docker daemon shipped inside the devcontainer image still tries to use the legacy
# iptables backend via xtables. This mismatch causes container networking to fail
# silently. The fix consists of three steps:
#
#   1. Point the iptables/ip6tables alternatives at the nft-backed binaries so that
#      any tool calling "iptables" gets the nftables implementation transparently.
#   2. Write /etc/docker/daemon.json to tell dockerd itself to use the nftables
#      firewall backend instead of xtables.
#   3. Hard-restart the daemon (kill existing processes, clean up stale PID files,
#      relaunch) so the new configuration is picked up from a clean slate.
#
# The script is idempotent: running it multiple times is safe.
set -eu

# ── 1. Redirect iptables tooling to the nftables-backed binaries ──────────────
update-alternatives --set iptables  /usr/sbin/iptables-nft
update-alternatives --set ip6tables /usr/sbin/ip6tables-nft

# ── 2. Configure dockerd to use the nftables firewall backend ─────────────────
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'EOF'
{
  "firewall-backend": "nftables"
}
EOF

# ── 3. Restart dockerd from a clean state ────────────────────────────────────
# Kill any running daemon processes (|| true so the script does not abort when
# no process is found).
pkill dockerd     || true
pkill containerd  || true

# Remove stale PID files that would prevent a clean restart.
rm -f /run/docker*.pid      /var/run/docker*.pid
rm -f /run/containerd/*.pid /var/run/containerd/*.pid

# Launch dockerd in the background; redirect output to a log file for debugging.
nohup dockerd > /tmp/dockerd.log 2>&1 &

# ── 4. Wait until the daemon is ready ────────────────────────────────────────
# Poll docker info until the socket is responsive or the timeout is reached.
TIMEOUT=30
ELAPSED=0
printf 'Waiting for dockerd to be ready'
until docker info > /dev/null 2>&1; do
    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
        printf '\nERROR: dockerd did not become ready within %s seconds.\n' "$TIMEOUT" >&2
        printf 'Check /tmp/dockerd.log for details.\n' >&2
        exit 1
    fi
    printf '.'
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done
printf '\ndockerd is ready.\n'
