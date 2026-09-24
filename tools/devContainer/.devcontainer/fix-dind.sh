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
#      firewall backend instead of xtables, and to use the cgroupfs cgroup driver:
#      without it dockerd picks the systemd driver as soon as /run/systemd/system
#      exists (the manager installer creates it), and in a container without
#      systemd no container starts after the next restart ("failed to connect to
#      dbus ... /run/systemd/private").
#   3. Hard-restart the daemon (kill existing processes, clean up stale PID files,
#      relaunch) so the new configuration is picked up from a clean slate.
#
# The script is idempotent: if daemon.json already asks for both settings and the
# RUNNING dockerd reports both (docker info), it exits without restarting it.
set -eu

# ── 1. Redirect iptables tooling to the nftables-backed binaries ──────────────
update-alternatives --set iptables  /usr/sbin/iptables-nft
update-alternatives --set ip6tables /usr/sbin/ip6tables-nft

# ── 2. Configure dockerd to use the nftables firewall backend ─────────────────
DAEMON_JSON=/etc/docker/daemon.json

# The file only states what was asked for: a run cut between writing it and the
# restart below leaves the old daemon answering. So the restart is skipped only
# when the running daemon itself reports both settings; a daemon that cannot
# report them (an older Docker without FirewallBackend in docker info) is restarted.
running_cgroup=$(docker info --format '{{.CgroupDriver}}' 2>/dev/null || true)
running_firewall=$(docker info --format '{{if .FirewallBackend}}{{.FirewallBackend.Driver}}{{end}}' 2>/dev/null || true)
if [ -f "$DAEMON_JSON" ] && grep -q '"firewall-backend"[[:space:]]*:[[:space:]]*"nftables"' "$DAEMON_JSON" \
   && grep -q 'native.cgroupdriver=cgroupfs' "$DAEMON_JSON" \
   && [ "$running_cgroup" = cgroupfs ] && [ "$running_firewall" = nftables ]; then
    echo "dockerd already running with the nftables firewall backend and the cgroupfs driver."
    exit 0
fi

mkdir -p /etc/docker
cat > "$DAEMON_JSON" <<'EOF'
{
  "firewall-backend": "nftables",
  "exec-opts": ["native.cgroupdriver=cgroupfs"]
}
EOF

# ── 3. Restart dockerd from a clean state ────────────────────────────────────
# Kill any running daemon processes (|| true so the script does not abort when
# no process is found).
pkill dockerd     || true
pkill containerd  || true
# Wait (up to 30 s) for the old daemon to exit: it takes a moment to shut down,
# and a new dockerd started while it still holds its socket can fail to start.
i=0
while pgrep -x dockerd > /dev/null 2>&1 && [ "$i" -lt 30 ]; do sleep 1; i=$((i + 1)); done

# Remove stale PID files that would prevent a clean restart.
rm -f /run/docker*.pid      /var/run/docker*.pid
rm -f /run/containerd/*.pid /var/run/containerd/*.pid

# Launch dockerd in the background; redirect output to a log file for debugging.
nohup dockerd > /tmp/dockerd.log 2>&1 &

# ── 4. Wait until the daemon is ready ────────────────────────────────────────
# Poll docker info until the socket is responsive or the timeout is reached.
TIMEOUT=90
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
