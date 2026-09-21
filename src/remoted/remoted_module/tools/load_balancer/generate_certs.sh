#!/usr/bin/env bash
# Issues the lab PKI with the installation assistant's wazuh-certs-tool.
#
# One invocation, because the tool takes the agent-facing address separately from the node
# list -- it belongs to no node:
#
#   --agent-san <address>   adds it to the listener certificate of EVERY manager node, which
#                           is what TLS passthrough needs: the agent dials the balancer but
#                           completes the handshake against whichever backend answers.
#   load_balancer:          a config.yml section that issues the proxy its own leaf from the
#                           same CA, which is what TLS termination needs.
#
# This lab exercises both models at once, so it asks for both.
#
# Point CERTS_TOOL at the assistant's built wazuh-certs-tool.sh. See
# docs/ref/modules/cluster/lb.md §8.2.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/certs"
TOOL="${CERTS_TOOL:-}"

if [[ -z "$TOOL" || ! -f "$TOOL" ]]; then
    cat >&2 <<'MSG'
Set CERTS_TOOL to the installation assistant's wazuh-certs-tool.sh, for example:

    git clone https://github.com/wazuh/wazuh-installation-assistant
    cd wazuh-installation-assistant && bash builder.sh -c
    CERTS_TOOL=$PWD/wazuh-certs-tool.sh ./generate_certs.sh

The lab needs a version that supports --agent-san and the load_balancer section.
MSG
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The names agents dial. Shared by every backend on purpose: that is the SAN rule passthrough
# imposes, and --agent-san is how the tool expresses it.
LB_NAMES=(wazuh-lb-haproxy wazuh-lb-nginx)

rm -rf "$OUT"; mkdir -p "$OUT"

cat > "$WORK/config.yml" <<'CONFIG'
nodes:
  indexer:
    - name: wazuh-indexer
      ip: "172.28.0.30"
      dns:
        - "wazuh-indexer"

  manager:
    - name: wazuh-master
      ip: "172.28.0.11"
      node_type: master
    - name: wazuh-worker1
      ip: "172.28.0.12"
      node_type: worker
    - name: wazuh-worker2
      ip: "172.28.0.13"
      node_type: worker

  dashboard:
    - name: dashboard
      ip: "172.28.0.40"

  # Only the TLS termination model uses this leaf: under termination the balancer is the
  # agent's TLS peer, so it needs a certificate from the CA the agents trust.
  load_balancer:
    - name: wazuh-lb
      dns:
        - "wazuh-lb-haproxy"
        - "wazuh-lb-nginx"
      ip:
        - "172.28.0.20"
CONFIG

echo "==> issuing the PKI"
# The tool reads config.yml from its OWN directory and writes wazuh-certificates/ there, so it
# is copied next to the configuration rather than invoked in place.
cp "$TOOL" "$WORK/wazuh-certs-tool.sh"
SAN_ARGS=()
for n in "${LB_NAMES[@]}"; do SAN_ARGS+=(--agent-san "$n"); done
( cd "$WORK" && bash wazuh-certs-tool.sh -A "${SAN_ARGS[@]}" ) >"$WORK/tool.log" 2>&1 || {
    echo "!! the tool failed:" >&2; tail -20 "$WORK/tool.log" >&2; exit 1; }
[[ -d "$WORK/wazuh-certificates" ]] || {
    echo "!! the tool produced no wazuh-certificates/ directory" >&2
    tail -20 "$WORK/tool.log" >&2; exit 1; }
mv "$WORK/wazuh-certificates" "$WORK/out"

install -m 644 "$WORK/out/root-ca.pem" "$OUT/root-ca.pem"
install -m 600 "$WORK/out/root-ca.key" "$OUT/root-ca.key"

for n in wazuh-master wazuh-worker1 wazuh-worker2 wazuh-lb; do
    mkdir -p "$OUT/$n"
    src="$WORK/out/$n-remoted.pem"; key="$WORK/out/$n-remoted-key.pem"
    # The load_balancer entry produces <name>.pem, not <name>-remoted.pem.
    [[ -f "$src" ]] || { src="$WORK/out/$n.pem"; key="$WORK/out/$n-key.pem"; }
    install -m 644 "$src" "$OUT/$n/node.pem"
    install -m 644 "$key" "$OUT/$n/node-key.pem"
    printf '  %-16s SAN %s\n' "$n" \
        "$(openssl x509 -in "$OUT/$n/node.pem" -noout -ext subjectAltName | tail -1 | tr -s ' ' | sed 's/^ //')"
done

# The indexer keeps the DNs opensearch.yml pins: CN=node-1 as nodes_dn, CN=admin as admin_dn.
mkdir -p "$OUT/../certs-indexer"
IDX="$(cd "$OUT/.." && pwd)/certs-indexer"
install -m 644 "$WORK/out/wazuh-indexer.pem"     "$IDX/indexer.pem"
install -m 644 "$WORK/out/wazuh-indexer-key.pem" "$IDX/indexer-key.pem"
install -m 644 "$WORK/out/admin.pem"             "$IDX/admin.pem"
install -m 644 "$WORK/out/admin-key.pem"         "$IDX/admin-key.pem"
install -m 644 "$OUT/root-ca.pem"                "$IDX/root-ca.pem"

echo "==> deliberately broken leaves, for the certificate failure drills"
# cert_drill.sh installs these on one node to measure what every front end reports. They are
# issued here rather than by hand so the drills the README documents actually run.
BAD="$(cd "$OUT/.." && pwd)/certs-bad"
rm -rf "$BAD"; mkdir -p "$BAD"

# 1. Expired: correct CA, correct SAN, but past its notAfter. Isolates the expiry check.
#    `openssl x509 -days` cannot backdate ("-days parameter arg must be >= -1") and the
#    -not_before/-not_after options only exist from OpenSSL 3.2, so this goes through
#    `openssl ca`, which takes explicit dates on every version the lab supports.
openssl req -newkey rsa:2048 -nodes -keyout "$BAD/expired-key.pem" \
    -subj "/CN=wazuh-master" -out "$WORK/exp.csr" 2>/dev/null
mkdir -p "$WORK/ca-db"; : > "$WORK/ca-db/index.txt"; echo 01 > "$WORK/ca-db/serial"
cat > "$WORK/ca.cnf" <<'EOF'
[ca]
default_ca = CA_default
[CA_default]
database      = $ENV::WORK/ca-db/index.txt
serial        = $ENV::WORK/ca-db/serial
new_certs_dir = $ENV::WORK/ca-db
default_md    = sha256
policy        = pol
email_in_dn   = no
rand_serial   = no
unique_subject = no
copy_extensions = none
x509_extensions = ext
[pol]
commonName = optional
[ext]
subjectAltName = DNS:wazuh-master,DNS:wazuh-lb-haproxy,DNS:wazuh-lb-nginx,IP:172.28.0.11
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EOF
WORK="$WORK" openssl ca -config "$WORK/ca.cnf" -cert "$OUT/root-ca.pem" -keyfile "$OUT/root-ca.key" \
    -in "$WORK/exp.csr" -out "$BAD/expired.pem" -notext -batch \
    -startdate "$(date -u -d '-400 days' '+%y%m%d%H%M%SZ')" \
    -enddate   "$(date -u -d '-30 days'  '+%y%m%d%H%M%SZ')" >/dev/null 2>&1 || {
    echo "!! could not issue the expired leaf" >&2; exit 1; }
# `openssl verify` exits non-zero here BY DESIGN -- the leaf must fail verification. Capture its
# output first: piping it straight into grep makes `set -o pipefail` report that intended failure
# and trips the guard on a correct certificate.
EXPVERIFY="$(openssl verify -CAfile "$OUT/root-ca.pem" "$BAD/expired.pem" 2>&1 || true)"
grep -q 'has expired' <<<"$EXPVERIFY" || {
    echo "!! the expired leaf is not actually expired:" >&2
    echo "$EXPVERIFY" >&2; exit 1; }
printf '  %-16s notAfter %s (in the past, on purpose)\n' "expired" \
    "$(openssl x509 -in "$BAD/expired.pem" -noout -enddate | cut -d= -f2)"

# 2. Rogue CA: correct SAN and not expired, but signed by a CA the agents do not trust.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/rogue-ca-key.pem" \
    -out "$WORK/rogue-ca.pem" -days 3650 -subj "/CN=Rogue CA" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$BAD/rogue-key.pem" \
    -subj "/CN=wazuh-master" -out "$WORK/rogue.csr" 2>/dev/null
cat > "$WORK/rogue.cnf" <<'EOF'
subjectAltName=DNS:wazuh-master,DNS:wazuh-lb-haproxy,DNS:wazuh-lb-nginx,IP:172.28.0.11
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in "$WORK/rogue.csr" -CA "$WORK/rogue-ca.pem" -CAkey "$WORK/rogue-ca-key.pem" \
    -CAcreateserial -extfile "$WORK/rogue.cnf" -days 3650 \
    -out "$BAD/rogue.pem" 2>/dev/null
openssl verify -CAfile "$OUT/root-ca.pem" "$BAD/rogue.pem" >/dev/null 2>&1 && {
    echo "!! the rogue leaf verifies against the lab CA; it must not" >&2; exit 1; }
printf '  %-16s issuer %s\n' "rogue" \
    "$(openssl x509 -in "$BAD/rogue.pem" -noout -issuer | sed 's/^issuer=//')"
chmod -R a+rX "$BAD"

echo "==> a deliberately wrong leaf, for the SAN-mismatch drill"
mkdir -p "$OUT/wazuh-badsan"
openssl req -newkey rsa:2048 -nodes -keyout "$OUT/wazuh-badsan/node-key.pem" \
    -subj "/CN=wazuh-badsan" -out "$WORK/bad.csr" 2>/dev/null
cat > "$WORK/bad.cnf" <<'EOF'
subjectAltName=DNS:not-the-balancer,IP:10.99.99.99
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in "$WORK/bad.csr" -CA "$OUT/root-ca.pem" -CAkey "$OUT/root-ca.key" \
    -CAcreateserial -extfile "$WORK/bad.cnf" -days 3650 \
    -out "$OUT/wazuh-badsan/node.pem" 2>/dev/null
echo "  wazuh-badsan     names nothing an agent dials, on purpose"

# A SEPARATE CA, standing in for the public or corporate one a real balancer fronts with. The
# :1519 frontend uses it to reproduce what GET /cacerts returns when the agent's TLS peer is not
# signed by the manager's CA. Without this the lab's HAProxy refuses to start.
echo "==> issuing the public-edge CA and balancer leaf"
PUB="$(cd "$OUT/.." && pwd)/certs-public"
rm -rf "$PUB"; mkdir -p "$PUB"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$PUB/public-ca-key.pem" \
    -out "$PUB/public-ca.pem" -days 3650 -subj "/CN=Public Edge CA" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$PUB/lb-key.pem" \
    -subj "/CN=wazuh-lb-haproxy" -out "$WORK/pub.csr" 2>/dev/null
cat > "$WORK/pub.cnf" <<'EOF'
subjectAltName=DNS:wazuh-lb-haproxy,DNS:wazuh-lb-nginx,DNS:localhost,IP:172.28.0.20
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in "$WORK/pub.csr" -CA "$PUB/public-ca.pem" -CAkey "$PUB/public-ca-key.pem" \
    -CAcreateserial -extfile "$WORK/pub.cnf" -days 3650 -out "$PUB/lb.pem" 2>/dev/null
cat "$PUB/lb.pem" "$PUB/lb-key.pem" > "$PUB/lb-bundle.pem"
chmod -R a+rX "$PUB"
echo "  public-ca        a CA the managers do NOT chain to, on purpose"

# Only the leaves under certs/ are expected to verify. certs-bad/ is broken on purpose and
# lives outside this directory precisely so this loop never sees it.
echo "==> verifying every leaf against the CA"
for d in "$OUT"/*/; do
    n="$(basename "$d")"
    if openssl verify -CAfile "$OUT/root-ca.pem" "$d/node.pem" >/dev/null 2>&1; then
        printf '  %-16s OK\n' "$n"
    else
        printf '  %-16s FAILED\n' "$n"; exit 1
    fi
done

cat "$OUT/wazuh-lb/node.pem" "$OUT/wazuh-lb/node-key.pem" > "$OUT/lb-bundle.pem"
chmod 644 "$OUT/lb-bundle.pem"
chmod -R a+rX "$OUT" "$IDX" "$PUB"
echo "==> PKI in $OUT"
