#!/bin/bash
# Creates the certificates the load-balancer lab needs.
#
# WHY A PRIVATE CA IS NEEDED: the certificate the manager generates at install time has NO
# subjectAltName extension at all. Modern TLS clients require a SAN (the CN fallback was removed
# from the standard), so that certificate passes chain validation but FAILS hostname
# verification. Anything that verifies the hostname -- an agent doing the right thing, or NGINX
# with proxy_ssl_verify on -- cannot use it. Verify for yourself:
#
#     openssl x509 -in /var/wazuh-manager/etc/certs/remoted.pem -noout -ext subjectAltName
#         -> "No extensions in certificate"
#
# Produces, under ./certs:
#   ca.crt / ca.key                    the lab CA; signs everything else
#   load_balancer.crt / .key           what the AGENT validates under termination
#   manager_node1.crt / .key           remoted's server certificate on node 1
#   manager_node2.crt / .key           remoted's server certificate on node 2
#   agent.crt / .key                   the AGENT's client certificate (mTLS tests)
#   proxy_client.crt / .key            the client certificate NGINX presents to remoted
#
# Usage: ./generate_test_certificates.sh [output-directory]

set -euo pipefail

OUTPUT="${1:-$(cd "$(dirname "$0")" && pwd)/certs}"
mkdir -p "$OUTPUT"
cd "$OUTPUT"

VALID_DAYS=365

echo "==> lab CA"
openssl req -x509 -newkey rsa:2048 -nodes -days "$VALID_DAYS" \
    -keyout ca.key -out ca.crt \
    -subj "/C=ES/O=Wazuh remoted LB lab/CN=Wazuh remoted LB lab CA" 2>/dev/null

# $1 = file base name, $2 = common name, $3 = subjectAltName, $4 = extendedKeyUsage
generate_certificate() {
    local name="$1" common_name="$2" subject_alt_name="$3" key_usage="$4"
    echo "==> $name  (CN=$common_name, SAN=$subject_alt_name, EKU=$key_usage)"
    openssl req -newkey rsa:2048 -nodes \
        -keyout "${name}.key" -out "${name}.csr" \
        -subj "/C=ES/O=Wazuh remoted LB lab/CN=${common_name}" 2>/dev/null
    openssl x509 -req -in "${name}.csr" -days "$VALID_DAYS" \
        -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out "${name}.crt" \
        -extfile <(printf 'subjectAltName=%s\nextendedKeyUsage=%s\nbasicConstraints=CA:FALSE\n' \
                   "$subject_alt_name" "$key_usage") 2>/dev/null
    rm -f "${name}.csr"
}

# The load balancer's front end: agents connect here under termination, so the SAN must cover
# whatever name they use.
generate_certificate load_balancer "wazuh-lb.test" \
    "DNS:wazuh-lb.test,DNS:localhost,DNS:nginx,IP:127.0.0.1" serverAuth

# remoted's server certificates, one per node. The SAN must contain the name NGINX uses in
# proxy_ssl_name, or proxy_ssl_verify on will fail.
generate_certificate manager_node1 "manager_node1" "DNS:manager_node1,DNS:localhost,IP:127.0.0.1" serverAuth
generate_certificate manager_node2 "manager_node2" "DNS:manager_node2,DNS:localhost,IP:127.0.0.1" serverAuth

# The agent's client certificate. The IPs in the SAN are deliberate: verification_mode=full
# compares the peer's TCP address against them, so a client connecting from one of these
# addresses with this certificate is exactly the case that mode is supposed to accept.
generate_certificate agent "agent-1001" "IP:127.0.0.1,DNS:agent-1001" clientAuth

# The same agent, with a valid certificate signed by the same CA, whose SAN carries an address it
# is NOT connecting from. It is the control for the check above: verification_mode=certificate
# accepts it (the chain is good), verification_mode=full rejects it (the address is not there).
# Without this certificate a passing 'full' check proves nothing -- everything in this lab
# connects from 127.0.0.1, so a mode that accepted every certificate would look identical.
generate_certificate agent_wrong_ip "agent-1001" "IP:10.99.99.99,DNS:agent-1001" clientAuth


# The client certificate the proxy presents to remoted when remoted requires mTLS. Note this is
# the PROXY's identity, not any agent's -- which is the point of one of the findings.
generate_certificate proxy_client "lb-proxy" "DNS:lb-proxy,DNS:nginx-proxy,IP:127.0.0.1" clientAuth

# The proxy's certificate again, with an address the proxy does not connect from. Under
# verification_mode=full remoted compares the SAN against the address the CONNECTION came from,
# which under termination is the proxy's own -- so this is what a real deployment hits the moment
# the balancer's egress address is not the one in its certificate: a second balancer node, a new
# member of an autoscaling group, traffic leaving through a NAT address. Every agent then gets
# 403, however correct the agent's own certificate is.
generate_certificate proxy_client_wrong_ip "lb-proxy" "DNS:lb-proxy,IP:10.99.99.99" clientAuth

chmod 644 ./*.crt
chmod 640 ./*.key

# HAProxy wants the certificate and its key in ONE file, unlike NGINX which takes two separate
# directives. Same material, just concatenated -- so both proxies run off this one PKI instead of
# each needing its own, which is what makes the two sets of measurements comparable.
# World-readable on purpose: the haproxy container runs as a non-root user and must read them.
for name in load_balancer proxy_client; do
    cat "${name}.crt" "${name}.key" > "${name}.pem"
    chmod 644 "${name}.pem"
    echo "==> ${name}.pem  (cert+key combined, for haproxy)"
done

echo
echo "==> written to $OUTPUT"
echo
echo "SAN check (this is the field hostname verification reads):"
for name in load_balancer manager_node1 manager_node2 agent proxy_client; do
    printf '  %-15s ' "$name"
    openssl x509 -in "${name}.crt" -noout -ext subjectAltName 2>/dev/null | tail -1 | xargs
done
echo
echo "Next: install the node-1 certificate into the manager (see README.md, section 5)."
