#!/bin/sh

# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
#
# Issues the manager's two TLS pairs, driven by resolve-credentials. Certificates follow the same
# resolution ladder as passwords, with two complications passwords do not have: a certificate can be
# generated successfully and still be wrong, and signing one locally means the CA private key is on
# that host.
#
# Which of the four cases applies is decided by the *contents of the CA directory*, not by a mode
# flag -- the presence of a private key beside the anchor is the signal, so a host that was never
# given one cannot sign and cannot be where a CA key leaks from:
#
#   A   nothing in the CA dir        -> mint a bootstrap CA, then issue both pairs from it
#   B   anchor + key                 -> issue both pairs from the CA found
#   C   anchor only, pair in place   -> install the anchor, generate nothing   (handled by the caller)
#   D   anchor only, no pair         -> install the anchor; unresolved, the service will not start
#
# A and B are one install run twice: the first package creates what the second finds.
#
# The manager needs *two* pairs, not one, and both must chain to the same anchor:
#
#   remoted.pem / remoted-key.pem                  the HTTPS agent listener on 1517, reused by authd
#                                                  on 1515. Opened AFTER the privilege drop, so it
#                                                  belongs to wazuh-manager.
#   indexer-connector.pem / -key.pem               the client certificate the manager presents to the
#                                                  indexer. Read as root, so root-owned: a daemon
#                                                  must not be able to replace its own trust material.
#
# root-ca.pem is installed as the manager's anchor for both, and is what remoted serves on
# GET /cacerts for agents to pin.
#
# The bootstrap CA minted in case A is local to this host and disposable. A host that minted its own
# and later joins a real cluster does not merge trust: the cluster's CA re-issues everything.

DIR=""

while [ -n "$1" ]; do
    case "$1" in
        -H) DIR="$2"; shift 2 ;;
        *)  shift ;;
    esac
done

[ -n "${DIR}" ] || DIR="/var/wazuh-manager"

CA_DIR="${WAZUH_CA_DIR:-/etc/wazuh/ca}"
CERTS_DIR="${DIR}/etc/certs"

CA_CERT="${CA_DIR}/root-ca.pem"
CA_KEY="${CA_DIR}/root-ca.key"

RSA_BITS=2048
DAYS=3650

log() {
    echo "mint-certs: $*"
}

err() {
    echo "mint-certs: $*" >&2
}

if ! command -v openssl >/dev/null 2>&1; then
    err "openssl is not available; cannot issue certificates"
    exit 1
fi

# -----------------------------------------------------------------------------------------
# Subject alternative names
#
# A certificate is only usable by the peers that reach this node through the names it carries, so
# getting this wrong produces a certificate that is valid, installs cleanly, and fails on the first
# peer connection -- possibly weeks later, because the pre-start step deliberately opens no
# connections. That is why the list is logged on every run.
# -----------------------------------------------------------------------------------------

derive_sans() {
    _ds_names="DNS:localhost"

    _ds_host=$(hostname 2>/dev/null)
    if [ -n "${_ds_host}" ]; then
        _ds_names="DNS:${_ds_host},${_ds_names}"
    else
        err "could not determine this host's name; the certificate will not carry one"
        err "set WAZUH_MANAGER_CERT_SANS if peers reach this node by name"
    fi

    _ds_fqdn=$(hostname -f 2>/dev/null)
    if [ -n "${_ds_fqdn}" ] && [ "${_ds_fqdn}" != "${_ds_host}" ]; then
        _ds_names="${_ds_names},DNS:${_ds_fqdn}"
    fi

    # Global addresses on default-route interfaces only. Without that filter a host running
    # containers advertises docker0, veth* and CNI addresses too, and link-local ranges are never
    # reachable by a peer.
    #
    # iproute2 is not a package dependency, because this is a heuristic and WAZUH_MANAGER_CERT_SANS
    # is the escape hatch when it guesses wrong. It is worth a warning rather than silence: a
    # certificate missing the address a peer connects to is valid, installs cleanly, and fails at
    # the first peer connection, possibly weeks later.
    if ! command -v ip >/dev/null 2>&1; then
        err "iproute2 is not installed, so no IP address could be derived for the certificate"
        err "set WAZUH_MANAGER_CERT_SANS if peers reach this node by address"
        printf '%s' "${_ds_names}"
        return 0
    fi

    _ds_ifaces=$(ip -o route show default 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | sort -u)
    _ds_found=""

    for _ds_if in ${_ds_ifaces}; do
        _ds_addrs=$(ip -o addr show dev "${_ds_if}" scope global 2>/dev/null \
            | sed -n 's/.* inet6\{0,1\} \([^ /]*\).*/\1/p')
        for _ds_a in ${_ds_addrs}; do
            case "${_ds_a}" in
                169.254.*|fe80:*) continue ;;
            esac
            _ds_names="${_ds_names},IP:${_ds_a}"
            _ds_found="yes"
        done
    done

    if [ -z "${_ds_found}" ]; then
        err "no global address on a default-route interface; the certificate will carry only loopback"
        err "set WAZUH_MANAGER_CERT_SANS if peers reach this node by address"
    fi

    printf '%s' "${_ds_names}"
}

# WAZUH_MANAGER_CERT_SANS replaces the derived set rather than extending it: one typed value maps
# onto the OpenSSL configuration directly and cannot be half-set. Loopback is always appended
# because local tooling connects to localhost.
build_sans() {
    if [ -n "${WAZUH_MANAGER_CERT_SANS}" ]; then
        _bs="${WAZUH_MANAGER_CERT_SANS}"
    else
        _bs=$(derive_sans)
    fi

    case "${_bs}" in
        *IP:127.0.0.1*) ;;
        *) _bs="${_bs},IP:127.0.0.1" ;;
    esac
    case "${_bs}" in
        *IP:::1*) ;;
        *) _bs="${_bs},IP:::1" ;;
    esac

    # A wildcard name is never emitted: under a shared CA a node holding one can present a
    # certificate for any other node.
    printf '%s' "${_bs}" | tr ',' '\n' | grep -q '^DNS:\*' && {
        err "refusing a wildcard name in the SAN list"
        return 1
    }

    printf '%s' "${_bs}"
}

# -----------------------------------------------------------------------------------------
# Issuing
# -----------------------------------------------------------------------------------------

openssl_config() {
    _oc_cn="$1"
    _oc_sans="$2"

    cat <<EOF
[req]
distinguished_name = dn
req_extensions     = ext
prompt             = no

[dn]
CN = ${_oc_cn}
O  = Wazuh
OU = Wazuh Manager

[ext]
basicConstraints = CA:FALSE
keyUsage         = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName   = ${_oc_sans}
EOF
}

mint_ca() {
    log "no certificate authority found in ${CA_DIR}; minting a bootstrap CA"

    if ! install -d -m 0700 -o root -g root "${CA_DIR}" 2>/dev/null; then
        mkdir -p "${CA_DIR}" || return 1
        chmod 0700 "${CA_DIR}" 2>/dev/null
    fi

    _mc_umask=$(umask)
    umask 077

    if ! openssl req -x509 -nodes -newkey "rsa:${RSA_BITS}" -sha256 -days "${DAYS}" \
        -keyout "${CA_KEY}" -out "${CA_CERT}" \
        -subj "/CN=Wazuh bootstrap CA/O=Wazuh" >/dev/null 2>&1; then
        umask "${_mc_umask}"
        err "could not mint the bootstrap CA"
        return 1
    fi

    umask "${_mc_umask}"

    chmod 0400 "${CA_KEY}" 2>/dev/null
    chmod 0644 "${CA_CERT}" 2>/dev/null
    chown root:root "${CA_KEY}" "${CA_CERT}" 2>/dev/null

    log "minted ${CA_CERT}"
    return 0
}

# Issue one leaf from the CA. The certificate and key land in the manager's own certificates
# directory, which is also where an operator places a pre-issued pair to make step 0 true.
issue_pair() {
    _ip_name="$1"
    _ip_cn="$2"
    _ip_sans="$3"

    _ip_key="${CERTS_DIR}/${_ip_name}-key.pem"
    _ip_cert="${CERTS_DIR}/${_ip_name}.pem"
    _ip_csr="${CERTS_DIR}/.${_ip_name}.csr"
    _ip_conf="${CERTS_DIR}/.${_ip_name}.cnf"

    openssl_config "${_ip_cn}" "${_ip_sans}" > "${_ip_conf}" || return 1

    _ip_umask=$(umask)
    umask 077

    if ! openssl req -new -nodes -newkey "rsa:${RSA_BITS}" -sha256 \
        -keyout "${_ip_key}" -out "${_ip_csr}" -config "${_ip_conf}" >/dev/null 2>&1; then
        umask "${_ip_umask}"
        rm -f "${_ip_csr}" "${_ip_conf}"
        err "could not create the ${_ip_name} key and request"
        return 1
    fi

    if ! openssl x509 -req -in "${_ip_csr}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" -CAcreateserial \
        -out "${_ip_cert}" -days "${DAYS}" -sha256 \
        -extensions ext -extfile "${_ip_conf}" >/dev/null 2>&1; then
        umask "${_ip_umask}"
        rm -f "${_ip_csr}" "${_ip_conf}" "${_ip_key}" "${_ip_cert}"
        err "could not sign the ${_ip_name} certificate"
        return 1
    fi

    umask "${_ip_umask}"

    # The request, the config and the serial are intermediate material, not something to leave in a
    # directory the daemons can read.
    rm -f "${_ip_csr}" "${_ip_conf}" "${CA_DIR}/root-ca.srl" "${CERTS_DIR}/root-ca.srl"

    log "issued ${_ip_cert} CN=${_ip_cn}"
    return 0
}

# -----------------------------------------------------------------------------------------
# Run
# -----------------------------------------------------------------------------------------

if ! install -d -m 1770 -o root -g wazuh-manager "${CERTS_DIR}" 2>/dev/null; then
    mkdir -p "${CERTS_DIR}" 2>/dev/null || {
        err "could not create ${CERTS_DIR}"
        exit 1
    }
fi

# Resolved before anything is created: a rejected SAN set must not leave a freshly minted CA behind
# for the next run to adopt.
SANS=$(build_sans) || exit 1
CN=$(hostname 2>/dev/null)
[ -n "${CN}" ] || CN="wazuh-manager"

if [ -f "${CA_CERT}" ] && [ ! -f "${CA_KEY}" ]; then
    # Case D. A trust anchor but no identity, and no way to invent one -- the certificate equivalent
    # of a missing consumed password. The anchor is still installed, so the manager trusts the right
    # CA the moment somebody places an issued pair here.
    install -m 0640 -o root -g wazuh-manager "${CA_CERT}" "${CERTS_DIR}/root-ca.pem" 2>/dev/null \
        || cp -f "${CA_CERT}" "${CERTS_DIR}/root-ca.pem"
    err "found a trust anchor in ${CA_DIR} but no CA private key: this host cannot sign for itself"
    err "place an issued certificate and key in ${CERTS_DIR} (remoted.pem/remoted-key.pem and"
    err "indexer-connector.pem/indexer-connector-key.pem), or supply the CA key on the host that mints it"
    exit 1
fi

if [ ! -f "${CA_CERT}" ]; then
    mint_ca || exit 1            # case A
else
    log "using the existing CA ${CA_CERT}"   # case B
fi

# Logged on every run: a wrong SAN set is the one failure here that is otherwise silent until the
# first peer connection.
log "issuing with CN=${CN} SANs ${SANS}"

issue_pair "remoted" "${CN}" "${SANS}" || exit 1
issue_pair "indexer-connector" "${CN}" "${SANS}" || exit 1

install -m 0640 -o root -g wazuh-manager "${CA_CERT}" "${CERTS_DIR}/root-ca.pem" 2>/dev/null \
    || cp -f "${CA_CERT}" "${CERTS_DIR}/root-ca.pem"

# remoted and authd open the listener pair after dropping privileges, so it belongs to the service
# user. The indexer material is read as root and stays root-owned, so a compromised daemon cannot
# replace the manager's own trust anchor.
chown wazuh-manager:wazuh-manager "${CERTS_DIR}/remoted.pem" "${CERTS_DIR}/remoted-key.pem" 2>/dev/null
chown root:wazuh-manager "${CERTS_DIR}/root-ca.pem" \
    "${CERTS_DIR}/indexer-connector.pem" "${CERTS_DIR}/indexer-connector-key.pem" 2>/dev/null
chmod 0640 "${CERTS_DIR}/remoted.pem" "${CERTS_DIR}/remoted-key.pem" \
    "${CERTS_DIR}/root-ca.pem" \
    "${CERTS_DIR}/indexer-connector.pem" "${CERTS_DIR}/indexer-connector-key.pem" 2>/dev/null

log "certificates are in place under ${CERTS_DIR}"
exit 0
