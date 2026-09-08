/*
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef X509_OP_H
#define X509_OP_H

#include <stdint.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

/**
 * @brief Load the first certificate of a PEM file.
 *
 * A leaf followed by its CA in the same file (the shape of remoted.pem) therefore yields
 * the leaf.
 *
 * @param path Path of the PEM file.
 * @return The certificate, which the caller must X509_free(), or NULL on error.
 */
X509 *w_x509_load_pem(const char *path);

/**
 * @brief SHA-256 of the DER SubjectPublicKeyInfo of a certificate.
 *
 * This is the public key pin of RFC 7469 section 2.4: it survives a re-issue of the
 * certificate as long as the key pair is kept.
 *
 * @param cert Certificate to pin.
 * @param out Receives the 32 bytes of the digest.
 * @return 0 on success, -1 on error.
 */
int w_x509_spki_sha256(X509 *cert, uint8_t out[32]);

/**
 * @brief Whether the signature of a certificate verifies against the public key of another.
 *
 * Only the signature is checked: no validity window, no basic constraints, no chain
 * building. Callers that need a full validation must use the OpenSSL store API.
 *
 * @param leaf Certificate whose signature is checked.
 * @param ca Certificate holding the issuer public key.
 * @return 1 when @p ca signed @p leaf, 0 otherwise (NULL arguments included).
 */
int w_x509_signed_by(X509 *leaf, X509 *ca);

/**
 * @brief Whether a host matches a subject alternative name of a certificate.
 *
 * The subject common name is never consulted. An IP literal is matched against the
 * iPAddress entries, anything else against the dNSName entries (case insensitive, with no
 * partial wildcards).
 *
 * @param cert Certificate to check.
 * @param host DNS name or IP literal.
 * @return 1 on match, 0 otherwise.
 */
int w_x509_san_matches(X509 *cert, const char *host);

/**
 * @brief Whether a certificate only names the loopback interface.
 *
 * True when there are no subject alternative names at all or every entry is the DNS name
 * `localhost`, an IPv4 address in 127.0.0.0/8 or the IPv6 address ::1. Such a certificate
 * cannot be reached by an agent, so minting an enrollment token for it is refused.
 *
 * @param cert Certificate to check.
 * @return 1 when the certificate is loopback only, 0 otherwise.
 */
int w_x509_san_is_loopback_only(X509 *cert);

#endif /* X509_OP_H */
