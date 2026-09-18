/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_HTTP_SERVER_CERTIFICATE_DESCRIPTOR_HPP
#define _REMOTED_HTTP_SERVER_CERTIFICATE_DESCRIPTOR_HPP

/**
 * @file certificateDescriptor.hpp
 * @brief One certificate as an operator reads it: names, validity window, identity. What `GET /tls`
 *        on the admin socket says about the listener's leaf and about every certificate of the CA
 *        bundle (issue #39320), and the one place the `x509-sha256:` identity the rotation runbook
 *        types is computed.
 *
 * Pure functions of an X509: no I/O, no clock, no logger, so the tests drive them from certificates
 * built in memory. Times are epoch seconds; rfc3339Utc() renders them for the document.
 *
 * TODO(#39319): `wazuh-manager-certs inspect` needs this same descriptor (subject, issuer, notAfter,
 * identity, signs-active-leaf) and the bundle's `Content-SHA256`. Both issues were specified in
 * parallel, so if #39319 lands a descriptor of its own first, this pair is the one to keep and the
 * tool should link it: two fingerprint implementations for the one string `remove <identity>` takes
 * would eventually disagree.
 */

#include "tlsCertificateStatus.hpp"

#include <openssl/types.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace remoted::http
{
    /// What every certificate identity this module prints starts with: the algorithm, then the digest.
    constexpr std::string_view kFingerprintPrefix {"x509-sha256:"};

    /// The fields `GET /tls` publishes for one certificate.
    struct CertificateDescriptor
    {
        std::string subject; ///< RFC 2253 one-liner (`CN=manager-01,O=Corp`); non-ASCII kept as UTF-8.
        std::string issuer;  ///< Same form.
        /// dNSName and iPAddress entries, bare (`manager-01.example.com`, `10.0.0.5`, `2001:db8::1`).
        /// The other GENERAL_NAME types are not something a TLS client matches a server against.
        std::vector<std::string> subjectAltNames;
        std::int64_t notBefore {0}; ///< Epoch seconds, UTC.
        std::int64_t notAfter {0};  ///< Epoch seconds, UTC. `notAfter - now` negative means expired.
        std::string serial;         ///< `0x` + lowercase hex of the serial number.
        std::string fingerprint;    ///< fingerprintOf().
    };

    /// nullopt for a null certificate or one whose validity times cannot be converted.
    std::optional<CertificateDescriptor> describeCertificate(const X509* certificate);

    /**
     * @brief kFingerprintPrefix + SHA-256 of the DER encoding as 64 lowercase hex digits, no
     *        separators. Empty for a null certificate.
     *
     * The DER, not the SPKI: a reissue with the same key is a different certificate and must read
     * as one (spike #39277). Lowercase and colon-free so the identity is one token to copy, and
     * because the bundle's own `Content-SHA256` (#39319) is bare hex too -- one style for the whole
     * feature. `openssl x509 -noout -fingerprint -sha256` prints the same digest uppercase with
     * colons: a consumer comparing the two folds case and drops the colons, and #39319's
     * `remove <identity>` is asked to accept both spellings, with or without the prefix.
     */
    std::string fingerprintOf(const X509* certificate);

    /**
     * @brief Bare-hex SHA-256 over the DER encodings of @p certificates sorted bytewise and
     *        concatenated (#39319 § 1's `Content-SHA256`): the identity of a bundle, independent of
     *        the order its certificates were written in. Empty when there is nothing to hash or one
     *        of them cannot be encoded.
     */
    std::string contentSha256(const std::vector<X509Ptr>& certificates);

    /// `YYYY-MM-DDTHH:MM:SSZ` for an epoch second, UTC. Empty when the value cannot be broken down.
    std::string rfc3339Utc(std::int64_t epochSeconds);

    /// Bare lowercase hex SHA-256 of @p bytes: the digest every identity and cache key of this module is built from.
    std::string sha256Hex(std::string_view bytes);
} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_CERTIFICATE_DESCRIPTOR_HPP
