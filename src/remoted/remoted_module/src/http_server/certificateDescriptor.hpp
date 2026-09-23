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
 * The identity string (`x509-sha256:<hex>`) and the bundle hash are ca_bundle's -- identityOf() and
 * contentSha256(), the same functions `wazuh-manager-certs` prints and takes for `remove <identity>`
 * -- so exactly one implementation produces the two strings an operator copies. This pair adds what
 * ca_bundle::describe() does not carry and only GET /tls needs: the subjectAltName list, the serial,
 * RFC 2253 names and the RFC 3339 rendering.
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
        std::string fingerprint;    ///< ca_bundle::identityOf(): `x509-sha256:` + 64 lowercase hex digits.
    };

    /// nullopt for a null certificate or one whose validity times cannot be converted.
    std::optional<CertificateDescriptor> describeCertificate(const X509* certificate);

    /// `YYYY-MM-DDTHH:MM:SSZ` for an epoch second, UTC. Empty when the value cannot be broken down.
    std::string rfc3339Utc(std::int64_t epochSeconds);

    /// Bare lowercase hex SHA-256 of @p bytes: the digest every identity and cache key of this module is built from.
    std::string sha256Hex(std::string_view bytes);
} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_CERTIFICATE_DESCRIPTOR_HPP
