/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _INDEXER_CLIENT_TLS_MATERIAL_HPP
#define _INDEXER_CLIENT_TLS_MATERIAL_HPP

// TLS material of <indexer>.ssl, read and validated once in RuntimeOwner::start, and the verification policy
// derived from it (ssl.verify_certificates and the system CA store). Lives in TransportShared
// and is handed to curl as CURL_BLOB_NOCOPY blobs (the system store as a path), so it must outlive every multi of the
// transport.

#include <string>
#include <vector>

#include "indexer_client/runtimeConfig.hpp"
#include "indexer_client/types.hpp"

namespace indexer_client::detail
{
    struct TlsMaterial final
    {
        std::string caBundle; ///< Every configured CA file, concatenated (PEM). Empty: no CA configured.
        std::string
            certificateChain;   ///< The client certificate file as is (leaf + optional intermediates). Empty: no mTLS.
        std::string privateKey; ///< Unencrypted PEM key matching the first certificate. Empty: no mTLS.
        /// No CA configured and verification on: the first path of the system CA stores that is a regular file, handed
        /// to curl as CAINFO (curl reads it; a broken store fails the handshake). Empty: a configured CA, or no store
        /// at all (then, with verifyPeer on, curl gets no trust anchor and every handshake fails verification).
        std::string systemCaPath;
        bool verifyPeer {true}; ///< CURLOPT_SSL_VERIFYPEER.
        bool verifyHost {true}; ///< CURLOPT_SSL_VERIFYHOST (2 when true, 0 when false).
        /// The WARN RuntimeOwner::start logs once (verification off, or no CA and no system store so that every https
        /// connection will fail verification; with some https host); empty when there is nothing to warn about.
        std::string warning;
        /// The INFO it logs once when the system CA store is used for some https host; empty otherwise.
        std::string notice;

        TlsMaterial() = default;
        /// Wipes the private key (best effort) on every path, also when a constructor that took it by value
        /// throws before keeping it. Moves stay defaulted (a moved-from key is empty); copies are not needed.
        ~TlsMaterial();
        TlsMaterial(TlsMaterial&&) noexcept = default;
        TlsMaterial& operator=(TlsMaterial&&) noexcept = default;
        TlsMaterial(const TlsMaterial&) = delete;
        TlsMaterial& operator=(const TlsMaterial&) = delete;

        bool mutual() const noexcept
        {
            return !certificateChain.empty();
        }
    };

    /// Where the system CA store is looked for: Utils::SYSTEM_CA_BUNDLE_PATHS (shared_modules/utils), the list the
    /// configuration check uses.
    const std::vector<std::string>& systemCaStorePaths();

    /// Reads and validates the configured material, whatever the hosts' scheme, and derives the policy:
    /// - every host is http or https (case-insensitive);
    /// - verify_certificates true and a CA configured: peer and host verified against it; no CA: the first path of
    ///   systemCaStorePaths() that is a regular file (Utils::systemCaBundle(), as the configuration check does), never
    ///   read here; none exists: peer and host
    ///   stay verified with no trust anchor, so every https handshake fails verification (as the Python framework
    ///   does), and `warning` is set when some host is https;
    /// - verify_certificates false: neither peer nor host verified, `warning` set when some host is https; the
    ///   material below is loaded and validated all the same;
    /// - each CA file (at most 1 MiB) exists, parses as curl parses CAINFO_BLOB (`PEM_X509_INFO_read_bio`, no
    ///   malformed block anywhere) and holds at least one certificate; the concatenation parses too and stays below
    ///   curl's blob limit (8 000 000 bytes);
    /// - certificate and key come together or not at all ("" counts as absent); the certificate file parses as curl
    ///   parses SSLCERT_BLOB (a leaf, then only PEM certificates); the key is PEM, not encrypted, and matches the
    ///   leaf.
    /// Relative paths resolve against the process's working directory (the manager runs with cwd = home).
    /// Failures are InvalidConfig naming the path or the host. Never throws.
    Outcome<TlsMaterial> loadTlsMaterial(const RuntimeConfig& config) noexcept;

    /// OPENSSL_cleanse over the string's bytes, then clear() (best effort: curl and OpenSSL keep their own
    /// copies).
    void cleanseString(std::string& text) noexcept;
} // namespace indexer_client::detail

#endif // _INDEXER_CLIENT_TLS_MATERIAL_HPP
