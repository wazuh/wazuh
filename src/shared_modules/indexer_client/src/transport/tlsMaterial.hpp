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

// TLS material of <indexer>.ssl, read and validated once in RuntimeOwner::start (I48). Lives in TransportShared and is
// handed to curl as CURL_BLOB_NOCOPY blobs, so it must outlive every multi of the transport.

#include <string>

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

        TlsMaterial() = default;
        /// Wipes the private key (I55, best effort) on every path, also when a constructor that took it by value
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

    /// Reads and validates the configured material (I48), whatever the hosts' scheme:
    /// - every host is http or https (case-insensitive); some https host without any CA ⇒ InvalidConfig;
    /// - each CA file (at most 1 MiB) exists, parses as curl parses CAINFO_BLOB (`PEM_X509_INFO_read_bio`, no
    ///   malformed block anywhere) and holds at least one certificate; the concatenation parses too and stays below
    ///   curl's blob limit (8 000 000 bytes);
    /// - certificate and key come together or not at all ("" counts as absent); the certificate file parses as curl
    ///   parses SSLCERT_BLOB (a leaf, then only PEM certificates); the key is PEM, not encrypted, and matches the
    ///   leaf.
    /// Relative paths resolve against the process's working directory (the manager runs with cwd = home).
    /// Failures are InvalidConfig naming the path or the host. Never throws.
    Outcome<TlsMaterial> loadTlsMaterial(const RuntimeConfig& config) noexcept;

    /// OPENSSL_cleanse over the string's bytes, then clear() (best effort, I55: curl and OpenSSL keep their own
    /// copies).
    void cleanseString(std::string& text) noexcept;
} // namespace indexer_client::detail

#endif // _INDEXER_CLIENT_TLS_MATERIAL_HPP
