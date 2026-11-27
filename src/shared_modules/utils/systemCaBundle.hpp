/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _SYSTEM_CA_BUNDLE_HPP
#define _SYSTEM_CA_BUNDLE_HPP

#include <array>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>

namespace Utils
{
    /**
     * @brief Where the operating system's CA bundle is looked for, in this order.
     *
     * One list for every reader of the indexer configuration: the configuration check and the indexer client
     * both resolve the bundle from it, so a configuration the check accepts is one the client finds a
     * certificate authority for. The Python framework keeps the same list (framework/wazuh/core/indexer).
     */
    inline constexpr std::array<std::string_view, 8> SYSTEM_CA_BUNDLE_PATHS {
        "/etc/ssl/certs/ca-certificates.crt",                // Debian, Ubuntu, Alpine
        "/etc/pki/tls/certs/ca-bundle.crt",                  // RHEL, CentOS, Fedora, Amazon Linux
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // RHEL family, where the above is a link to it
        "/etc/ssl/ca-bundle.pem",                            // SUSE
        "/var/lib/ca-certificates/ca-bundle.pem",            // SUSE, where the above is a link to it
        "/usr/share/ssl/certs/ca-bundle.crt",                // Old Red Hat
        "/usr/local/share/certs/ca-root-nss.crt",            // FreeBSD
        "/etc/ssl/cert.pem",                                 // OpenBSD, FreeBSD, macOS
    };

    /**
     * @brief First of @p candidates that is a regular file, or an empty string when none is.
     *
     * The rule behind systemCaBundle(), over a list the caller names (tests replace the system's).
     */
    template<typename TPaths>
    std::string systemCaBundle(const TPaths& candidates)
    {
        for (const auto& candidate : candidates)
        {
            std::error_code ec;
            if (std::filesystem::is_regular_file(std::filesystem::path {std::string_view {candidate}}, ec))
            {
                return std::string {std::string_view {candidate}};
            }
        }

        return {};
    }

    /**
     * @brief Path of the operating system's CA bundle, or an empty string when none is found.
     *
     * For a TLS client that was given no certificate authority of its own. The HTTP client library
     * looks for a bundle itself when it gets none and, finding none, switches peer verification off:
     * a caller that names the bundle it wants, and refuses to connect when this returns nothing,
     * never reaches that fallback.
     */
    inline std::string systemCaBundle()
    {
        return systemCaBundle(SYSTEM_CA_BUNDLE_PATHS);
    }
} // namespace Utils

#endif // _SYSTEM_CA_BUNDLE_HPP
