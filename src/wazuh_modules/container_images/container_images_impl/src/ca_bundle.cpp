/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "ca_bundle.hpp"

#include <filesystem>

namespace containerimages
{
    const std::vector<std::string>& wellKnownCaBundles()
    {
        // The same set cURL's own configure script probes for, in the same order, so a
        // run-time answer matches what a correctly built cURL would have found.
        static const std::vector<std::string> LOCATIONS {
            "/etc/ssl/certs/ca-certificates.crt",    // Debian, Ubuntu, Gentoo
            "/etc/pki/tls/certs/ca-bundle.crt",      // RHEL, Fedora, CentOS, Amazon Linux
            "/etc/ssl/ca-bundle.pem",                // openSUSE, SLES
            "/etc/pki/tls/cacert.pem",               // older RHEL
            "/etc/ssl/cert.pem",                     // Alpine, macOS, FreeBSD
            "/usr/local/share/certs/ca-root-nss.crt" // FreeBSD ports
        };

        return LOCATIONS;
    }

    CaBundle resolveCaBundle(const std::string& configured, const std::function<bool(const std::string&)>& exists)
    {
        const auto present = [&exists](const std::string& path)
        {
            if (exists)
            {
                return exists(path);
            }

            std::error_code error;

            return std::filesystem::exists(path, error) && !error;
        };

        if (!configured.empty())
        {
            if (present(configured))
            {
                return {CaBundleOrigin::Configured, configured, {}};
            }

            // A configured path that does not exist is an operator mistake, and silently
            // probing elsewhere would hide it behind a connection that happens to work.
            return {CaBundleOrigin::None,
                    {},
                    "the configured certificate bundle '" + configured + "' does not exist"};
        }

        for (const auto& location : wellKnownCaBundles())
        {
            if (present(location))
            {
                return {CaBundleOrigin::Detected, location, {}};
            }
        }

        return {CaBundleOrigin::None,
                {},
                "no certificate bundle was found at any of the well-known locations, so the registry's "
                "certificate cannot be verified"};
    }
} // namespace containerimages
