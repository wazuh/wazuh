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

#ifndef _INDEXER_CLIENT_I_CONFIG_SOURCE_HPP
#define _INDEXER_CLIENT_I_CONFIG_SOURCE_HPP

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "types.hpp"

namespace indexer_client
{
    /// The only way configuration reaches the library. The library never opens a file:
    /// the engine wraps its own `conf` (env -> file -> default precedence), modulesd injects a key=value reader.
    class INDEXER_CLIENT_API IConfigSource
    {
    public:
        virtual ~IConfigSource() = default;

        /// Raw value of an internal option, or nullopt when unset. Keys are full names under
        /// RuntimeConfig::prefixFor(process)
        /// (`analysisd.indexer_client_*` for the engine, also in standalone; `wazuh_modules.indexer_client_*` for
        /// modulesd).
        virtual std::optional<std::string> raw(std::string_view key) const = 0;

        /// Every key present in the source that starts with `prefix` (used to reject unknown keys), including the keys
        /// that problem() reports.
        virtual std::vector<std::string> keysWithPrefix(std::string_view prefix) const = 0;

        /// Why `key` is present but unusable (e.g. a malformed line or an empty value), or nullopt when it is fine or
        /// absent. RuntimeConfig::from() asks it for every key under the process prefix and fails with
        /// Cause::InvalidConfig and this text; keys outside the prefix are never asked, so another daemon's broken
        /// line never fails this process. Sources that cannot hold an unusable key keep the default.
        virtual std::optional<std::string> problem(std::string_view /*key*/) const
        {
            return std::nullopt;
        }

        /// The `<indexer>` section as canonical JSON (shape of manager_config's `sectionJson("indexer")`): exactly an
        /// object with `hosts` and, optionally, `ssl` (`certificate_authorities`, `certificate`, `key`,
        /// `verify_certificates`); any other member is Cause::InvalidConfig.
        virtual std::string indexerSectionJson() const = 0;

        /// The indexer user and password. RuntimeOwner::start copies them and fails with InvalidConfig, before
        /// creating any thread, when either is empty. The library never reads a keystore itself.
        virtual Credentials credentials() const = 0;
    };
} // namespace indexer_client

#endif // _INDEXER_CLIENT_I_CONFIG_SOURCE_HPP
