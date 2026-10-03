/*
 * Wazuh indexer client
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
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
    /// The only way configuration reaches the library (I26, I26b, I26c). The library never opens a file:
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

        /// Every key present in the source that starts with `prefix` (used to reject unknown keys).
        virtual std::vector<std::string> keysWithPrefix(std::string_view prefix) const = 0;

        /// The `<indexer>` section as canonical JSON (shape of manager_config's `sectionJson("indexer")`): exactly an
        /// object with `hosts` and, optionally, `ssl`; any other member is Cause::InvalidConfig. The engine's current
        /// `wiconnector::Config::toJson()` is NOT valid input (it adds `max_queue_bytes` and
        /// `max_retry_delay_seconds`).
        virtual std::string indexerSectionJson() const = 0;
    };
} // namespace indexer_client

#endif // _INDEXER_CLIENT_I_CONFIG_SOURCE_HPP
