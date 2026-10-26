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

#ifndef _INDEXER_CLIENT_RUNTIME_CONFIG_HPP
#define _INDEXER_CLIENT_RUNTIME_CONFIG_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "iConfigSource.hpp"
#include "types.hpp"

namespace indexer_client
{
    /// TLS material of the `<indexer>` section.
    struct SslConfig final
    {
        std::vector<std::string> certificateAuthorities;
        std::string certificate;
        std::string key;
        /// `indexer.ssl.verify_certificates` (default true, also when absent): false turns off server certificate and
        /// host name verification; the CA and client pair above are still loaded and validated.
        bool verifyCertificates {true};
    };

    /// Typed, validated runtime configuration (RF-18). Every field has exactly one entry in the schema (`kSchema`
    /// in src/config/runtimeConfig.cpp and the table in the module README): key, type, unit, range and default.
    struct INDEXER_CLIENT_API RuntimeConfig final
    {
        // From `<indexer>`.
        std::vector<std::string> hosts;
        SslConfig ssl;

        // From `<process>.indexer_client_*`.
        std::uint32_t networkThreads {1};                 ///< K (I22c), [1, 64]
        std::uint32_t cpuThreads {2};                     ///< M, [1, 64]
        std::uint64_t globalQuotaBytes {256u << 20};      ///< runtime-wide cap of retained bytes, > 0
        std::uint64_t maxResponseBytes {64u << 20};       ///< > 0
        std::uint64_t drrQuantumBytes {1u << 20};         ///< > 0 (I97b)
        Duration requestTimeout {Duration {60000}};       ///< > 0
        Duration probeTimeout {Duration {5000}};          ///< > 0
        Duration probeInterval {Duration {10000}};        ///< > 0
        Duration drain {Duration {10000}};                ///< > 0, total shutdown budget (I37)
        Duration ambiguousRetryWindow {Duration {30000}}; ///< > 0 (I36)
        Duration latencyTarget {Duration {2000}};         ///< > 0 (AIMD)
        Duration paceInitial {Duration {100}};            ///< > 0 (pacing seed)
        std::uint32_t paceRelaxAfter {20};                ///< > 0
        Duration retryAfterMax {Duration {60000}};        ///< > 0
        Duration callbackBudget {Duration {200}};         ///< > 0 (k4-1)
        std::uint32_t maxOpenPits {64};                   ///< > 0
        Duration logSummaryInterval {Duration {60000}};   ///< [1 s, 1 h], periodic log summary (I102)
        std::uint32_t nodeWindowMax {4};                  ///< [1, 64], AIMD window cap and start (I96, I98)
        std::uint64_t bulkMinBytes {64u << 10};           ///< [1, 32 MiB], AIMD bulk target floor (I98)

        /// Prefix of the internal-options family for a process (`analysisd.indexer_client_` /
        /// `wazuh_modules.indexer_client_`).
        static std::string prefixFor(ProcessId process);

        /// Builds and validates the configuration from a source. Unknown keys under the prefix, wrong types,
        /// out-of-range values, numeric overflow and an invalid `<indexer>` JSON are all Cause::InvalidConfig, with the
        /// offending key in `reason`. Values are read only through `raw()`.
        static Outcome<RuntimeConfig> from(ProcessId process, const IConfigSource& source);
    };
} // namespace indexer_client

#endif // _INDEXER_CLIENT_RUNTIME_CONFIG_HPP
