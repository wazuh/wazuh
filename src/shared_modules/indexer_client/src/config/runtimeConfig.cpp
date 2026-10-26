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

#include "indexer_client/runtimeConfig.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

#include "json.hpp"
#include "write/sender.hpp"

namespace indexer_client
{
    namespace
    {
        constexpr std::uint64_t KIB = 1024;
        constexpr std::uint64_t MIB = 1024 * KIB;
        constexpr std::uint64_t GIB = 1024 * MIB;
        constexpr std::uint64_t SECOND_MS = 1000;
        constexpr std::uint64_t MINUTE_MS = 60 * SECOND_MS;
        constexpr std::uint64_t HOUR_MS = 60 * MINUTE_MS;

        using Apply = void (*)(RuntimeConfig&, std::uint64_t);

        /// One internal option `<process>.indexer_client_<name>`. Every value is an unsigned decimal integer.
        struct SchemaEntry final
        {
            const char* name;           ///< Suffix after the process prefix.
            const char* unit;           ///< "count", "bytes" or "ms".
            std::uint64_t min;          ///< Inclusive.
            std::uint64_t max;          ///< Inclusive.
            std::uint64_t defaultValue; ///< Equal to the RuntimeConfig initializer (checked by DefaultsWhenUnset).
            Apply apply;
        };

        template<std::uint32_t RuntimeConfig::* Field>
        void setU32(RuntimeConfig& config, std::uint64_t value)
        {
            config.*Field = static_cast<std::uint32_t>(value);
        }

        template<std::uint64_t RuntimeConfig::* Field>
        void setU64(RuntimeConfig& config, std::uint64_t value)
        {
            config.*Field = value;
        }

        template<Duration RuntimeConfig::* Field>
        void setMs(RuntimeConfig& config, std::uint64_t value)
        {
            config.*Field = Duration {static_cast<Duration::rep>(value)};
        }

        /// The single schema of the internal-options family (RF-18). Mirrored by the table in the module README.
        constexpr std::array<SchemaEntry, 19> kSchema {{
            {"network_threads", "count", 1, 64, 1, &setU32<&RuntimeConfig::networkThreads>},
            {"cpu_threads", "count", 1, 64, 2, &setU32<&RuntimeConfig::cpuThreads>},
            {"global_quota_bytes", "bytes", 1, 64 * GIB, 256 * MIB, &setU64<&RuntimeConfig::globalQuotaBytes>},
            {"max_response_bytes", "bytes", 1, 1 * GIB, 64 * MIB, &setU64<&RuntimeConfig::maxResponseBytes>},
            {"drr_quantum_bytes", "bytes", 1, 64 * MIB, 1 * MIB, &setU64<&RuntimeConfig::drrQuantumBytes>},
            {"request_timeout_ms", "ms", 1, HOUR_MS, 60 * SECOND_MS, &setMs<&RuntimeConfig::requestTimeout>},
            {"probe_timeout_ms", "ms", 1, 5 * MINUTE_MS, 5 * SECOND_MS, &setMs<&RuntimeConfig::probeTimeout>},
            {"probe_interval_ms", "ms", 1, HOUR_MS, 10 * SECOND_MS, &setMs<&RuntimeConfig::probeInterval>},
            {"drain_ms", "ms", 1, 10 * MINUTE_MS, 10 * SECOND_MS, &setMs<&RuntimeConfig::drain>},
            {"ambiguous_retry_window_ms",
             "ms",
             1,
             HOUR_MS,
             30 * SECOND_MS,
             &setMs<&RuntimeConfig::ambiguousRetryWindow>},
            {"latency_target_ms", "ms", 1, 10 * MINUTE_MS, 2 * SECOND_MS, &setMs<&RuntimeConfig::latencyTarget>},
            {"pace_initial_ms", "ms", 1, MINUTE_MS, 100, &setMs<&RuntimeConfig::paceInitial>},
            {"pace_relax_after", "count", 1, 1000000, 20, &setU32<&RuntimeConfig::paceRelaxAfter>},
            {"retry_after_max_ms", "ms", 1, HOUR_MS, 60 * SECOND_MS, &setMs<&RuntimeConfig::retryAfterMax>},
            {"callback_budget_ms", "ms", 1, MINUTE_MS, 200, &setMs<&RuntimeConfig::callbackBudget>},
            {"max_open_pits", "count", 1, 10000, 64, &setU32<&RuntimeConfig::maxOpenPits>},
            {"log_summary_interval_ms",
             "ms",
             SECOND_MS,
             HOUR_MS,
             MINUTE_MS,
             &setMs<&RuntimeConfig::logSummaryInterval>},
            {"node_window_max", "count", 1, 64, 4, &setU32<&RuntimeConfig::nodeWindowMax>},
            {"bulk_min_bytes", "bytes", 1, 32 * MIB, 64 * KIB, &setU64<&RuntimeConfig::bulkMinBytes>},
        }};

        constexpr bool schemaIsConsistent()
        {
            for (const auto& entry : kSchema)
            {
                if (entry.min < 1 || entry.min > entry.max || entry.defaultValue < entry.min ||
                    entry.defaultValue > entry.max)
                {
                    return false;
                }
            }
            return true;
        }
        static_assert(schemaIsConsistent(), "every kSchema default must lie inside its [min, max] and min must be > 0");

        constexpr std::uint64_t schemaMax(std::string_view name)
        {
            for (const auto& entry : kSchema)
            {
                if (std::string_view {entry.name} == name)
                {
                    return entry.max;
                }
            }
            return 0;
        }
        // I98 (G-diff obj. 7): a decrease never yields a target at or above the uncapped mark, so bulk_min_bytes stays
        // below it.
        static_assert(schemaMax("bulk_min_bytes") != 0 &&
                          schemaMax("bulk_min_bytes") < detail::write::BULK_TARGET_UNCAPPED,
                      "bulk_min_bytes must stay below BULK_TARGET_UNCAPPED (write/sender.hpp)");

        bool isBlank(char c)
        {
            return c == ' ' || c == '\t' || c == '\r' || c == '\n';
        }

        /// Strict unsigned decimal: optional surrounding blanks, then one or more digits and nothing else.
        std::optional<std::uint64_t> parseUnsigned(std::string_view text, bool& overflow)
        {
            overflow = false;
            while (!text.empty() && isBlank(text.front()))
            {
                text.remove_prefix(1);
            }
            while (!text.empty() && isBlank(text.back()))
            {
                text.remove_suffix(1);
            }
            if (text.empty())
            {
                return std::nullopt;
            }

            std::uint64_t value = 0;
            constexpr auto LIMIT = std::numeric_limits<std::uint64_t>::max();
            for (const char c : text)
            {
                if (c < '0' || c > '9')
                {
                    return std::nullopt;
                }
                const auto digit = static_cast<std::uint64_t>(c - '0');
                if (value > (LIMIT - digit) / 10)
                {
                    overflow = true;
                    return std::nullopt;
                }
                value = value * 10 + digit;
            }
            return value;
        }

        const SchemaEntry* findEntry(std::string_view name)
        {
            const auto it = std::find_if(
                kSchema.begin(), kSchema.end(), [name](const SchemaEntry& entry) { return name == entry.name; });
            return it == kSchema.end() ? nullptr : &*it;
        }

        Outcome<Unit> invalid(std::string why)
        {
            return Outcome<Unit>::failure(Cause::InvalidConfig, std::move(why));
        }

        Outcome<Unit> readStringArray(const nlohmann::json& node,
                                      const std::string& path,
                                      bool requireNonEmpty,
                                      std::vector<std::string>& out)
        {
            if (!node.is_array())
            {
                return invalid(path + ": expected an array of strings");
            }
            if (requireNonEmpty && node.empty())
            {
                return invalid(path + ": must contain at least one entry");
            }
            out.clear();
            out.reserve(node.size());
            for (std::size_t i = 0; i < node.size(); ++i)
            {
                const auto& item = node[i];
                if (!item.is_string() || item.get_ref<const std::string&>().empty())
                {
                    return invalid(path + "[" + std::to_string(i) + "]: expected a non-empty string");
                }
                out.push_back(item.get<std::string>());
            }
            return Outcome<Unit>::success({});
        }

        Outcome<Unit> readString(const nlohmann::json& node, const std::string& path, std::string& out)
        {
            if (!node.is_string())
            {
                return invalid(path + ": expected a string");
            }
            out = node.get<std::string>();
            return Outcome<Unit>::success({});
        }

        Outcome<Unit> readBool(const nlohmann::json& node, const std::string& path, bool& out)
        {
            if (!node.is_boolean())
            {
                return invalid(path + ": expected a boolean");
            }
            out = node.get<bool>();
            return Outcome<Unit>::success({});
        }

        /// `<indexer>` in the shape of manager_config's `sectionJson("indexer")` (schema section `indexer`):
        /// {"hosts": [..], "ssl": {"certificate_authorities": [..], "certificate": "..", "key": "..",
        /// "verify_certificates": true}}.
        Outcome<Unit> parseIndexerSection(const std::string& text, RuntimeConfig& config)
        {
            if (text.empty())
            {
                return invalid("indexer: section missing (hosts is required)");
            }
            const auto root = nlohmann::json::parse(text, nullptr, false);
            if (root.is_discarded())
            {
                return invalid("indexer: section is not valid JSON");
            }
            if (!root.is_object())
            {
                return invalid("indexer: section must be a JSON object");
            }

            for (const auto& [name, value] : root.items())
            {
                if (name != "hosts" && name != "ssl")
                {
                    return invalid("indexer." + name + ": unknown member");
                }
            }

            const auto hosts = root.find("hosts");
            if (hosts == root.end())
            {
                return invalid("indexer.hosts: required");
            }
            if (auto r = readStringArray(*hosts, "indexer.hosts", true, config.hosts); !r.ok())
            {
                return r;
            }

            const auto ssl = root.find("ssl");
            if (ssl == root.end())
            {
                return Outcome<Unit>::success({});
            }
            if (!ssl->is_object())
            {
                return invalid("indexer.ssl: expected an object");
            }
            for (const auto& [name, value] : ssl->items())
            {
                Outcome<Unit> r = Outcome<Unit>::success({});
                if (name == "certificate_authorities")
                {
                    r = readStringArray(
                        value, "indexer.ssl.certificate_authorities", false, config.ssl.certificateAuthorities);
                }
                else if (name == "certificate")
                {
                    r = readString(value, "indexer.ssl.certificate", config.ssl.certificate);
                }
                else if (name == "key")
                {
                    r = readString(value, "indexer.ssl.key", config.ssl.key);
                }
                else if (name == "verify_certificates")
                {
                    r = readBool(value, "indexer.ssl.verify_certificates", config.ssl.verifyCertificates);
                }
                else
                {
                    r = invalid("indexer.ssl." + name + ": unknown member");
                }
                if (!r.ok())
                {
                    return r;
                }
            }
            return Outcome<Unit>::success({});
        }

        Outcome<RuntimeConfig> build(ProcessId process, const IConfigSource& source)
        {
            const auto prefix = RuntimeConfig::prefixFor(process);

            for (const auto& key : source.keysWithPrefix(prefix))
            {
                const bool underPrefix = key.size() >= prefix.size() && key.compare(0, prefix.size(), prefix) == 0;
                if (!underPrefix)
                {
                    return Outcome<RuntimeConfig>::failure(Cause::InvalidConfig,
                                                           key + ": unknown option under '" + prefix + "'");
                }
                // A key under the prefix that the source holds but cannot use (malformed line, empty value) is fatal
                // for this process only; outside the prefix nobody asks (same per-key scope as the C reader).
                if (auto why = source.problem(key))
                {
                    return Outcome<RuntimeConfig>::failure(Cause::InvalidConfig, std::move(*why));
                }
                if (findEntry(std::string_view {key}.substr(prefix.size())) == nullptr)
                {
                    return Outcome<RuntimeConfig>::failure(Cause::InvalidConfig,
                                                           key + ": unknown option under '" + prefix + "'");
                }
            }

            RuntimeConfig config;
            for (const auto& entry : kSchema)
            {
                const std::string key = prefix + entry.name;
                std::uint64_t value = entry.defaultValue;
                if (const auto raw = source.raw(key))
                {
                    bool overflow = false;
                    const auto parsed = parseUnsigned(*raw, overflow);
                    if (!parsed)
                    {
                        return Outcome<RuntimeConfig>::failure(
                            Cause::InvalidConfig,
                            key + ": '" + *raw + "' is not " +
                                (overflow ? std::string {"representable (unsigned 64-bit overflow)"}
                                          : std::string {"an unsigned decimal integer"}));
                    }
                    value = *parsed;
                    if (value < entry.min || value > entry.max)
                    {
                        return Outcome<RuntimeConfig>::failure(
                            Cause::InvalidConfig,
                            key + ": " + std::to_string(value) + " is out of range [" + std::to_string(entry.min) +
                                ", " + std::to_string(entry.max) + "] " + entry.unit);
                    }
                }
                entry.apply(config, value);
            }

            if (auto r = parseIndexerSection(source.indexerSectionJson(), config); !r.ok())
            {
                return Outcome<RuntimeConfig>::failure(r.cause, std::move(r.reason));
            }
            return Outcome<RuntimeConfig>::success(std::move(config));
        }
    } // namespace

    std::string RuntimeConfig::prefixFor(ProcessId process)
    {
        switch (process)
        {
            case ProcessId::Modulesd: return "wazuh_modules.indexer_client_";
            case ProcessId::Analysisd:
            case ProcessId::Standalone:
            default: return "analysisd.indexer_client_";
        }
    }

    Outcome<RuntimeConfig> RuntimeConfig::from(ProcessId process, const IConfigSource& source)
    {
        try
        {
            return build(process, source);
        }
        catch (const std::exception& e)
        {
            return Outcome<RuntimeConfig>::failure(Cause::InvalidConfig, std::string {"configuration: "} + e.what());
        }
        catch (...)
        {
            return Outcome<RuntimeConfig>::failure(Cause::InvalidConfig, "configuration: unknown error");
        }
    }
} // namespace indexer_client
