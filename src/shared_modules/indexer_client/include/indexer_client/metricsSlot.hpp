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

#ifndef _INDEXER_CLIENT_METRICS_SLOT_HPP
#define _INDEXER_CLIENT_METRICS_SLOT_HPP

// What a consumer's pull metrics read (D95, I140, I141b, I168): its Client WEAKLY, optionally the process's
// RuntimeRef, and the last snapshot of both, refreshed at most once per `maxAge`. Header-only: nothing here is exported
// by the library.

#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include "client.hpp"
#include "metrics.hpp"
#include "runtime.hpp"

namespace indexer_client
{
    /// The values a MetricsSlot serves, as of its last refresh.
    struct MetricsSlotSnapshot final
    {
        /// forEachMetric of the runtime snapshot and of the ClientMetrics, by name, kept when a prefix matches.
        std::unordered_map<std::string, double> values;
        std::optional<MetricsSnapshot> runtime; ///< Set when the slot points at a runtime.
        std::optional<ClientMetrics> client;    ///< Set when the Client was alive at the refresh.

        /// @return The metric @p name, 0 when absent (no live Client, no runtime, or filtered out).
        double value(const std::string& name) const
        {
            const auto it = values.find(name);
            return it == values.end() ? 0.0 : it->second;
        }
    };

    /**
     * @brief A pull-metrics source over a Client held weakly and an optional RuntimeRef.
     *
     * A scrape locks the Client only for one metrics() call, so it never keeps a closed Client alive; without a live
     * Client its bucket values read 0, while the runtime's are still taken (they do not depend on a Client, I168). One
     * refresh serves every read within `maxAge`, so one scrape of N metrics costs one metrics() and one snapshot().
     * Its own mutex: a scrape never contends with the consumer's lifecycle. Meant to be shared (shared_ptr) by the
     * consumer and every getter it registers.
     */
    class MetricsSlot final
    {
    public:
        /**
         * @param maxAge Longest a snapshot is served.
         * @param prefixes Names kept; empty keeps every name.
         */
        explicit MetricsSlot(std::chrono::milliseconds maxAge, std::vector<std::string> prefixes = {})
            : m_maxAge {maxAge}
            , m_prefixes {std::move(prefixes)}
        {
        }

        /// Points the slot at another Client and runtime (a restart); the next read refreshes.
        void repoint(std::weak_ptr<IClient> client, std::optional<RuntimeRef> runtime = std::nullopt)
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            m_client = std::move(client);
            m_runtime = std::move(runtime);
            m_fresh = false;
        }

        /// Runs @p reader over the snapshot, refreshed first when older than `maxAge`.
        template<typename TRead>
        std::invoke_result_t<TRead&, const MetricsSlotSnapshot&> read(TRead&& reader)
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            refreshLocked();
            return reader(m_snapshot);
        }

        /// @return The metric @p name as of the (refreshed) snapshot; 0 when absent.
        double value(const std::string& name)
        {
            return read([&name](const MetricsSlotSnapshot& snapshot) { return snapshot.value(name); });
        }

    private:
        bool kept(std::string_view name) const
        {
            if (m_prefixes.empty())
            {
                return true;
            }
            for (const auto& prefix : m_prefixes)
            {
                if (name.substr(0, prefix.size()) == prefix)
                {
                    return true;
                }
            }
            return false;
        }

        void refreshLocked()
        {
            const auto now = std::chrono::steady_clock::now();
            if (m_fresh && now - m_refreshedAt < m_maxAge)
            {
                return;
            }
            m_fresh = true;
            m_refreshedAt = now;
            m_snapshot = MetricsSlotSnapshot {};

            const auto collect = [this](std::string_view name, MetricKind, double value)
            {
                if (kept(name))
                {
                    m_snapshot.values[std::string(name)] = value;
                }
            };

            // The runtime first: its values do not depend on a live Client (I168).
            if (m_runtime)
            {
                m_snapshot.runtime = m_runtime->snapshot();
                forEachMetric(*m_snapshot.runtime, collect);
            }

            // Scoped: the strong reference lives only for this one call.
            m_snapshot.client = [this]
            {
                const auto live = m_client.lock();
                return live ? std::optional<ClientMetrics> {live->metrics()} : std::nullopt;
            }();
            if (m_snapshot.client)
            {
                forEachMetric(*m_snapshot.client, collect);
            }
        }

        std::mutex m_mutex;
        const std::chrono::milliseconds m_maxAge;
        const std::vector<std::string> m_prefixes;
        std::weak_ptr<IClient> m_client;
        std::optional<RuntimeRef> m_runtime;
        bool m_fresh {false};
        std::chrono::steady_clock::time_point m_refreshedAt;
        MetricsSlotSnapshot m_snapshot;
    };
} // namespace indexer_client

#endif // _INDEXER_CLIENT_METRICS_SLOT_HPP
