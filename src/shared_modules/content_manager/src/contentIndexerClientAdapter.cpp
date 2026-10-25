/*
 * Wazuh content manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include "components/keepAlive.hpp"
#include "contentIndexerAdapters.hpp"
#include "indexer_client/client.hpp"
#include "indexer_client/types.hpp"
#include "loggerHelper.h"
#include "sharedDefs.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>

namespace
{
    using indexer_client::Cause;
    using indexer_client::Duration;

    std::uint64_t nowMillis()
    {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
    }

    template<typename T>
    [[noreturn]] void throwFailure(const char* what, const indexer_client::Outcome<T>& outcome)
    {
        std::string message {what};
        message += ": ";
        message += indexer_client::toString(outcome.cause);
        if (!outcome.reason.empty())
        {
            message += ": ";
            message += outcome.reason;
        }
        logDebug2(WM_CONTENTUPDATER, "%s", message.c_str());
        throw std::runtime_error {message};
    }

    /// IContentIndexer over a host's indexer_client Client (I154). PITs are the library's: this adapter only maps the
    /// opaque ContentPit id to its Pit handle; releasing the handle lets the library delete the PIT (I90).
    class ClientIndexer final : public content_manager::IContentIndexer
    {
    public:
        ClientIndexer(std::shared_ptr<indexer_client::IClient> client, content_manager::ContentIndexerOptions options)
            : m_client(std::move(client))
            , m_options(options)
        {
            if (!m_client)
            {
                throw std::invalid_argument {"The content manager needs the host's indexer client; got null"};
            }
            if (m_options.callDeadline.count() <= 0 || m_options.pageDeadline.count() <= 0 ||
                m_options.probeDeadline.count() <= 0)
            {
                throw std::invalid_argument {"Every ContentIndexerOptions deadline must be positive"};
            }
            m_query = m_client->query();
            if (!m_query)
            {
                throw std::invalid_argument {"The host's indexer client has no query handle (is it closed?)"};
            }
        }

        content_manager::ContentPit
        openPit(const std::vector<std::string>& indices, std::string_view keepAlive, bool expandWildcards) override
        {
            indexer_client::PitOptions pitOptions;
            pitOptions.keepAlive = content_manager::detail::parseKeepAlive(keepAlive);
            pitOptions.expandWildcardsAll = expandWildcards;

            auto outcome = m_query->pit(indices, pitOptions, queryOptions(), deadline(m_options.callDeadline));
            if (!outcome.ok())
            {
                throwFailure("Failed to open PIT", outcome);
            }

            auto key = "cm-pit-" + std::to_string(outcome.value.generation());
            {
                std::lock_guard lock {m_mutex};
                m_pits.insert_or_assign(key, std::move(outcome.value));
            }
            logDebug2(WM_CONTENTUPDATER, "Opened PIT '%s' over %zu indices.", key.c_str(), indices.size());
            return content_manager::ContentPit {std::move(key), nowMillis(), std::string {keepAlive}};
        }

        void closePit(const content_manager::ContentPit& pit) noexcept override
        {
            try
            {
                // Destroyed outside the lock: the last handle hands its delete over to the library (never blocks).
                indexer_client::Pit released;
                {
                    std::lock_guard lock {m_mutex};
                    const auto it = m_pits.find(pit.id);
                    if (it == m_pits.end())
                    {
                        logDebug2(WM_CONTENTUPDATER, "PIT '%s' is not open; nothing to release.", pit.id.c_str());
                        return;
                    }
                    released = std::move(it->second);
                    m_pits.erase(it);
                }
                logDebug2(WM_CONTENTUPDATER, "Released PIT '%s'.", pit.id.c_str());
            }
            catch (const std::exception& e)
            {
                // A leaked PIT expires on its own after keepAlive; never let this abort a cycle.
                logDebug2(WM_CONTENTUPDATER, "Failed to release PIT: %s", e.what());
            }
            catch (...)
            {
                logDebug2(WM_CONTENTUPDATER, "Failed to release PIT.");
            }
        }

        nlohmann::json search(const content_manager::ContentPit& pit,
                              std::size_t size,
                              const nlohmann::json& query,
                              const nlohmann::json& sort,
                              const std::optional<nlohmann::json>& searchAfter,
                              const std::optional<nlohmann::json>& source,
                              const std::optional<nlohmann::json>& slice) override
        {
            // A copy of the handle: no lock is held across the request (contentIndexer.hpp), and a concurrent
            // closePit only defers the delete until this search returns.
            indexer_client::Pit handle;
            {
                std::lock_guard lock {m_mutex};
                const auto it = m_pits.find(pit.id);
                if (it == m_pits.end())
                {
                    throw std::runtime_error {"Unknown PIT '" + pit.id + "'"};
                }
                handle = it->second;
            }

            // The v1 body; the library sets `pit`.
            nlohmann::json body;
            body["size"] = size;
            body["query"] = query;
            body["sort"] = sort;
            if (source.has_value())
            {
                body["_source"] = *source;
            }
            if (slice.has_value())
            {
                body["slice"] = *slice;
            }
            if (searchAfter.has_value())
            {
                body["search_after"] = *searchAfter;
            }
            else
            {
                body["track_total_hits"] = true;
            }

            auto outcome = handle.search(body, deadline(m_options.callDeadline));
            if (!outcome.ok())
            {
                throwFailure("PIT search failed", outcome);
            }
            if (!outcome.value.is_object() || !outcome.value.contains("hits"))
            {
                throw std::runtime_error {"Response does not contain 'hits' field"};
            }
            return std::move(outcome.value.at("hits"));
        }

        nlohmann::json searchIndex(std::string_view index,
                                   std::size_t size,
                                   const nlohmann::json& query,
                                   const std::optional<nlohmann::json>& source) override
        {
            nlohmann::json body {{"size", size}, {"query", query}};
            if (source.has_value())
            {
                body["_source"] = *source;
            }

            auto outcome = m_query->search(index, body, queryOptions(), deadline(m_options.probeDeadline));
            if (!outcome.ok())
            {
                throwFailure("Index search failed", outcome);
            }
            // Parity with the v1 sync adapter: no hits object is an empty result.
            if (outcome.value.is_object() && outcome.value.contains("hits"))
            {
                return std::move(outcome.value.at("hits"));
            }
            return nlohmann::json::object();
        }

    private:
        indexer_client::QueryOptions queryOptions() const
        {
            indexer_client::QueryOptions options;
            options.pageDeadline = m_options.pageDeadline;
            return options;
        }

        /// The deadline of one call. With no usable node it is cut to probeDeadline: the library waits for a node
        /// without sending anything and returns its own cause (I158b). With failFastWithoutNode, once every node was
        /// probed (a Down node with a reason) and none is usable, the call fails at once instead (I190, I190b).
        indexer_client::Deadline deadline(std::chrono::milliseconds budget) const
        {
            const auto health = m_client->health();
            if (!health.anyUsable())
            {
                if (m_options.failFastWithoutNode && allProbed(health))
                {
                    std::string message {"No usable indexer node: "};
                    message += indexer_client::toString(Cause::Unavailable);
                    for (const auto& node : health.nodes)
                    {
                        message += "; ";
                        message += node.url;
                        message += ": ";
                        message += node.reason;
                    }
                    logDebug2(WM_CONTENTUPDATER, "%s", message.c_str());
                    throw std::runtime_error {message};
                }
                budget = std::min(budget, m_options.probeDeadline);
            }
            return std::chrono::steady_clock::now() + budget;
        }

        /// Every node already went through a probe round: a node is born Down with an empty reason (I190b).
        static bool allProbed(const indexer_client::HealthView& health)
        {
            return !health.nodes.empty() && std::all_of(health.nodes.begin(),
                                                        health.nodes.end(),
                                                        [](const auto& node) { return !node.reason.empty(); });
        }

        std::shared_ptr<indexer_client::IClient> m_client;
        std::shared_ptr<indexer_client::IQuery> m_query;
        const content_manager::ContentIndexerOptions m_options;
        std::mutex m_mutex;
        std::unordered_map<std::string, indexer_client::Pit> m_pits;
    };
} // namespace

namespace content_manager
{
    std::shared_ptr<IContentIndexer> makeContentIndexer(std::shared_ptr<indexer_client::IClient> client,
                                                        ContentIndexerOptions options)
    {
        return std::make_shared<ClientIndexer>(std::move(client), options);
    }

    ContentIndexerOptions contentIndexerOptionsFor(std::chrono::milliseconds requestTimeout,
                                                   std::chrono::milliseconds probeTimeout)
    {
        // The defaults are the floor: a host with shorter timeouts keeps the budgets the adapter was tuned with.
        ContentIndexerOptions options;
        if (requestTimeout.count() > 0)
        {
            options.callDeadline = std::max(options.callDeadline, requestTimeout * 2);
            options.pageDeadline = std::max(options.pageDeadline, requestTimeout * 3 / 2);
        }
        if (probeTimeout.count() > 0)
        {
            options.probeDeadline = std::max(options.probeDeadline, probeTimeout * 2);
        }
        return options;
    }
} // namespace content_manager
