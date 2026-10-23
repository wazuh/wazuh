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

#ifndef _PIT_PAGINATOR_HPP
#define _PIT_PAGINATOR_HPP

#include "contentIndexer.hpp"
#include "contentSink.hpp"
#include "loggerHelper.h"
#include "pitSession.hpp"
#include "sharedDefs.hpp"
#include "tokenHelpers.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <iterator>
#include <json.hpp>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

/**
 * @brief Everything the paginator needs to know. No domain vocabulary in sight.
 */
struct FetchSpec
{
    nlohmann::json query;                       ///< Query to run, already scoped by the session.
    nlohmann::json sort;                        ///< Sort array; drives `search_after`.
    std::optional<nlohmann::json> sourceFilter; ///< Optional `_source` filter.
    std::string pageTokenPointer;               ///< Pointer into a hit giving its token; "" disables tokens.
    std::size_t pageSize {100};                 ///< Hits per request.
    std::size_t slices {1};                     ///< Parallel PIT slices. Only legal on a full fetch.
};

/**
 * @brief What one fetch achieved.
 */
struct FetchOutcome
{
    std::size_t documentsDelivered {0}; ///< Documents handed to the sink.
    std::string highestPageToken;       ///< Highest token observed across every page.
    bool interrupted {false};           ///< A stop was requested mid-fetch.
    bool sinkRejected {false};          ///< The sink answered `PageStatus::Reject`.
    std::string error;                  ///< Transport error, or the sink's reason on a rejection.
};

/**
 * @brief Pages a PIT into the sink. Knows nothing about CVEs, spaces or IOC types.
 *
 *  - **Every slice worker shares the host's one indexer** (D1), which accepts concurrent calls.
 *  - **Sink calls are serialised by one mutex**, so a sink never needs to be thread-safe to be
 *    sliceable.
 *  - **Durable acknowledgements only advance the resume point on the unsliced path.** A slice's
 *    highest token says nothing about the other slices' progress, so treating it as a resume point
 *    would silently skip whatever the slower slices had not delivered yet.
 *  - **The first slice to fail ends the fetch for all of them**, so the siblings do not keep paying
 *    full download cost for pages the sink can no longer keep.
 */
class PitPaginator final
{
public:
    /// Invoked, on the fetch thread, each time the sink reports a new durable resume point.
    using DurableCallback = std::function<void(const std::string& token)>;

    /**
     * @brief Build a paginator over an open session.
     *
     * @param port Indexer access. Must outlive the paginator.
     * @param session The open PIT. Must outlive the paginator.
     * @param stop Cooperative stop flag, checked between pages.
     */
    PitPaginator(content_manager::IContentIndexer& port, PitSession& session, const std::atomic<bool>& stop)
        : m_port {port}
        , m_session {session}
        , m_stop {stop}
    {
    }

    /**
     * @brief Run the fetch to completion, to interruption, or to the first hard failure.
     *
     * @param spec What to fetch.
     * @param sink Where pages go.
     * @param topic Topic name, carried on every page.
     * @param onDurable Called when a new durable resume point is reached. Never called on a sliced
     *                  fetch. May be empty.
     * @return What the fetch achieved. Never throws.
     */
    FetchOutcome run(const FetchSpec& spec,
                     content_manager::IContentSink& sink,
                     std::string_view topic,
                     const DurableCallback& onDurable = {}) noexcept
    {
        if (spec.slices <= 1)
        {
            return pageLoop(spec, sink, topic, std::nullopt, onDurable);
        }

        std::vector<FetchOutcome> results(spec.slices);
        std::vector<std::thread> workers;
        workers.reserve(spec.slices);
        for (std::size_t sliceId = 0; sliceId < spec.slices; ++sliceId)
        {
            workers.emplace_back([&, sliceId] { results[sliceId] = pageLoop(spec, sink, topic, sliceId, {}); });
        }
        for (auto& worker : workers)
        {
            worker.join();
        }

        FetchOutcome outcome;
        for (const auto& result : results)
        {
            outcome.documentsDelivered += result.documentsDelivered;
            advanceHighest(outcome.highestPageToken, result.highestPageToken);
            outcome.interrupted = outcome.interrupted || result.interrupted;
            outcome.sinkRejected = outcome.sinkRejected || result.sinkRejected;
            if (outcome.error.empty())
            {
                outcome.error = result.error;
            }
        }
        return outcome;
    }

    /**
     * @brief Order two tokens, numerically when both are integers and lexicographically otherwise.
     *
     * @param lhs First token.
     * @param rhs Second token.
     * @return True when @p lhs sorts before @p rhs.
     */
    static bool tokenLess(const std::string& lhs, const std::string& rhs)
    {
        std::uint64_t left = 0;
        std::uint64_t right = 0;
        if (tokenHelpers::parseUnsigned(lhs, left) && tokenHelpers::parseUnsigned(rhs, right))
        {
            return left < right;
        }
        if (lhs.empty())
        {
            return !rhs.empty();
        }
        return lhs < rhs;
    }

private:
    /// One slice's pages (or the whole fetch when @p sliceId is empty), until the source runs dry.
    FetchOutcome pageLoop(const FetchSpec& spec,
                          content_manager::IContentSink& sink,
                          std::string_view topic,
                          std::optional<std::size_t> sliceId,
                          const DurableCallback& onDurable) noexcept
    {
        FetchOutcome outcome;
        const auto started = std::chrono::steady_clock::now();

        try
        {
            std::optional<nlohmann::json> slice;
            if (sliceId.has_value())
            {
                slice = nlohmann::json {{"id", *sliceId}, {"max", spec.slices}};
            }

            std::optional<nlohmann::json> searchAfter;
            while (!m_abandon.load(std::memory_order_acquire))
            {
                if (m_stop.load())
                {
                    outcome.interrupted = true;
                    break;
                }

                const auto hits = m_port.search(
                    m_session.pit(), spec.pageSize, spec.query, spec.sort, searchAfter, spec.sourceFilter, slice);
                const auto& hitArray = hits.at("hits");
                if (!hitArray.is_array() || hitArray.empty())
                {
                    break;
                }

                const auto& lastHit = hitArray.back();
                const auto pageToken = readToken(lastHit, spec.pageTokenPointer);

                const auto status = deliverPage(hitArray, pageToken, sink, topic, outcome);
                if (status == content_manager::PageStatus::Reject)
                {
                    m_abandon.store(true, std::memory_order_release);
                    break;
                }
                if (status == content_manager::PageStatus::Durable && !pageToken.empty() && !sliceId.has_value() &&
                    onDurable)
                {
                    onDurable(pageToken);
                }

                advanceHighest(outcome.highestPageToken, pageToken);
                if (hitArray.size() < spec.pageSize)
                {
                    break;
                }
                searchAfter = lastHit.at("sort");
            }
        }
        catch (const std::exception& e)
        {
            outcome.error = sliceId.has_value() ? "slice " + std::to_string(*sliceId) + ": " + e.what() : e.what();
            m_abandon.store(true, std::memory_order_release);
        }
        catch (...)
        {
            outcome.error = "unknown error during fetch";
            m_abandon.store(true, std::memory_order_release);
        }

        if (sliceId.has_value())
        {
            const auto elapsed =
                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
            logDebug1(WM_CONTENTUPDATER,
                      "Slice %zu/%zu of '%s' %s: %zu docs in %lldms",
                      *sliceId + 1,
                      spec.slices,
                      std::string {topic}.c_str(),
                      !outcome.error.empty() ? "failed" : (outcome.interrupted ? "interrupted" : "ended"),
                      outcome.documentsDelivered,
                      static_cast<long long>(elapsed.count()));
        }
        return outcome;
    }

    /**
     * @brief Hand one page to the sink, minus any consumer document that slipped through.
     *
     * @return The sink's answer; `Accepted` when nothing was left to deliver. On `Reject`,
     *         @p outcome carries the sink's reason.
     */
    content_manager::PageStatus deliverPage(const nlohmann::json& hits,
                                            const std::string& pageToken,
                                            content_manager::IContentSink& sink,
                                            std::string_view topic,
                                            FetchOutcome& outcome)
    {
        nlohmann::json scratch;
        const auto& filtered = dropConsumerDocs(hits, scratch);
        if (filtered.empty())
        {
            return content_manager::PageStatus::Accepted;
        }

        content_manager::ContentPage page;
        page.topic = topic;
        page.hits = &filtered;
        page.pageToken = pageToken;

        // One mutex for every sink call, sliced or not: this is what lets a sink be written as if it
        // were single-threaded.
        std::lock_guard<std::mutex> lock {m_sinkMutex};
        content_manager::PageAck ack;
        try
        {
            ack = sink.acceptPage(page);
        }
        catch (...)
        {
            // The sink surface is noexcept; this catch makes a host that violates it fail its own
            // cycle rather than unwind across the DSO boundary.
            ack = content_manager::PageAck {content_manager::PageStatus::Reject, "sink threw from acceptPage"};
        }

        outcome.documentsDelivered += filtered.size();
        if (ack.status == content_manager::PageStatus::Reject)
        {
            outcome.sinkRejected = true;
            outcome.error = ack.detail;
        }
        return ack.status;
    }

    /// Second defence against consumer documents reaching the sink; the query-side `must_not` is the
    /// first. They fail differently, which is the point of having both.
    ///
    /// @return A reference to @p hits when nothing needed dropping, so the common case costs a scan
    ///         rather than a copy of the page; @p scratch owns the copy when one is made.
    const nlohmann::json& dropConsumerDocs(const nlohmann::json& hits, nlohmann::json& scratch) const
    {
        const auto isConsumerDoc = [this](const nlohmann::json& hit)
        {
            return m_session.isConsumerDoc(hit);
        };
        if (std::none_of(hits.begin(), hits.end(), isConsumerDoc))
        {
            return hits;
        }

        scratch = nlohmann::json::array();
        std::copy_if(hits.begin(),
                     hits.end(),
                     std::back_inserter(scratch),
                     [&isConsumerDoc](const nlohmann::json& hit) { return !isConsumerDoc(hit); });
        return scratch;
    }

    static void advanceHighest(std::string& highest, const std::string& candidate)
    {
        if (!candidate.empty() && (highest.empty() || tokenLess(highest, candidate)))
        {
            highest = candidate;
        }
    }

    static std::string readToken(const nlohmann::json& hit, const std::string& pointer)
    {
        const auto* value = tokenHelpers::resolve(hit, pointer);
        if (value == nullptr)
        {
            return {};
        }
        if (value->is_string())
        {
            return value->get<std::string>();
        }
        if (value->is_number_unsigned())
        {
            return std::to_string(value->get<std::uint64_t>());
        }
        if (value->is_number_integer())
        {
            return std::to_string(value->get<std::int64_t>());
        }
        return {};
    }

    content_manager::IContentIndexer& m_port;
    PitSession& m_session;
    const std::atomic<bool>& m_stop;
    std::atomic<bool> m_abandon {false}; ///< A slice failed or was rejected: every slice stops.
    std::mutex m_sinkMutex;
};

#endif // _PIT_PAGINATOR_HPP
