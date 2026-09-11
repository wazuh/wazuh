/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PIT_PAGINATOR_HPP
#define _PIT_PAGINATOR_HPP

#include "conditionSync.hpp"
#include "contentSink.hpp"
#include "indexerQueryPort.hpp"
#include "loggerHelper.h"
#include "pitSession.hpp"
#include "sharedDefs.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
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
    nlohmann::json query;                        ///< Query to run, already scoped by the session.
    nlohmann::json sort;                         ///< Sort array; drives `search_after`.
    std::optional<nlohmann::json> sourceFilter;  ///< Optional `_source` filter.
    std::string pageTokenPointer;                ///< Pointer into a hit giving its token; "" disables tokens.
    std::size_t pageSize {100};                  ///< Hits per request.
    std::size_t slices {1};                      ///< Parallel PIT slices. Only legal on a full fetch.
};

/**
 * @brief What one fetch achieved.
 */
struct FetchOutcome
{
    std::size_t documentsDelivered {0}; ///< Documents handed to the sink.
    std::string highestPageToken;       ///< Highest token observed across every page.
    std::string durableToken;           ///< Highest token the sink acknowledged as durable.
    bool interrupted {false};           ///< A stop was requested mid-fetch.
    bool sinkRejected {false};          ///< The sink answered `PageStatus::Reject`.
    std::string error;                  ///< Transport error, when the fetch could not complete.
};

/**
 * @brief Pages a PIT into the sink. Knows nothing about CVEs, spaces or IOC types.
 *
 * Absorbs the old `fetchWithPit` and `fetchWithSlicedPit`. Three rules it keeps from them, each for
 * a reason worth restating:
 *
 *  - **Each slice worker gets its own port** (`IIndexerQueryPort::clone`). HTTP state is not
 *    shareable across threads.
 *  - **Sink calls are serialised by one mutex**, so a sink never needs to be thread-safe to be
 *    sliceable.
 *  - **Durable acknowledgements only advance the resume point on the unsliced path.** A slice's
 *    highest token says nothing about the other slices' progress, so treating it as a resume point
 *    would silently skip whatever the slower slices had not delivered yet.
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
    PitPaginator(IIndexerQueryPort& port, PitSession& session, ConditionSync& stop)
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
    FetchOutcome
    run(const FetchSpec& spec, content_manager::IContentSink& sink, std::string_view topic, DurableCallback onDurable = {}) noexcept
    {
        try
        {
            if (spec.slices > 1)
            {
                return runSliced(spec, sink, topic);
            }
            return runSingle(spec, sink, topic, std::move(onDurable));
        }
        catch (const std::exception& e)
        {
            FetchOutcome outcome;
            outcome.error = e.what();
            return outcome;
        }
        catch (...)
        {
            FetchOutcome outcome;
            outcome.error = "unknown error during fetch";
            return outcome;
        }
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
        const auto numeric = [](const std::string& value)
        { return !value.empty() && value.find_first_not_of("0123456789") == std::string::npos; };

        if (numeric(lhs) && numeric(rhs))
        {
            try
            {
                return std::stoull(lhs) < std::stoull(rhs);
            }
            catch (const std::exception&)
            {
                // Out of range for uint64: fall through to the lexicographic comparison, which for
                // equal-length digit strings agrees with the numeric one anyway.
            }
        }
        if (lhs.empty())
        {
            return !rhs.empty();
        }
        return lhs < rhs;
    }

private:
    struct SliceResult
    {
        std::size_t delivered {0};
        std::string highestToken;
        std::string error;
        bool interrupted {false};
        bool rejected {false};
        bool abandoned {false}; ///< Stopped early because a sibling slice had already failed.
    };

    FetchOutcome runSingle(const FetchSpec& spec,
                           content_manager::IContentSink& sink,
                           std::string_view topic,
                           DurableCallback onDurable)
    {
        FetchOutcome outcome;
        std::optional<nlohmann::json> searchAfter;
        std::size_t pageIndex = 0;

        while (true)
        {
            if (m_stop.check())
            {
                outcome.interrupted = true;
                break;
            }

            const auto hits = m_port.search(
                m_session.pit(), spec.pageSize, spec.query, spec.sort, searchAfter, spec.sourceFilter, std::nullopt);
            const auto& hitArray = hits.at("hits");

            if (!hitArray.is_array() || hitArray.empty())
            {
                break;
            }

            const auto& lastHit = hitArray.back();
            const auto pageToken = readToken(lastHit, spec.pageTokenPointer);

            nlohmann::json scratch;
            const auto& filtered = dropConsumerDocs(hitArray, scratch);
            if (!filtered.empty())
            {
                content_manager::ContentPage page;
                page.topic = topic;
                page.hits = &filtered;
                page.pageToken = pageToken;
                page.sliceId = 0;
                page.pageIndex = pageIndex;

                const auto ack = deliver(sink, page);
                outcome.documentsDelivered += filtered.size();

                if (ack.status == content_manager::PageStatus::Reject)
                {
                    outcome.sinkRejected = true;
                    outcome.error = ack.detail;
                    break;
                }

                if (ack.status == content_manager::PageStatus::Durable && !pageToken.empty())
                {
                    outcome.durableToken = pageToken;
                    if (onDurable)
                    {
                        onDurable(pageToken);
                    }
                }
            }

            advanceHighest(outcome.highestPageToken, pageToken);
            ++pageIndex;

            if (hitArray.size() < spec.pageSize)
            {
                break;
            }

            searchAfter = lastHit.at("sort");
        }

        return outcome;
    }

    FetchOutcome runSliced(const FetchSpec& spec, content_manager::IContentSink& sink, std::string_view topic)
    {
        FetchOutcome outcome;

        std::vector<SliceResult> results(spec.slices);
        std::vector<std::thread> workers;
        workers.reserve(spec.slices);

        // The first slice to fail ends the fetch for all of them. Without this the siblings run to
        // completion feeding a sink that has already torn down its staging state on the rejection —
        // pages that can no longer be kept, paid for at full download cost.
        std::atomic<bool> abandon {false};

        logDebug1(WM_CONTENTUPDATER,
                  "Starting sliced fetch for '%s' with %zu slices, pageSize=%zu",
                  std::string {topic}.c_str(),
                  spec.slices,
                  spec.pageSize);

        for (std::size_t sliceId = 0; sliceId < spec.slices; ++sliceId)
        {
            workers.emplace_back([&, sliceId] { results[sliceId] = runSlice(spec, sink, topic, sliceId, abandon); });
        }
        for (auto& worker : workers)
        {
            worker.join();
        }

        for (const auto& result : results)
        {
            outcome.documentsDelivered += result.delivered;
            advanceHighest(outcome.highestPageToken, result.highestToken);
            outcome.interrupted = outcome.interrupted || result.interrupted;
            outcome.sinkRejected = outcome.sinkRejected || result.rejected;
            if (outcome.error.empty() && !result.error.empty())
            {
                outcome.error = result.error;
            }
        }

        // Deliberately no durableToken: a per-slice token is not a resume point, so an interrupted
        // sliced fetch restarts from scratch rather than resuming from a bound only one slice met.
        return outcome;
    }

    SliceResult runSlice(const FetchSpec& spec,
                         content_manager::IContentSink& sink,
                         std::string_view topic,
                         std::size_t sliceId,
                         std::atomic<bool>& abandon)
    {
        SliceResult result;
        const auto started = std::chrono::steady_clock::now();

        try
        {
            auto slicePort = m_port.clone();
            const nlohmann::json sliceParam {{"id", sliceId}, {"max", spec.slices}};
            std::optional<nlohmann::json> searchAfter;
            std::size_t pageIndex = 0;

            while (true)
            {
                if (abandon.load(std::memory_order_acquire))
                {
                    result.abandoned = true;
                    break;
                }

                if (m_stop.check())
                {
                    result.interrupted = true;
                    break;
                }

                const auto hits = slicePort->search(
                    m_session.pit(), spec.pageSize, spec.query, spec.sort, searchAfter, spec.sourceFilter, sliceParam);
                const auto& hitArray = hits.at("hits");

                if (!hitArray.is_array() || hitArray.empty())
                {
                    break;
                }

                const auto& lastHit = hitArray.back();
                const auto pageToken = readToken(lastHit, spec.pageTokenPointer);

                nlohmann::json scratch;
                const auto& filtered = dropConsumerDocs(hitArray, scratch);
                if (!filtered.empty())
                {
                    content_manager::ContentPage page;
                    page.topic = topic;
                    page.hits = &filtered;
                    page.pageToken = pageToken;
                    page.sliceId = sliceId;
                    page.pageIndex = pageIndex;

                    const auto ack = deliver(sink, page);
                    result.delivered += filtered.size();

                    if (ack.status == content_manager::PageStatus::Reject)
                    {
                        result.rejected = true;
                        result.error = ack.detail;
                        abandon.store(true, std::memory_order_release);
                        break;
                    }
                }

                advanceHighest(result.highestToken, pageToken);
                ++pageIndex;

                if (hitArray.size() < spec.pageSize)
                {
                    break;
                }

                searchAfter = lastHit.at("sort");
            }
        }
        catch (const std::exception& e)
        {
            result.error = "slice " + std::to_string(sliceId) + ": " + e.what();
            abandon.store(true, std::memory_order_release);
        }

        const auto elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count();
        logDebug1(WM_CONTENTUPDATER,
                  "Slice %zu/%zu of '%s' %s — %zu docs in %lldms",
                  sliceId + 1,
                  spec.slices,
                  std::string {topic}.c_str(),
                  !result.error.empty() ? "failed"
                                        : (result.interrupted ? "interrupted"
                                                              : (result.abandoned ? "abandoned" : "complete")),
                  result.delivered,
                  static_cast<long long>(elapsed));

        return result;
    }

    /// One mutex for every sink call, sliced or not: this is what lets a sink be written as if it
    /// were single-threaded.
    content_manager::PageAck deliver(content_manager::IContentSink& sink, const content_manager::ContentPage& page)
    {
        std::lock_guard<std::mutex> lock {m_sinkMutex};
        try
        {
            return sink.acceptPage(page);
        }
        catch (...)
        {
            // The sink surface is noexcept; this catch exists so that a host that violates it takes
            // down its own cycle rather than unwinding across the DSO boundary.
            return content_manager::PageAck {content_manager::PageStatus::Reject, "sink threw from acceptPage"};
        }
    }

    /// Second defence against consumer documents reaching the sink; the query-side `must_not` is the
    /// first. They fail differently, which is the point of having both.
    ///
    /// @return A reference to @p hits when nothing needed dropping, so the common case costs a scan
    ///         rather than a deep copy of the page. Filtering every page unconditionally would copy
    ///         the whole feed one page at a time to remove documents the query already excluded.
    ///         @p scratch owns the copy when one is made, so the returned reference outlives the
    ///         call for as long as the caller keeps the scratch alive.
    const nlohmann::json& dropConsumerDocs(const nlohmann::json& hits, nlohmann::json& scratch) const
    {
        if (!m_session.validationEnabled())
        {
            return hits;
        }

        const bool anyConsumerDoc = std::any_of(
            hits.begin(), hits.end(), [this](const nlohmann::json& hit) { return m_session.isConsumerDoc(hit); });

        if (!anyConsumerDoc)
        {
            return hits;
        }

        scratch = nlohmann::json::array();
        for (const auto& hit : hits)
        {
            if (!m_session.isConsumerDoc(hit))
            {
                scratch.push_back(hit);
            }
        }
        return scratch;
    }

    static void advanceHighest(std::string& highest, const std::string& candidate)
    {
        if (candidate.empty())
        {
            return;
        }
        if (highest.empty() || tokenLess(highest, candidate))
        {
            highest = candidate;
        }
    }

    static std::string readToken(const nlohmann::json& hit, const std::string& pointer)
    {
        if (pointer.empty() || pointer.front() != '/')
        {
            return {};
        }
        try
        {
            const nlohmann::json::json_pointer jp {pointer};
            if (!hit.contains(jp))
            {
                return {};
            }
            const auto& value = hit.at(jp);
            if (value.is_string())
            {
                return value.get<std::string>();
            }
            if (value.is_number_unsigned())
            {
                return std::to_string(value.get<std::uint64_t>());
            }
            if (value.is_number_integer())
            {
                return std::to_string(value.get<std::int64_t>());
            }
        }
        catch (const std::exception&)
        {
            return {};
        }
        return {};
    }

    IIndexerQueryPort& m_port;
    PitSession& m_session;
    ConditionSync& m_stop;
    std::mutex m_sinkMutex;
};

#endif // _PIT_PAGINATOR_HPP
