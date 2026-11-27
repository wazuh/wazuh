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
    std::size_t pageSize {100};                 ///< Hits per request (at most: see PageSizer).
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
 *  - **The resume point of a sliced fetch is the slices' low watermark.** A slice's own token says
 *    nothing about the other slices' progress, so it is never a resume point. But every slice reads
 *    in ascending token order, so everything below the lowest token among the slices still running
 *    has been delivered: on a `Durable` acknowledgement that value is the resume point. A slice
 *    that ran dry stops counting; one that failed or was abandoned keeps holding the mark back.
 *  - **A resume point is one below the token it comes from.** The sort is (token, `_id`) and the
 *    next cycle asks for tokens strictly greater than the stored one, so documents sharing the
 *    token of a page's last hit may still be on the next page: only what is below it is certain.
 *  - **After a `Reject` the session is dead.** No sibling's page in flight reaches the sink and no
 *    resume point is reported: a sink that dropped its staged work on the rejection would otherwise
 *    acknowledge that page as durable over documents it no longer holds.
 *  - **The first slice to fail ends the fetch for all of them**, so the siblings do not keep paying
 *    full download cost for pages the sink can no longer keep.
 *  - **A page the indexer throttled is asked again on the same PIT.** A read that ended on 429s
 *    (`ThrottledError`: the adapter already waited the page's deadline through the library's backoff)
 *    is repeated with the same `search_after` and slice and half the hits, since a smaller page asks
 *    less memory of an indexer whose circuit breaker is tripping; after MAX_THROTTLED_RETRIES in a row
 *    for one page the fetch fails as before. A page that arrives resets the count. Failing instead
 *    would restart the download from its first page, which repeats the load that caused the 429s.
 *  - **A page too large for a query is asked again with half the hits** (same PIT, `search_after`
 *    and slice), down to one hit; the size grows back after a few pages that fit. Only a single
 *    document over the cap fails the fetch. The end of the data is a page shorter than the size it
 *    asked for, not than `pageSize`.
 */
class PitPaginator final
{
public:
    /// Invoked each time the sink's acknowledgement gives a new durable resume point: on the thread that
    /// delivered the page (a slice worker on a sliced fetch), with the sink calls still serialised, and
    /// always with a token past the previous one.
    using DurableCallback = std::function<void(const std::string& token)>;

    /// Times in a row one page is asked again after the indexer throttled it, before the fetch fails.
    static constexpr std::size_t MAX_THROTTLED_RETRIES = 3;

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
     * @param onDurable Called when a new durable resume point is reached (see the class notes for a
     *                  sliced fetch). May be empty.
     * @return What the fetch achieved. Never throws.
     */
    FetchOutcome run(const FetchSpec& spec,
                     content_manager::IContentSink& sink,
                     std::string_view topic,
                     const DurableCallback& onDurable = {}) noexcept
    {
        {
            std::lock_guard<std::mutex> lock {m_sinkMutex};
            m_progress.assign(spec.slices > 1 ? spec.slices : 0, SliceProgress {});
            m_lastResumePoint.clear();
            m_sessionDead = false;
        }
        m_abandon.store(false, std::memory_order_release);
        if (spec.slices <= 1)
        {
            return pageLoop(spec, sink, topic, std::nullopt, onDurable);
        }

        std::vector<FetchOutcome> results(spec.slices);
        std::vector<std::thread> workers;
        workers.reserve(spec.slices);
        for (std::size_t sliceId = 0; sliceId < spec.slices; ++sliceId)
        {
            workers.emplace_back([&, sliceId] { results[sliceId] = pageLoop(spec, sink, topic, sliceId, onDurable); });
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
            // The sink's reason for a rejection wins over whatever else failed around it.
            if (outcome.error.empty() || (result.sinkRejected && !result.error.empty()))
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
    /**
     * @brief The hits a page asks for: `pageSize`, halved while responses are too large for a query.
     *
     * After a cut, the size doubles back (capped at `pageSize`) once REGROW_AFTER pages in a row
     * fitted, so one large stretch of documents does not slow the rest of the fetch down for good.
     */
    class PageSizer final
    {
    public:
        /// Pages in a row that must fit before the size doubles back.
        static constexpr std::size_t REGROW_AFTER = 4;

        explicit PageSizer(std::size_t pageSize)
            : m_max {std::max<std::size_t>(pageSize, 1)}
            , m_size {m_max}
        {
        }

        std::size_t size() const noexcept
        {
            return m_size;
        }

        /// Halve the size. @return False when it is already 1 (nothing left to cut).
        // NOLINTNEXTLINE(modernize-use-nodiscard): the throttled retry asks again at the same size when it cannot cut
        bool shrink() noexcept
        {
            m_fitted = 0;
            if (m_size <= 1)
            {
                return false;
            }
            m_size /= 2;
            return true;
        }

        /// A page fitted at the current size.
        void grow() noexcept
        {
            if (m_size < m_max && ++m_fitted >= REGROW_AFTER)
            {
                m_size = std::min(m_max, m_size * 2);
                m_fitted = 0;
            }
        }

    private:
        std::size_t m_max;
        std::size_t m_size;
        std::size_t m_fitted {0};
    };

    static std::string sliceLabel(const std::optional<std::size_t>& sliceId, std::size_t slices)
    {
        if (!sliceId.has_value())
        {
            return {};
        }
        return " (slice " + std::to_string(*sliceId + 1) + "/" + std::to_string(slices) + ")";
    }

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
            PageSizer sizer {spec.pageSize};
            std::size_t throttledRetries = 0;
            while (!m_abandon.load(std::memory_order_acquire))
            {
                if (m_stop.load())
                {
                    outcome.interrupted = true;
                    break;
                }

                const auto size = sizer.size();
                nlohmann::json hits;
                try
                {
                    hits = m_port.search(
                        m_session.pit(), size, spec.query, spec.sort, searchAfter, spec.sourceFilter, slice);
                }
                catch (const content_manager::ResponseTooLargeError&)
                {
                    // The same page again (same PIT, cursor and slice) with half the hits; one hit that is still
                    // too large is the error it always was.
                    if (!sizer.shrink())
                    {
                        throw;
                    }
                    logDebug1(WM_CONTENTUPDATER,
                              "Page of '%s'%s too large for a query at %zu hits; retrying it with %zu.",
                              std::string {topic}.c_str(),
                              sliceLabel(sliceId, spec.slices).c_str(),
                              size,
                              sizer.size());
                    continue;
                }
                catch (const content_manager::ThrottledError& e)
                {
                    // The same page again (same PIT, cursor and slice): the adapter already waited the page's
                    // deadline through the 429s. Fewer hits ask less of the indexer; at one hit the size stays.
                    if (throttledRetries >= MAX_THROTTLED_RETRIES)
                    {
                        throw;
                    }
                    ++throttledRetries;
                    sizer.shrink();
                    logWarn(WM_CONTENTUPDATER,
                            "The indexer throttled a page of '%s'%s (%s); asking it again with %zu hits (retry %zu of "
                            "%zu).",
                            std::string {topic}.c_str(),
                            sliceLabel(sliceId, spec.slices).c_str(),
                            e.what(),
                            sizer.size(),
                            throttledRetries,
                            MAX_THROTTLED_RETRIES);
                    continue;
                }
                throttledRetries = 0;
                sizer.grow();
                const auto& hitArray = hits.at("hits");
                if (!hitArray.is_array() || hitArray.empty())
                {
                    markRanDry(sliceId);
                    break;
                }

                const auto& lastHit = hitArray.back();
                const auto pageToken = readToken(lastHit, spec.pageTokenPointer);

                const auto status = deliverPage(hitArray, pageToken, sink, topic, outcome, sliceId, onDurable);
                if (status == content_manager::PageStatus::Reject)
                {
                    m_abandon.store(true, std::memory_order_release);
                    break;
                }

                advanceHighest(outcome.highestPageToken, pageToken);
                // Against the size this page asked for: a page cut down for size is not the end.
                if (hitArray.size() < size)
                {
                    markRanDry(sliceId);
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
     * Also where the resume point is worked out: under the same mutex as the sink call, so the tokens
     * it reads are exactly those of the pages the sink had accepted when it answered `Durable`.
     *
     * @return The sink's answer; `Accepted` when nothing was left to deliver. On `Reject`,
     *         @p outcome carries the sink's reason — unless the session was already dead (another
     *         slice's page was rejected): then the sink is not called and @p outcome is left as it
     *         was, so the first rejection's reason is the one the fetch reports.
     */
    content_manager::PageStatus deliverPage(const nlohmann::json& hits,
                                            const std::string& pageToken,
                                            content_manager::IContentSink& sink,
                                            std::string_view topic,
                                            FetchOutcome& outcome,
                                            const std::optional<std::size_t>& sliceId,
                                            const DurableCallback& onDurable)
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
        if (m_sessionDead)
        {
            return content_manager::PageStatus::Reject;
        }
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
            m_sessionDead = true;
            outcome.sinkRejected = true;
            outcome.error = ack.detail;
            return ack.status;
        }

        // Order matters, and all of it under the mutex: record this page's token, then read the mark.
        if (!pageToken.empty() && sliceId.has_value())
        {
            m_progress[*sliceId].token = pageToken;
        }
        if (ack.status == content_manager::PageStatus::Durable && onDurable)
        {
            const auto resumePoint = sliceId.has_value() ? belowToken(lowestRunningToken()) : belowToken(pageToken);
            if (!resumePoint.empty() && (m_lastResumePoint.empty() || tokenLess(m_lastResumePoint, resumePoint)))
            {
                m_lastResumePoint = resumePoint;
                onDurable(resumePoint);
            }
        }
        return ack.status;
    }

    /// A slice read its last page: it no longer holds the mark back. Not for a slice that failed,
    /// was interrupted or was abandoned — what that one had left is not delivered.
    void markRanDry(const std::optional<std::size_t>& sliceId)
    {
        if (sliceId.has_value())
        {
            std::lock_guard<std::mutex> lock {m_sinkMutex};
            m_progress[*sliceId].ranDry = true;
        }
    }

    /// @pre m_sinkMutex is held.
    /// @return The lowest token among the slices still running; "" when one of them has no numeric
    ///         token yet or none is running (the commit writes the final token then).
    std::string lowestRunningToken() const
    {
        std::string lowest;
        for (const auto& slice : m_progress)
        {
            if (slice.ranDry)
            {
                continue;
            }
            std::uint64_t value = 0;
            if (!tokenHelpers::parseUnsigned(slice.token, value))
            {
                return {}; // None yet, or not a number: no order to take a lowest from.
            }
            if (lowest.empty() || tokenLess(slice.token, lowest))
            {
                lowest = slice.token;
            }
        }
        return lowest;
    }

    /// @return The token before @p token: everything up to it is delivered even when other documents
    ///         share @p token. "" when there is none worth storing: an empty or non-numeric token, or
    ///         one whose predecessor is 0, which a cursor reads as "no token" (a full fetch).
    static std::string belowToken(const std::string& token)
    {
        std::uint64_t value = 0;
        if (!tokenHelpers::parseUnsigned(token, value) || value <= 1)
        {
            return {};
        }
        return std::to_string(value - 1);
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
    /// How far one slice got. Guarded by m_sinkMutex.
    struct SliceProgress
    {
        std::string token;   ///< Token of its last accepted page; "" until one carries a token.
        bool ranDry {false}; ///< It read its last page.
    };

    std::atomic<bool> m_abandon {false}; ///< A slice failed or was rejected: every slice stops.
    std::mutex m_sinkMutex;
    std::vector<SliceProgress> m_progress; ///< One per slice of a sliced fetch; empty otherwise.
    std::string m_lastResumePoint;         ///< The last one reported: they only move forward.
    bool m_sessionDead {false};            ///< The sink rejected a page: it is not called again.
};

#endif // _PIT_PAGINATOR_HPP
