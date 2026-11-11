/*
 * Wazuh content manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INDEXER_PAGE_WALK_HPP
#define _INDEXER_PAGE_WALK_HPP

#include "json.hpp"
#include "sharedDefs.hpp"
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <optional>
#include <string>

/**
 * @brief The indexer-independent half of IndexerDownloader's PIT pagination: the page loop and the
 *        retry of a failed page request.
 *
 * Kept apart from IndexerDownloader.hpp so it can be unit-tested with fake searches: that class takes
 * IndexerConnectorSync by concrete type, so nothing that lives inside it can run without a live
 * indexer.
 *
 * Why a failed page is retried here and not by restarting the download: a page request that fails
 * has delivered nothing to the consumer, and its position (the `search_after` of the last page that
 * was processed) is still valid in the same point-in-time snapshot. Repeating that one request from
 * that position keeps every page already processed -- in a sliced load, every other slice's progress
 * too -- where the previous behaviour threw the whole load away and started again from offset 0.
 * A failure of the consumer callback is never retried: the page may be half applied, so it still
 * fails the walk.
 */
namespace IndexerPageWalk
{
    /**
     * @brief Bounds of the retry of one failed page request.
     *
     * The defaults wait 5 s, 10 s, 20 s, 40 s and 60 s (135 s in total) before giving up, on top of
     * the connector's own short 429 retry budget per request. That keeps the whole window well inside
     * the 5-minute keep-alive of the point-in-time the request belongs to, so a page that is still
     * failing after it fails the walk instead of retrying against an expired snapshot.
     */
    struct RetryPolicy
    {
        std::size_t maxRetries {5};
        std::chrono::milliseconds initialDelay {std::chrono::seconds {5}};
        std::chrono::milliseconds maxDelay {std::chrono::seconds {60}};
    };

    /**
     * @brief What one paginated walk did.
     */
    struct WalkResult
    {
        std::size_t processed {0}; ///< Documents handed to the page callback.
        std::string cursor;        ///< Offset of the last document of the last processed page.
        bool interrupted {false};  ///< The walk stopped before the last page (stop or abort).
    };

    /**
     * @brief Runs one page request, retrying it with exponential backoff when it throws.
     *
     * Every failure that is going to be retried is logged at WARNING with its reason, so the
     * operator sees why a download slowed down even when the retry then succeeds.
     *
     * @param label   Who is paging, for the log line (e.g. "Slice 0 (1/2)").
     * @param search  `() -> nlohmann::json`; may throw.
     * @param waitFor `(std::chrono::milliseconds) -> bool`; waits, and returns true to abandon
     *                (stop requested).
     * @param policy  Retry bounds.
     * @return The search result, or std::nullopt when `waitFor` asked to abandon.
     * @throws The last failure once `policy.maxRetries` retries have failed.
     */
    template<typename SearchFn, typename WaitFn>
    std::optional<nlohmann::json>
    searchWithRetry(const std::string& label, SearchFn&& search, WaitFn&& waitFor, const RetryPolicy& policy)
    {
        auto delay = policy.initialDelay;
        for (std::size_t retry = 1;; ++retry)
        {
            try
            {
                return search();
            }
            catch (const std::exception& e)
            {
                if (retry > policy.maxRetries)
                {
                    throw;
                }
                logWarn(WM_CONTENTUPDATER,
                        "IndexerDownloader: %s page request failed (%s) — retrying from the same position in "
                        "%lldms (retry %zu/%zu).",
                        label.c_str(),
                        e.what(),
                        static_cast<long long>(delay.count()),
                        retry,
                        policy.maxRetries);
            }

            if (waitFor(delay))
            {
                return std::nullopt;
            }
            delay = std::min(delay * 2, policy.maxDelay);
        }
    }

    /**
     * @brief Pages through one `search_after` sequence (a whole PIT, or one slice of it).
     *
     * @param label         Who is paging, for the log lines.
     * @param pageSize      Requested page size; a shorter page is the last one.
     * @param startCursor   Cursor reported when no page carries an offset.
     * @param search        `(const std::optional<nlohmann::json>& searchAfter) -> nlohmann::json`,
     *                      returning the `hits` object of the response; may throw (retried).
     * @param onPage        `(const nlohmann::json& hits, const std::string& cursor, std::size_t processed)`,
     *                      called for every non-empty page after `processed` was updated; may throw
     *                      (not retried: the exception leaves the walk).
     * @param stopRequested `() -> bool`, checked before every page.
     * @param waitFor       `(std::chrono::milliseconds) -> bool`, the retry wait; true abandons the walk.
     * @param policy        Retry bounds of one page request.
     */
    template<typename SearchFn, typename PageFn, typename StopFn, typename WaitFn>
    WalkResult walkPages(const std::string& label,
                         const std::size_t pageSize,
                         const std::string& startCursor,
                         SearchFn&& search,
                         PageFn&& onPage,
                         StopFn&& stopRequested,
                         WaitFn&& waitFor,
                         const RetryPolicy& policy)
    {
        WalkResult result;
        result.cursor = startCursor;
        std::optional<nlohmann::json> searchAfter = std::nullopt;

        while (true)
        {
            if (stopRequested())
            {
                result.interrupted = true;
                break;
            }

            const auto hitsObj =
                searchWithRetry(label, [&search, &searchAfter]() { return search(searchAfter); }, waitFor, policy);
            if (!hitsObj.has_value())
            {
                result.interrupted = true;
                break;
            }

            const auto& hitArray = hitsObj->at("hits");
            if (!hitArray.is_array() || hitArray.empty())
            {
                break;
            }

            const auto& lastHit = hitArray.back();
            if (lastHit.contains("_source") && lastHit.at("_source").contains("offset"))
            {
                result.cursor = std::to_string(lastHit.at("_source").at("offset").template get<uint64_t>());
            }

            result.processed += hitArray.size();
            onPage(hitArray, result.cursor, result.processed);

            if (hitArray.size() < pageSize)
            {
                break;
            }

            searchAfter = lastHit.at("sort");
        }

        return result;
    }
} // namespace IndexerPageWalk

#endif // _INDEXER_PAGE_WALK_HPP
