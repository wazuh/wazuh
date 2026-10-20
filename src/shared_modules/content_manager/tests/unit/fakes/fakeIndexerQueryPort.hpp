/*
 * Wazuh content manager - unit test fakes
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FAKE_INDEXER_QUERY_PORT_HPP
#define _FAKE_INDEXER_QUERY_PORT_HPP

// Everything the three fakes below derive from or name, included here rather than assumed from the
// includer. `MemoryTokenStore` implements `IContentTokenStore`, and leaving that header to arrive
// transitively is exactly the kind of thing that compiles in one test and not another: the suites
// that include `contentCycle.hpp` or `action.hpp` first got it for free, and the ones that start
// from `changeDetector.hpp` did not.
#include "contentIndexer.hpp"
#include "contentSink.hpp"
#include "contentTokenStore.hpp"
#include "contentTypes.hpp"
#include <algorithm>
#include <cstddef>
#include <functional>
#include <json.hpp>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace fakes
{

    /**
     * @brief A scriptable indexer.
     *
     * This is the seam the previous implementation did not have: it took `IndexerConnectorSync` by
     * concrete type, so most of it could not be exercised without a live cluster and was excluded from
     * coverage on exactly those grounds. Everything above @ref content_manager::IContentIndexer is now reachable from
     * a unit test.
     *
     * One instance serves every caller at once, as the host's connector does (D1): slice workers
     * search it concurrently, so its bookkeeping is locked and it records how many searches were in
     * flight together.
     */
    class FakeIndexerQueryPort final : public content_manager::IContentIndexer
    {
    public:
        /// One recorded search request.
        struct SearchCall
        {
            std::size_t size {0};
            nlohmann::json query;
            nlohmann::json sort;
            std::optional<nlohmann::json> searchAfter;
            std::optional<nlohmann::json> source;
            std::optional<nlohmann::json> slice;
        };

        /// Everything the fake records and is scripted with. Shared with every clone.
        struct State
        {
            std::mutex mutex;

            // --- scripted behaviour ---
            /// Answers PIT searches. Receives the call and its 0-based index within its slice (or among
            /// the unsliced calls), so a scripted "first page, then empty" holds per slice worker.
            std::function<nlohmann::json(const SearchCall&, std::size_t)> onSearch;
            /// Answers non-PIT searches with the hits object. Receives the index and the request body
            /// the call stands for (`size`, `query`, `_source`).
            std::function<nlohmann::json(std::string_view, const nlohmann::json&)> onSearchIndex;
            /// When set, openPit throws with this message.
            std::string openPitError;

            // --- recorded ---
            std::vector<std::vector<std::string>> openedIndices;
            std::vector<SearchCall> searches;
            std::vector<std::pair<std::string, nlohmann::json>> indexSearches;
            std::size_t openedPits {0};
            std::size_t closedPits {0};
            std::size_t inFlight {0};
            std::size_t maxConcurrentSearches {0}; ///< Peak number of searches in flight at once.
            /// Calls seen so far, per slice id; unsliced calls are counted under SIZE_MAX.
            std::map<std::size_t, std::size_t> callsPerSlice;
        };

        FakeIndexerQueryPort()
            : m_state {std::make_shared<State>()}
        {
        }

        /// @return The recorded and scripted state.
        const std::shared_ptr<State>& state() const noexcept
        {
            return m_state;
        }

        content_manager::ContentPit
        openPit(const std::vector<std::string>& indices, std::string_view keepAlive, bool) override
        {
            std::lock_guard<std::mutex> lock {m_state->mutex};
            if (!m_state->openPitError.empty())
            {
                throw std::runtime_error(m_state->openPitError);
            }
            m_state->openedIndices.push_back(indices);
            ++m_state->openedPits;
            return content_manager::ContentPit {"fake-pit", 0, std::string {keepAlive}};
        }

        void closePit(const content_manager::ContentPit&) noexcept override
        {
            std::lock_guard<std::mutex> lock {m_state->mutex};
            ++m_state->closedPits;
        }

        nlohmann::json search(const content_manager::ContentPit&,
                              std::size_t size,
                              const nlohmann::json& query,
                              const nlohmann::json& sort,
                              const std::optional<nlohmann::json>& searchAfter,
                              const std::optional<nlohmann::json>& source,
                              const std::optional<nlohmann::json>& slice) override
        {
            SearchCall call {size, query, sort, searchAfter, source, slice};

            std::function<nlohmann::json(const SearchCall&, std::size_t)> handler;
            std::size_t ordinal = 0;
            {
                std::lock_guard<std::mutex> lock {m_state->mutex};
                m_state->searches.push_back(call);
                handler = m_state->onSearch;
                const auto sliceKey =
                    slice.has_value() ? slice->at("id").get<std::size_t>() : std::numeric_limits<std::size_t>::max();
                ordinal = m_state->callsPerSlice[sliceKey]++;
                m_state->maxConcurrentSearches = std::max(m_state->maxConcurrentSearches, ++m_state->inFlight);
            }

            struct InFlight
            {
                State& state;
                ~InFlight()
                {
                    std::lock_guard<std::mutex> lock {state.mutex};
                    --state.inFlight;
                }
            } inFlight {*m_state};

            if (!handler)
            {
                return emptyHits();
            }
            return handler(call, ordinal);
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

            std::function<nlohmann::json(std::string_view, const nlohmann::json&)> handler;
            {
                std::lock_guard<std::mutex> lock {m_state->mutex};
                m_state->indexSearches.emplace_back(std::string {index}, body);
                handler = m_state->onSearchIndex;
            }

            if (!handler)
            {
                return emptyHits();
            }

            // Handlers may script either a whole search response or the hits object the contract
            // returns; a whole response is unwrapped, as the synchronous adapter does.
            auto response = handler(index, body);
            if (response.is_object() && response.contains("hits") && response.at("hits").is_object())
            {
                return std::move(response.at("hits"));
            }
            return response;
        }

        /// @return A hits object with no results, which terminates a fetch.
        static nlohmann::json emptyHits()
        {
            return nlohmann::json {{"hits", nlohmann::json::array()}};
        }

        /**
         * @brief Build a hits object out of raw hit documents.
         *
         * @param hits The hit documents.
         * @return The `hits` object a search returns.
         */
        static nlohmann::json hitsOf(nlohmann::json hits)
        {
            return nlohmann::json {{"hits", std::move(hits)}};
        }

        /**
         * @brief Build one CVE-shaped hit.
         *
         * @param id Document `_id`.
         * @param offset Value of `_source.offset`, which doubles as the sort key.
         * @param index Document `_index`.
         * @return The hit.
         */
        static nlohmann::json hit(const std::string& id, std::uint64_t offset, const std::string& index = "data-index")
        {
            return nlohmann::json {{"_id", id},
                                   {"_index", index},
                                   {"_source", {{"offset", offset}, {"type", "CVE"}, {"document", {{"x", 1}}}}},
                                   {"sort", nlohmann::json::array({offset, id})}};
        }

    private:
        std::shared_ptr<State> m_state;
    };

    /**
     * @brief A sink that records everything it is handed and answers whatever it is told to.
     */
    class RecordingSink final : public content_manager::IContentSink
    {
    public:
        std::vector<content_manager::SessionInfo> sessions;
        std::vector<nlohmann::json> pages;
        std::vector<std::string> pageTokens;
        std::vector<content_manager::CommitInfo> commits;
        std::vector<content_manager::AbortReason> aborts;

        content_manager::SessionDecision decision {content_manager::SessionDecision::Proceed};
        content_manager::PageStatus pageStatus {content_manager::PageStatus::Accepted};
        content_manager::CommitStatus commitStatus {content_manager::CommitStatus::Committed};

        content_manager::SessionDecision beginSession(const content_manager::SessionInfo& info) noexcept override
        {
            sessions.push_back(info);
            return decision;
        }

        content_manager::PageAck acceptPage(const content_manager::ContentPage& page) noexcept override
        {
            pages.push_back(page.hits != nullptr ? *page.hits : nlohmann::json::array());
            pageTokens.push_back(page.pageToken);
            return content_manager::PageAck {pageStatus, "recorded"};
        }

        content_manager::CommitResult commit(const content_manager::CommitInfo& info) noexcept override
        {
            commits.push_back(info);
            return content_manager::CommitResult {commitStatus, "recorded"};
        }

        void abort(content_manager::AbortReason reason, const std::string&) noexcept override
        {
            aborts.push_back(reason);
        }

        /// @return Every document delivered across every page.
        std::size_t documentCount() const
        {
            std::size_t total = 0;
            for (const auto& page : pages)
            {
                total += page.size();
            }
            return total;
        }
    };

    /**
     * @brief An in-memory token store.
     */
    class MemoryTokenStore final : public content_manager::IContentTokenStore
    {
    public:
        std::string token;
        std::vector<std::string> writes; ///< Every value written, in order. "" records a clear().
        bool storeSucceeds {true};

        std::string load(std::string_view) noexcept override
        {
            return token;
        }

        bool store(std::string_view, std::string_view value) noexcept override
        {
            if (!storeSucceeds)
            {
                return false;
            }
            token = std::string {value};
            writes.emplace_back(token);
            return true;
        }

        bool clear(std::string_view) noexcept override
        {
            token.clear();
            writes.emplace_back();
            return true;
        }
    };

} // namespace fakes

#endif // _FAKE_INDEXER_QUERY_PORT_HPP
