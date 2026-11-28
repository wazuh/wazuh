/*
 * Wazuh content manager - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _SLICED_DATA_HPP
#define _SLICED_DATA_HPP

#include "fakeIndexerQueryPort.hpp"
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

namespace fakes
{
    /**
     * @brief Documents behind the fake indexer, each in one slice, answered as OpenSearch would.
     *
     * A search gets the documents of its slice (all of them without one) whose offset is over the
     * query's `range … gt` (if it has one), ordered by (offset, _id), after its `search_after`, at
     * most `size` of them. Offsets may repeat: that is what the ties cases are about.
     */
    struct SlicedData
    {
        struct Doc
        {
            std::string id;
            std::uint64_t offset {0};
            std::size_t slice {0};
        };

        std::vector<Doc> docs;

        /// Adds one document per offset to @p slice, with an `_id` unique across slices.
        void add(std::size_t slice, const std::vector<std::uint64_t>& offsets)
        {
            for (const auto offset : offsets)
            {
                docs.push_back(Doc {"D" + std::to_string(offset) + "-s" + std::to_string(slice) + "-" +
                                        std::to_string(docs.size()),
                                    offset,
                                    slice});
            }
        }

        nlohmann::json answer(const FakeIndexerQueryPort::SearchCall& call) const
        {
            const auto lowerBound = greaterThan(call.query);
            std::optional<std::pair<std::uint64_t, std::string>> after;
            if (call.searchAfter.has_value())
            {
                after = std::make_pair(call.searchAfter->at(0).get<std::uint64_t>(),
                                       call.searchAfter->at(1).get<std::string>());
            }

            std::vector<Doc> matching;
            for (const auto& doc : docs)
            {
                if (call.slice.has_value() && doc.slice != call.slice->at("id").get<std::size_t>())
                {
                    continue;
                }
                if (lowerBound.has_value() && doc.offset <= *lowerBound)
                {
                    continue;
                }
                if (after.has_value() && std::tie(doc.offset, doc.id) <= std::tie(after->first, after->second))
                {
                    continue;
                }
                matching.push_back(doc);
            }
            std::sort(matching.begin(),
                      matching.end(),
                      [](const Doc& lhs, const Doc& rhs)
                      { return std::tie(lhs.offset, lhs.id) < std::tie(rhs.offset, rhs.id); });

            auto hits = nlohmann::json::array();
            for (std::size_t i = 0; i < matching.size() && i < call.size; ++i)
            {
                hits.push_back(FakeIndexerQueryPort::hit(matching[i].id, matching[i].offset));
            }
            return FakeIndexerQueryPort::hitsOf(std::move(hits));
        }

        /// @return Every `_id`.
        std::set<std::string> ids() const
        {
            std::set<std::string> all;
            for (const auto& doc : docs)
            {
                all.insert(doc.id);
            }
            return all;
        }

        /// @return The `gt` bound of the first `range` found anywhere in @p query.
        static std::optional<std::uint64_t> greaterThan(const nlohmann::json& query)
        {
            if (query.is_object())
            {
                if (query.contains("gt") && query.at("gt").is_number_unsigned())
                {
                    return query.at("gt").get<std::uint64_t>();
                }
                for (const auto& item : query.items())
                {
                    if (const auto found = greaterThan(item.value()))
                    {
                        return found;
                    }
                }
            }
            else if (query.is_array())
            {
                for (const auto& item : query)
                {
                    if (const auto found = greaterThan(item))
                    {
                        return found;
                    }
                }
            }
            return std::nullopt;
        }
    };

    /// @return The `_id` of every document the sink was handed.
    inline std::set<std::string> deliveredIds(const RecordingSink& sink)
    {
        std::set<std::string> ids;
        for (const auto& page : sink.pages)
        {
            for (const auto& hit : page)
            {
                ids.insert(hit.at("_id").get<std::string>());
            }
        }
        return ids;
    }

    /**
     * @brief Lets the searches of a sliced fetch through one at a time, in a scripted order of slices.
     *
     * `enter(slice)` blocks until it is that slice's turn; `advance()` gives the turn to the next
     * one. Whoever answers the search advances: the sink when the page reaches it, the search handler
     * itself when no page will (an empty answer, a failure). Once the order is used up every search
     * passes. Each turn starts after a short pause, so the slice that had the previous one has
     * finished what follows its answer (marking itself done, or failing). Waits are bounded: a
     * broken script fails the test's assertions instead of hanging it.
     */
    class TurnGate final
    {
    public:
        explicit TurnGate(std::vector<std::size_t> order)
            : m_order {std::move(order)}
        {
        }

        /// @return The 0-based position of this turn in the order; past its end once it is used up.
        std::size_t enter(std::size_t slice)
        {
            std::size_t turn = 0;
            {
                std::unique_lock<std::mutex> lock {m_mutex};
                ++m_entered[slice];
                m_changed.notify_all();
                m_changed.wait_for(lock,
                                   std::chrono::seconds {5},
                                   [&] { return m_next >= m_order.size() || m_order[m_next] == slice; });
                turn = m_next;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds {30});
            return turn;
        }

        void advance()
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            ++m_next;
            m_changed.notify_all();
        }

        /// Blocks (bounded) until @p slice has entered @p searches searches: it is inside one, waiting.
        void waitEntered(std::size_t slice, std::size_t searches)
        {
            std::unique_lock<std::mutex> lock {m_mutex};
            m_changed.wait_for(lock, std::chrono::seconds {5}, [&] { return m_entered[slice] >= searches; });
        }

    private:
        std::mutex m_mutex;
        std::condition_variable m_changed;
        std::vector<std::size_t> m_order;
        std::size_t m_next {0};
        std::map<std::size_t, std::size_t> m_entered;
    };
} // namespace fakes

#endif // _SLICED_DATA_HPP
