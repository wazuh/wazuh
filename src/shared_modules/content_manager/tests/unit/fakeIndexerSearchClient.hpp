/*
 * Wazuh content manager - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FAKE_INDEXER_SEARCH_CLIENT_HPP
#define _FAKE_INDEXER_SEARCH_CLIENT_HPP

#include "conditionSync.hpp"
#include "indexerSearchClient.hpp"
#include <algorithm>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

/**
 * @brief An in-memory index shared by every fake client the downloader creates (one per slice worker).
 *
 * Serves PIT searches the way the indexer does for the downloader's queries: `match_all` or
 * `range.offset.gt`, sorted by (offset, _id), `search_after`, `size`, and `slice` by a hash of the id.
 * Faults are injected by PIT-search ordinal: throw at request N (once), set the stop condition at
 * request N, or answer no hits for the first N requests.
 */
struct FakeIndex
{
    struct Doc
    {
        std::string id;
        uint64_t offset;
        std::string type;
    };

    struct SearchRecord
    {
        std::string pitId;
        nlohmann::json query;
        bool hasSearchAfter;
        std::optional<nlohmann::json> slice;
    };

    std::mutex mutex;
    std::vector<Doc> docs; ///< Kept sorted by (offset, id) by add().
    std::vector<SearchRecord> searches;
    size_t searchCalls {0};
    size_t pitsCreated {0};
    size_t pitsDeleted {0};
    size_t failAtRequest {0}; ///< The N-th PIT search throws (once).
    std::string failWhat {"injected failure"};
    size_t stopAtRequest {0}; ///< The N-th PIT search sets the stop condition before answering.
    std::shared_ptr<ConditionSync> stopCondition;
    size_t emptyUntilRequest {0}; ///< The first N PIT searches answer no hits.

    void add(std::string id, uint64_t offset, std::string type)
    {
        docs.push_back({std::move(id), offset, std::move(type)});
        std::sort(docs.begin(),
                  docs.end(),
                  [](const Doc& a, const Doc& b) { return std::tie(a.offset, a.id) < std::tie(b.offset, b.id); });
    }

    static size_t sliceOf(const std::string& id, size_t max)
    {
        return std::hash<std::string> {}(id) % max;
    }
};

class FakeIndexerSearchClient final : public IIndexerSearchClient
{
public:
    explicit FakeIndexerSearchClient(std::shared_ptr<FakeIndex> index)
        : m_index(std::move(index))
    {
    }

    nlohmann::json executeSearchQuery(const std::string& /*index*/, const nlohmann::json& searchQuery) override
    {
        std::lock_guard<std::mutex> lock(m_index->mutex);
        nlohmann::json hits = nlohmann::json::array();
        for (const auto& wanted : searchQuery.at("query").at("ids").at("values"))
        {
            for (const auto& doc : m_index->docs)
            {
                if (doc.id == wanted.get<std::string>())
                {
                    hits.push_back({{"_id", doc.id}});
                }
            }
        }
        return {{"hits", {{"hits", hits}}}};
    }

    SearchPit createPointInTime(const std::vector<std::string>& /*indices*/, std::string_view keepAlive) override
    {
        std::lock_guard<std::mutex> lock(m_index->mutex);
        return SearchPit {"pit-" + std::to_string(++m_index->pitsCreated), std::string {keepAlive}};
    }

    void deletePointInTime(const SearchPit& /*pit*/) override
    {
        std::lock_guard<std::mutex> lock(m_index->mutex);
        ++m_index->pitsDeleted;
    }

    nlohmann::json search(const SearchPit& pit,
                          std::size_t size,
                          const nlohmann::json& query,
                          const nlohmann::json& /*sort*/,
                          const std::optional<nlohmann::json>& searchAfter,
                          const std::optional<nlohmann::json>& /*source*/,
                          const std::optional<nlohmann::json>& slice) override
    {
        std::lock_guard<std::mutex> lock(m_index->mutex);
        const auto ordinal = ++m_index->searchCalls;
        m_index->searches.push_back({pit.id, query, searchAfter.has_value(), slice});

        if (ordinal == m_index->failAtRequest)
        {
            throw std::runtime_error(m_index->failWhat);
        }
        if (ordinal == m_index->stopAtRequest && m_index->stopCondition)
        {
            m_index->stopCondition->set(true);
        }
        if (ordinal <= m_index->emptyUntilRequest)
        {
            return {{"hits", nlohmann::json::array()}};
        }

        uint64_t minOffsetExclusive = 0;
        bool hasMin = false;
        if (query.contains("range"))
        {
            minOffsetExclusive = query.at("range").at("offset").at("gt").get<uint64_t>();
            hasMin = true;
        }
        std::optional<std::tuple<uint64_t, std::string>> after;
        if (searchAfter)
        {
            after = std::make_tuple(searchAfter->at(0).get<uint64_t>(), searchAfter->at(1).get<std::string>());
        }

        nlohmann::json hits = nlohmann::json::array();
        for (const auto& doc : m_index->docs)
        {
            if (hasMin && doc.offset <= minOffsetExclusive)
            {
                continue;
            }
            if (slice && FakeIndex::sliceOf(doc.id, slice->at("max").get<size_t>()) != slice->at("id").get<size_t>())
            {
                continue;
            }
            if (after && std::tie(doc.offset, doc.id) <= *after)
            {
                continue;
            }
            hits.push_back(
                {{"_id", doc.id},
                 {"_source", {{"offset", doc.offset}, {"type", doc.type}, {"document", nlohmann::json::object()}}},
                 {"sort", nlohmann::json::array({doc.offset, doc.id})}});
            if (hits.size() >= size)
            {
                break;
            }
        }
        return {{"hits", hits}};
    }

private:
    std::shared_ptr<FakeIndex> m_index;
};

#endif // _FAKE_INDEXER_SEARCH_CLIENT_HPP
