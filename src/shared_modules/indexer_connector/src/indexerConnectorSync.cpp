/*
 * Wazuh - Indexer connector.
 * Copyright (C) 2015, Wazuh Inc.
 * June 2, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "HTTPRequest.hpp"
#include "indexerConnector.hpp"
#include "indexerConnectorSyncImpl.hpp"
#include "loggerHelper.h"
#include "serverSelector.hpp"

// LCOV_EXCL_START
// Implementation of the facade IndexerConnectorSync
class IndexerConnectorSync::Impl
{
private:
    IndexerConnectorSyncImpl<TServerSelector<HTTPRequest>, HTTPRequest> m_impl;

public:
    Impl(const nlohmann::json& config,
         const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
             logFunction)
        : m_impl(config, logFunction)
    {
    }

    void deleteByQuery(const std::string& index, const std::string& agentId)
    {
        m_impl.deleteByQuery(index, agentId);
    }

    void executeUpdateByQuery(const std::vector<std::string>& indices, const nlohmann::json& updateQuery)
    {
        m_impl.executeUpdateByQuery(indices, updateQuery);
    }

    nlohmann::json executeSearchQuery(const std::string& index, const nlohmann::json& searchQuery)
    {
        return m_impl.executeSearchQuery(index, searchQuery);
    }

    void executeSearchQueryWithPagination(const std::string& index,
                                          const nlohmann::json& query,
                                          std::function<void(const nlohmann::json&)> onResponse)
    {
        m_impl.executeSearchQueryWithPagination(index, query, onResponse);
    }

    PointInTime
    createPointInTime(const std::vector<std::string>& indices, std::string_view keepAlive, bool expandWildcards = false)
    {
        return m_impl.createPointInTime(indices, keepAlive, expandWildcards);
    }

    void deletePointInTime(const PointInTime& pit)
    {
        m_impl.deletePointInTime(pit);
    }

    nlohmann::json search(const PointInTime& pit,
                          std::size_t size,
                          const nlohmann::json& query,
                          const nlohmann::json& sort,
                          const std::optional<nlohmann::json>& searchAfter = std::nullopt,
                          const std::optional<nlohmann::json>& source = std::nullopt,
                          const std::optional<nlohmann::json>& slice = std::nullopt)
    {
        return m_impl.search(pit, size, query, sort, searchAfter, source, slice);
    }

    void bulkDelete(std::string_view id, std::string_view index)
    {
        m_impl.bulkDelete(id, index);
    }

    void bulkIndex(std::string_view id, std::string_view index, std::string_view data)
    {
        m_impl.bulkIndex(id, index, data);
    }

    void bulkIndex(std::string_view id, std::string_view index, std::string_view data, std::string_view version)
    {
        m_impl.bulkIndex(id, index, data, version);
    }

    void flush()
    {
        m_impl.flush();
    }

    [[nodiscard]] std::unique_lock<std::mutex> scopeLock()
    {
        return m_impl.scopeLock();
    }

    void registerNotify(std::function<void()> callback)
    {
        m_impl.registerNotify(std::move(callback));
    }

    bool isAvailable() const
    {
        return m_impl.isAvailable();
    }
};

IndexerConnectorSync::IndexerConnectorSync(
    const nlohmann::json& config,
    const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
        logFunction)
    : m_impl(std::make_unique<Impl>(config, logFunction))
{
}

IndexerConnectorSync::~IndexerConnectorSync() = default;

void IndexerConnectorSync::deleteByQuery(const std::string& index, const std::string& agentId)
{
    m_impl->deleteByQuery(index, agentId);
}

void IndexerConnectorSync::executeUpdateByQuery(const std::vector<std::string>& indices,
                                                const nlohmann::json& updateQuery)
{
    m_impl->executeUpdateByQuery(indices, updateQuery);
}

nlohmann::json IndexerConnectorSync::executeSearchQuery(const std::string& index, const nlohmann::json& searchQuery)
{
    return m_impl->executeSearchQuery(index, searchQuery);
}

void IndexerConnectorSync::executeSearchQueryWithPagination(const std::string& index,
                                                            const nlohmann::json& query,
                                                            std::function<void(const nlohmann::json&)> onResponse)
{
    m_impl->executeSearchQueryWithPagination(index, query, onResponse);
}

PointInTime IndexerConnectorSync::createPointInTime(const std::vector<std::string>& indices,
                                                    std::string_view keepAlive,
                                                    bool expandWildcards)
{
    return m_impl->createPointInTime(indices, keepAlive, expandWildcards);
}

void IndexerConnectorSync::deletePointInTime(const PointInTime& pit)
{
    m_impl->deletePointInTime(pit);
}

nlohmann::json IndexerConnectorSync::search(const PointInTime& pit,
                                            std::size_t size,
                                            const nlohmann::json& query,
                                            const nlohmann::json& sort,
                                            const std::optional<nlohmann::json>& searchAfter,
                                            const std::optional<nlohmann::json>& source,
                                            const std::optional<nlohmann::json>& slice)
{
    return m_impl->search(pit, size, query, sort, searchAfter, source, slice);
}

void IndexerConnectorSync::bulkDelete(std::string_view id, std::string_view index)
{
    m_impl->bulkDelete(id, index);
}

void IndexerConnectorSync::bulkIndex(std::string_view id, std::string_view index, std::string_view data)
{
    m_impl->bulkIndex(id, index, data);
}

void IndexerConnectorSync::bulkIndex(std::string_view id,
                                     std::string_view index,
                                     std::string_view data,
                                     std::string_view version)
{
    m_impl->bulkIndex(id, index, data, version);
}

void IndexerConnectorSync::flush()
{
    m_impl->flush();
}

[[nodiscard]] std::unique_lock<std::mutex> IndexerConnectorSync::scopeLock()
{
    return m_impl->scopeLock();
}

void IndexerConnectorSync::registerNotify(std::function<void()> callback)
{
    m_impl->registerNotify(std::move(callback));
}

bool IndexerConnectorSync::isAvailable() const
{
    return m_impl->isAvailable();
}

// LCOV_EXCL_STOP
