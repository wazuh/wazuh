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
#include "indexerConnectorAsyncImpl.hpp"
#include "loggerHelper.h"
#include "serverSelector.hpp"

// LCOV_EXCL_START
// Implementation of the facade IndexerConnectorAsync
class IndexerConnectorAsync::Impl
{
private:
    IndexerConnectorAsyncImpl<TServerSelector<HTTPRequest>, HTTPRequest> m_impl;

public:
    Impl(const nlohmann::json& config,
         const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
             logFunction)
        : m_impl(config, logFunction)
    {
    }

    void index(std::string_view id, std::string_view index, std::string_view data)
    {
        m_impl.bulkIndex(id, index, data);
    }

    void index(std::string_view id, std::string_view index, std::string_view data, std::string_view version)
    {
        m_impl.bulkIndex(id, index, data, version);
    }

    void index(std::string_view index, std::string_view data)
    {
        m_impl.bulkIndex(std::string_view(), index, data);
    }

    void indexDataStream(std::string_view index, std::string_view data)
    {
        m_impl.bulkIndexDataStream(index, data);
    }

    bool isAvailable() const
    {
        return m_impl.isAvailable();
    }

    uint64_t getQueueSize() const
    {
        return m_impl.getQueueSize();
    }

    PointInTime
    createPointInTime(const std::vector<std::string>& indices, std::string_view keepAlive, bool expandWildcards)
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
                          const std::optional<nlohmann::json>& searchAfter,
                          const std::optional<nlohmann::json>& source)
    {
        return m_impl.search(pit, size, query, sort, searchAfter, source);
    }

    nlohmann::json search(std::string_view index,
                          std::size_t size,
                          const nlohmann::json& query,
                          const std::optional<nlohmann::json>& source)
    {
        return m_impl.search(index, size, query, source);
    }
};

IndexerConnectorAsync::IndexerConnectorAsync(
    const nlohmann::json& config,
    const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
        logFunction)
    : m_impl(std::make_unique<Impl>(config, logFunction))
{
}

IndexerConnectorAsync::~IndexerConnectorAsync() = default;

void IndexerConnectorAsync::index(std::string_view id, std::string_view index, std::string_view data)
{
    m_impl->index(id, index, data);
}

void IndexerConnectorAsync::index(std::string_view id,
                                  std::string_view index,
                                  std::string_view data,
                                  std::string_view version)
{
    m_impl->index(id, index, data, version);
}

void IndexerConnectorAsync::index(std::string_view index, std::string_view data)
{
    m_impl->index(std::string_view(), index, data);
}

void IndexerConnectorAsync::indexDataStream(std::string_view index, std::string_view data)
{
    m_impl->indexDataStream(index, data);
}

bool IndexerConnectorAsync::isAvailable() const
{
    return m_impl->isAvailable();
}

uint64_t IndexerConnectorAsync::getQueueSize() const
{
    return m_impl->getQueueSize();
}

PointInTime IndexerConnectorAsync::createPointInTime(const std::vector<std::string>& indices,
                                                     std::string_view keepAlive,
                                                     bool expandWildcards)
{
    return m_impl->createPointInTime(indices, keepAlive, expandWildcards);
}

void IndexerConnectorAsync::deletePointInTime(const PointInTime& pit)
{
    m_impl->deletePointInTime(pit);
}

nlohmann::json IndexerConnectorAsync::search(const PointInTime& pit,
                                             std::size_t size,
                                             const nlohmann::json& query,
                                             const nlohmann::json& sort,
                                             const std::optional<nlohmann::json>& searchAfter,
                                             const std::optional<nlohmann::json>& source)
{
    return m_impl->search(pit, size, query, sort, searchAfter, source);
}

nlohmann::json IndexerConnectorAsync::search(std::string_view index,
                                             std::size_t size,
                                             const nlohmann::json& query,
                                             const std::optional<nlohmann::json>& source)
{
    return m_impl->search(index, size, query, source);
}

// LCOV_EXCL_STOP
