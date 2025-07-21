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
#include "serverSelector.hpp"

// LCOV_EXCL_START
// Implementation of the facade IndexerConnectorAsync
class IndexerConnectorAsync::Impl
{
private:
    IndexerConnectorAsyncImpl<TServerSelector<HTTPRequest>, HTTPRequest> m_impl;

public:
    Impl(const nlohmann::json& config,
         const std::function<void(const int,
                                  const std::string&,
                                  const std::string&,
                                  const int,
                                  const std::string&,
                                  const std::string&,
                                  va_list)>& logFunction)
        : m_impl(config, logFunction)
    {
    }

    void index(std::string_view id, std::string_view index, std::string_view data)
    {
        m_impl.bulkIndex(id, index, data);
    }

    void index(std::string_view index, std::string_view data)
    {
        m_impl.bulkIndex(std::string_view(), index, data);
    }
};

IndexerConnectorAsync::IndexerConnectorAsync(
    const nlohmann::json& config,
    const std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>&
        logFunction)
    : m_impl(std::make_unique<Impl>(config, logFunction))
{
}

IndexerConnectorAsync::~IndexerConnectorAsync() = default;

void IndexerConnectorAsync::index(std::string_view id, std::string_view index, std::string_view data)
{
    m_impl->index(id, index, data);
}

void IndexerConnectorAsync::index(std::string_view index, std::string_view data)
{
    m_impl->index(std::string_view(), index, data);
}

// LCOV_EXCL_STOP
