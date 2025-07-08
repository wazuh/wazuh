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
#include <filesystem>
#include <fstream>
#include <grp.h>
#include <pwd.h>
#include <stringHelper.h>
#include <unistd.h>

namespace Log
{
    std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>
        GLOBAL_LOG_FUNCTION;
};

// Implementation of the facade IndexerConnectorSync
class IndexerConnectorSync::Impl
{
private:
    IndexerConnectorSyncImpl<> m_impl;

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

    void deleteByQuery(const std::string& index, const std::string& agentId)
    {
        m_impl.deleteByQuery(index, agentId);
    }

    void bulkDelete(std::string_view id, std::string_view index)
    {
        m_impl.bulkDelete(id, index);
    }

    void bulkIndex(std::string_view id, std::string_view index, std::string_view data)
    {
        m_impl.bulkIndex(id, index, data);
    }
};

IndexerConnectorSync::IndexerConnectorSync(
    const nlohmann::json& config,
    const std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>&
        logFunction)
    : m_impl(std::make_unique<Impl>(config, logFunction))
{
}

IndexerConnectorSync::~IndexerConnectorSync() = default;

void IndexerConnectorSync::deleteByQuery(const std::string& index, const std::string& agentId)
{
    m_impl->deleteByQuery(index, agentId);
}

void IndexerConnectorSync::bulkDelete(std::string_view id, std::string_view index)
{
    m_impl->bulkDelete(id, index);
}

void IndexerConnectorSync::bulkIndex(std::string_view id, std::string_view index, std::string_view data)
{
    m_impl->bulkIndex(id, index, data);
}
