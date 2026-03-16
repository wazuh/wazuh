/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MOCK_INDEXER_CONNECTOR_SYNC_HPP
#define _MOCK_INDEXER_CONNECTOR_SYNC_HPP

#include "json.hpp"
#include "gmock/gmock.h"
#include <functional>
#include <memory>
#include <string>

/**
 * @brief GMock class for IndexerConnectorSync used by the trampoline.
 */
class MockIndexerConnectorSync
{
public:
    MockIndexerConnectorSync() = default;
    virtual ~MockIndexerConnectorSync() = default;

    MOCK_METHOD(void,
                executeSearchQueryWithPagination,
                (const std::string& index,
                 const nlohmann::json& query,
                 std::function<void(const nlohmann::json&)> onResponse));
};

/// Global mock pointer — set in test SetUp, read by the trampoline.
extern std::shared_ptr<MockIndexerConnectorSync> spIndexerConnectorSyncMock;

/**
 * @brief Trampoline that IndexerDownloader instantiates via its template parameter.
 *        Forwards all calls to the global spIndexerConnectorSyncMock.
 */
class TrampolineIndexerConnectorSync final
{
public:
    explicit TrampolineIndexerConnectorSync(const nlohmann::json& /*config*/) {}

    void executeSearchQueryWithPagination(const std::string& index,
                                          const nlohmann::json& query,
                                          std::function<void(const nlohmann::json&)> onResponse)
    {
        spIndexerConnectorSyncMock->executeSearchQueryWithPagination(index, query, std::move(onResponse));
    }
};

#endif // _MOCK_INDEXER_CONNECTOR_SYNC_HPP
