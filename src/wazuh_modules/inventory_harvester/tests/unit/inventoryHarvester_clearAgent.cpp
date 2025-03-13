/**
 * Wazuh Inventory Harvester - Clear agent Unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * February 20, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "MockFimContext.hpp"
#include "MockIndexerConnector.hpp"
#include "MockSystemContext.hpp"
#include "common/clearAgent.hpp"

using ::testing::Return;
using ::testing::StrictMock;

class InventoryHarvesterClearAgent : public ::testing::Test
{
protected:
    // LCOV_EXCL_START
    InventoryHarvesterClearAgent() = default;
    ~InventoryHarvesterClearAgent() override = default;
};

/**
 * Successful case - All indexers should receive a `publish()` call
 */
TEST_F(InventoryHarvesterClearAgent, HandleRequest_FIMContextSuccess)
{
    using MockAffectedComponentType = MockFimContext::AffectedComponentType;
    std::map<MockAffectedComponentType, std::unique_ptr<MockIndexerConnector>, std::less<>> indexerConnectors;

    auto mockIndexerFile = std::make_unique<StrictMock<MockIndexerConnector>>();
    auto mockIndexerRegistry = std::make_unique<StrictMock<MockIndexerConnector>>();

    indexerConnectors.emplace(MockAffectedComponentType::File, std::move(mockIndexerFile));
    indexerConnectors.emplace(MockAffectedComponentType::Registry, std::move(mockIndexerRegistry));

    auto context = std::make_shared<MockFimContext>();

    // Declare indexerConnectors as const to match the constructor
    const auto& constIndexerConnectors = indexerConnectors;

    ClearAgent<MockFimContext, MockIndexerConnector> clearAgent(constIndexerConnectors);

    EXPECT_CALL(*context, agentId()).Times(2).WillRepeatedly(Return("001"));

    EXPECT_CALL(*indexerConnectors[MockAffectedComponentType::File],
                publish("{\"id\":\"001\",\"operation\":\"DELETED_BY_QUERY\"}"))
        .Times(1);
    EXPECT_CALL(*indexerConnectors[MockAffectedComponentType::Registry],
                publish("{\"id\":\"001\",\"operation\":\"DELETED_BY_QUERY\"}"))
        .Times(1);

    clearAgent.handleRequest(context);
}

/**
 * Successful case - All indexers in SystemContext should receive a `publish()` call
 */
TEST_F(InventoryHarvesterClearAgent, HandleRequest_SystemContextSuccess)
{
    using MockAffectedComponentType = MockSystemContext::AffectedComponentType;
    std::map<MockAffectedComponentType, std::unique_ptr<MockIndexerConnector>, std::less<>> indexerConnectors;

    auto mockIndexerPackages = std::make_unique<StrictMock<MockIndexerConnector>>();
    auto mockIndexerProcesses = std::make_unique<StrictMock<MockIndexerConnector>>();
    auto mockIndexerSystem = std::make_unique<StrictMock<MockIndexerConnector>>();

    indexerConnectors.emplace(MockAffectedComponentType::Package, std::move(mockIndexerPackages));
    indexerConnectors.emplace(MockAffectedComponentType::Process, std::move(mockIndexerProcesses));
    indexerConnectors.emplace(MockAffectedComponentType::System, std::move(mockIndexerSystem));

    auto context = std::make_shared<MockSystemContext>();

    const auto& constIndexerConnectors = indexerConnectors;
    ClearAgent<MockSystemContext, MockIndexerConnector> clearAgent(constIndexerConnectors);

    EXPECT_CALL(*indexerConnectors[MockAffectedComponentType::Package],
                publish("{\"id\":\"001\",\"operation\":\"DELETED_BY_QUERY\"}"))
        .Times(1);
    EXPECT_CALL(*indexerConnectors[MockAffectedComponentType::Process],
                publish("{\"id\":\"001\",\"operation\":\"DELETED_BY_QUERY\"}"))
        .Times(1);
    EXPECT_CALL(*indexerConnectors[MockAffectedComponentType::System],
                publish("{\"id\":\"001\",\"operation\":\"DELETED_BY_QUERY\"}"))
        .Times(1);

    EXPECT_CALL(*context, agentId()).Times(3).WillRepeatedly(Return("001"));

    clearAgent.handleRequest(context);
}

/**
 * Failure case - No indexers exist, should not call `publish()`
 */
TEST_F(InventoryHarvesterClearAgent, HandleRequest_NoIndexers)
{
    std::map<MockFimContext::AffectedComponentType, std::unique_ptr<MockIndexerConnector>, std::less<>> emptyIndexers;
    auto context = std::make_shared<MockFimContext>();

    const auto& constIndexerConnectors = emptyIndexers;
    ClearAgent<MockFimContext, MockIndexerConnector> clearAgent(constIndexerConnectors);

    EXPECT_CALL(*context, agentId()).Times(0);

    EXPECT_NO_THROW(clearAgent.handleRequest(context)); // Ensure it doesn't crash
}
