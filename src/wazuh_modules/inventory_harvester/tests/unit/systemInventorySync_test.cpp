/**
 * Wazuh Inventory Harvester - Integrity global Unit Test
 * Copyright (C) 2015, Wazuh Inc.
 * February 21, 2025.
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
#include "common/indexSync.hpp"

using ::testing::_;
using ::testing::Return;
using ::testing::StrictMock;

class InventoryHarvesterIndexSyncTestFIM : public testing::TestWithParam<MockFimContext::AffectedComponentType>
{
protected:
    void SetUp() override
    {
        // Common setup logic (if needed)
    }

    void TearDown() override
    {
        // Common teardown logic (if needed)
    }
};

class InventoryHarvesterIndexSyncTestInventory : public testing::TestWithParam<MockSystemContext::AffectedComponentType>
{
protected:
    void SetUp() override
    {
        // Common setup logic (if needed)
    }

    void TearDown() override
    {
        // Common teardown logic (if needed)
    }
};

TEST_P(InventoryHarvesterIndexSyncTestFIM, FimSyncByAffectedComponentType)
{
    std::map<MockFimContext::AffectedComponentType, std::unique_ptr<MockIndexerConnector>, std::less<>>
        indexerConnectorInstances;

    auto componentType = GetParam();

    // If the component is valid, add a connector.
    if (componentType != MockFimContext::AffectedComponentType::Invalid)
    {
        indexerConnectorInstances.emplace(componentType, std::make_unique<MockIndexerConnector>());
    }

    auto context = std::make_shared<MockFimContext>();
    auto indexSyncHandler =
        std::make_shared<IndexSync<MockFimContext, MockIndexerConnector>>(indexerConnectorInstances);

    // We always call this
    EXPECT_CALL(*context, affectedComponentType()).WillOnce(testing::Return(componentType));
    // In valid cases...
    if (componentType != MockFimContext::AffectedComponentType::Invalid)
    {
        EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));

        // For a valid component, expect a sync call.
        EXPECT_CALL(*indexerConnectorInstances[componentType], sync("001")).Times(1);

        // Should not throw.
        EXPECT_NO_THROW({
            auto result = indexSyncHandler->handleRequest(context);
            // Additional checks if needed
        });
    }
    else
    {
        // And if it's invalid, we expect an out_of_range exception
        // *and* no calls to agentId() or affectedComponentType().
        // So don't set up any EXPECT_CALL for context->agentId().

        // This will throw because we do "m_indexerConnectorInstances.at(...)"
        EXPECT_ANY_THROW({ indexSyncHandler->handleRequest(context); });
    }
}

TEST_P(InventoryHarvesterIndexSyncTestInventory, InventorySyncByAffectedComponentType)
{
    std::map<MockSystemContext::AffectedComponentType, std::unique_ptr<MockIndexerConnector>, std::less<>>
        indexerConnectorInstances;

    auto componentType = GetParam();

    // If the component is valid, add a connector.
    if (componentType != MockSystemContext::AffectedComponentType::Invalid)
    {
        indexerConnectorInstances.emplace(componentType, std::make_unique<MockIndexerConnector>());
    }

    auto context = std::make_shared<MockSystemContext>();
    auto indexSyncHandler =
        std::make_shared<IndexSync<MockSystemContext, MockIndexerConnector>>(indexerConnectorInstances);

    // We always call this
    EXPECT_CALL(*context, affectedComponentType()).WillOnce(testing::Return(componentType));
    // In valid cases...
    if (componentType != MockSystemContext::AffectedComponentType::Invalid)
    {
        EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));

        // For a valid component, expect a sync call.
        EXPECT_CALL(*indexerConnectorInstances[componentType], sync("001")).Times(1);

        // Should not throw.
        EXPECT_NO_THROW({
            auto result = indexSyncHandler->handleRequest(context);
            // Additional checks if needed
        });
    }
    else
    {
        // And if it's invalid, we expect an out_of_range exception
        // *and* no calls to agentId() or affectedComponentType().
        // So don't set up any EXPECT_CALL for context->agentId().

        // This will throw because we do "m_indexerConnectorInstances.at(...)"
        EXPECT_ANY_THROW({ indexSyncHandler->handleRequest(context); });
    }
}

// Instantiate the test suite with various component types
INSTANTIATE_TEST_SUITE_P(FimSyncByAffectedComponentType,
                         InventoryHarvesterIndexSyncTestFIM,
                         ::testing::Values(MockFimContext::AffectedComponentType::File,
                                           MockFimContext::AffectedComponentType::Registry,
                                           MockFimContext::AffectedComponentType::Invalid));

INSTANTIATE_TEST_SUITE_P(InventorySyncByAffectedComponentType,
                         InventoryHarvesterIndexSyncTestInventory,
                         ::testing::Values(MockSystemContext::AffectedComponentType::Package,
                                           MockSystemContext::AffectedComponentType::Process,
                                           MockSystemContext::AffectedComponentType::System,
                                           MockSystemContext::AffectedComponentType::Port,
                                           MockSystemContext::AffectedComponentType::Hotfix,
                                           MockSystemContext::AffectedComponentType::Hardware,
<<<<<<< HEAD
                                           MockSystemContext::AffectedComponentType::NetProto,
                                           MockSystemContext::AffectedComponentType::NetIface,
                                           MockSystemContext::AffectedComponentType::Network,
=======
                                           MockSystemContext::AffectedComponentType::NetworkAddress,
>>>>>>> d7a5890497 (change(ih): Rebase and improvement of documentation and code name)
                                           MockSystemContext::AffectedComponentType::Invalid));
