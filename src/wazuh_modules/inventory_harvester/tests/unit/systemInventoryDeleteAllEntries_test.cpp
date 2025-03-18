/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * February 20, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "MockIndexerConnector.hpp"
#include "MockSystemContext.hpp"
#include "common/clearElements.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

class SystemInventoryDeleteAllEntries : public ::testing::TestWithParam<MockSystemContext::AffectedComponentType>
{
protected:
    // LCOV_EXCL_START
    SystemInventoryDeleteAllEntries() = default;
    ~SystemInventoryDeleteAllEntries() override = default;
    // LCOV_EXCL_STOP
};

class SystemInventoryDeleteAllEntriesNoAgent : public ::testing::TestWithParam<MockSystemContext::AffectedComponentType>
{
protected:
    // LCOV_EXCL_START
    SystemInventoryDeleteAllEntriesNoAgent() = default;
    ~SystemInventoryDeleteAllEntriesNoAgent() override = default;
    // LCOV_EXCL_STOP
};

TEST_P(SystemInventoryDeleteAllEntries, ClearElementsDifferentComponents)
{
    std::map<MockSystemContext::AffectedComponentType, std::unique_ptr<MockIndexerConnector>, std::less<>>
        indexerConnectorInstancesSystem;

    auto component = GetParam();

    // indexerConnectorInstances is not initialized with an invalid component.
    if (component != MockSystemContext::AffectedComponentType::Invalid)
    {
        indexerConnectorInstancesSystem.emplace(component, std::make_unique<MockIndexerConnector>());
    }

    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement =
        std::make_shared<ClearElements<MockSystemContext, MockIndexerConnector>>(indexerConnectorInstancesSystem);

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, affectedComponentType()).WillOnce(testing::Return(component));

    if (!indexerConnectorInstancesSystem.empty())
    {
        EXPECT_CALL(*indexerConnectorInstancesSystem[component],
                    publish("{\"id\":\"001\",\"operation\":\"DELETED_BY_QUERY\"}"))
            .Times(1);
        EXPECT_NO_THROW(deleteElement->handleRequest(context));
    }
    else
    {
        // Exception will be captured in inventoryHarvesterFacade
        EXPECT_ANY_THROW(deleteElement->handleRequest(context));
    }
}

TEST_P(SystemInventoryDeleteAllEntriesNoAgent, ClearElementsDifferentComponentsNoAgent)
{
    std::map<MockSystemContext::AffectedComponentType, std::unique_ptr<MockIndexerConnector>, std::less<>>
        indexerConnectorInstancesSystem;

    auto component = GetParam();

    // indexerConnectorInstances is not initialized with an invalid component.
    if (component != MockSystemContext::AffectedComponentType::Invalid)
    {
        indexerConnectorInstancesSystem.emplace(component, std::make_unique<MockIndexerConnector>());
    }

    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement =
        std::make_shared<ClearElements<MockSystemContext, MockIndexerConnector>>(indexerConnectorInstancesSystem);

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, affectedComponentType()).WillOnce(testing::Return(component));

    if (!indexerConnectorInstancesSystem.empty())
    {
        EXPECT_CALL(*indexerConnectorInstancesSystem[component], publish("{\"operation\":\"DELETED_BY_QUERY\"}"))
            .Times(1);
        EXPECT_NO_THROW(deleteElement->handleRequest(context));
    }
    else
    {
        // Exception will be captured in inventoryHarvesterFacade
        EXPECT_ANY_THROW(deleteElement->handleRequest(context));
    }
}

INSTANTIATE_TEST_SUITE_P(ClearElementsDifferentComponents,
                         SystemInventoryDeleteAllEntries,
                         ::testing::Values(MockSystemContext::AffectedComponentType::Package,
                                           MockSystemContext::AffectedComponentType::Process,
                                           MockSystemContext::AffectedComponentType::System,
                                           MockSystemContext::AffectedComponentType::Invalid));

INSTANTIATE_TEST_SUITE_P(ClearElementsDifferentComponentsNoAgent,
                         SystemInventoryDeleteAllEntriesNoAgent,
                         ::testing::Values(MockSystemContext::AffectedComponentType::Package,
                                           MockSystemContext::AffectedComponentType::Process,
                                           MockSystemContext::AffectedComponentType::System,
                                           MockSystemContext::AffectedComponentType::Invalid));
