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

#include "MockFimContext.hpp"
#include "MockIndexerConnector.hpp"
#include "common/clearElements.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

class FimInventoryDeleteAllEntries : public ::testing::TestWithParam<MockFimContext::AffectedComponentType>
{
protected:
    // LCOV_EXCL_START
    FimInventoryDeleteAllEntries() = default;
    ~FimInventoryDeleteAllEntries() override = default;
    // LCOV_EXCL_STOP
};

class FimInventoryDeleteAllEntriesNoAgent : public ::testing::TestWithParam<MockFimContext::AffectedComponentType>
{
protected:
    // LCOV_EXCL_START
    FimInventoryDeleteAllEntriesNoAgent() = default;
    ~FimInventoryDeleteAllEntriesNoAgent() override = default;
    // LCOV_EXCL_STOP
};

TEST_P(FimInventoryDeleteAllEntries, ClearElementsDifferentComponents)
{
    std::map<MockFimContext::AffectedComponentType, std::unique_ptr<MockIndexerConnector>, std::less<>>
        indexerConnectorInstancesFim;

    auto component = GetParam();

    // indexerConnectorInstances is not initialized with an invalid component.
    if (component != MockFimContext::AffectedComponentType::Invalid)
    {
        indexerConnectorInstancesFim.emplace(component, std::make_unique<MockIndexerConnector>());
    }

    auto context = std::make_shared<MockFimContext>();
    auto deleteElement =
        std::make_shared<ClearElements<MockFimContext, MockIndexerConnector>>(indexerConnectorInstancesFim);

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, affectedComponentType()).WillOnce(testing::Return(component));

    if (!indexerConnectorInstancesFim.empty())
    {
        EXPECT_CALL(*indexerConnectorInstancesFim[component],
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

TEST_P(FimInventoryDeleteAllEntriesNoAgent, ClearElementsDifferentComponentsNoAgent)
{
    std::map<MockFimContext::AffectedComponentType, std::unique_ptr<MockIndexerConnector>, std::less<>>
        indexerConnectorInstancesFim;

    auto component = GetParam();

    // indexerConnectorInstances is not initialized with an invalid component.
    if (component != MockFimContext::AffectedComponentType::Invalid)
    {
        indexerConnectorInstancesFim.emplace(component, std::make_unique<MockIndexerConnector>());
    }

    auto context = std::make_shared<MockFimContext>();
    auto deleteElement =
        std::make_shared<ClearElements<MockFimContext, MockIndexerConnector>>(indexerConnectorInstancesFim);

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, affectedComponentType()).WillOnce(testing::Return(component));

    if (!indexerConnectorInstancesFim.empty())
    {
        EXPECT_CALL(*indexerConnectorInstancesFim[component], publish("{\"operation\":\"DELETED_BY_QUERY\"}")).Times(1);
        EXPECT_NO_THROW(deleteElement->handleRequest(context));
    }
    else
    {
        // Exception will be captured in inventoryHarvesterFacade
        EXPECT_ANY_THROW(deleteElement->handleRequest(context));
    }
}

INSTANTIATE_TEST_SUITE_P(ClearElementsDifferentComponents,
                         FimInventoryDeleteAllEntries,
                         ::testing::Values(MockFimContext::AffectedComponentType::File,
                                           MockFimContext::AffectedComponentType::Registry,
                                           MockFimContext::AffectedComponentType::Invalid));

INSTANTIATE_TEST_SUITE_P(ClearElementsDifferentComponentsNoAgent,
                         FimInventoryDeleteAllEntriesNoAgent,
                         ::testing::Values(MockFimContext::AffectedComponentType::File,
                                           MockFimContext::AffectedComponentType::Registry,
                                           MockFimContext::AffectedComponentType::Invalid));
