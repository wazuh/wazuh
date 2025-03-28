/**
 * Wazuh Inventory Harvester - SystemInventoryDeleteElement Unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * February 9, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "MockSystemContext.hpp"
#include "systemInventory/deleteElement.hpp"

class SystemInventoryDeleteElement : public ::testing::Test
{
protected:
    // LCOV_EXCL_START
    SystemInventoryDeleteElement() = default;
    ~SystemInventoryDeleteElement() override = default;
    // LCOV_EXCL_STOP
};

TEST_F(SystemInventoryDeleteElement, emptyAgentID_OS)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Os));

    EXPECT_ANY_THROW(deleteElement->handleRequest(context));
}

TEST_F(SystemInventoryDeleteElement, validAgentID_OS)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Os));

    EXPECT_NO_THROW(deleteElement->handleRequest(context));

    EXPECT_EQ(context->m_serializedElement, R"({"id":"001","operation":"DELETED"})");
}

TEST_F(SystemInventoryDeleteElement, emptyAgentID_Packages)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Packages));

    EXPECT_ANY_THROW(deleteElement->handleRequest(context));
}

TEST_F(SystemInventoryDeleteElement, emptyPackageID_Packages)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, packageItemId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Packages));

    EXPECT_ANY_THROW(deleteElement->handleRequest(context));
}

TEST_F(SystemInventoryDeleteElement, validAgentID_Packages)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, packageItemId()).WillOnce(testing::Return("0123456789ABCDEFFEDCBA9876543210"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Packages));

    EXPECT_NO_THROW(deleteElement->handleRequest(context));

    EXPECT_EQ(context->m_serializedElement, R"({"id":"001_0123456789ABCDEFFEDCBA9876543210","operation":"DELETED"})");
}

TEST_F(SystemInventoryDeleteElement, emptyAgentID_Processes)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Processes));

    EXPECT_ANY_THROW(deleteElement->handleRequest(context));
}

TEST_F(SystemInventoryDeleteElement, emptyProcessID_Processes)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, processId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Processes));

    EXPECT_ANY_THROW(deleteElement->handleRequest(context));
}

TEST_F(SystemInventoryDeleteElement, validAgentID_Processes)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, processId()).WillOnce(testing::Return("12345"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Processes));

    EXPECT_NO_THROW(deleteElement->handleRequest(context));

    EXPECT_EQ(context->m_serializedElement, R"({"id":"001_12345","operation":"DELETED"})");
}

TEST_F(SystemInventoryDeleteElement, emptyAgentID_Ports)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Ports));

    EXPECT_ANY_THROW(deleteElement->handleRequest(context));
}

TEST_F(SystemInventoryDeleteElement, emptyItemIdPorts)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, portItemId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Ports));

    EXPECT_ANY_THROW(deleteElement->handleRequest(context));
}

TEST_F(SystemInventoryDeleteElement, validAgentID_Ports)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, portItemId()).WillOnce(testing::Return("1234"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Ports));

    EXPECT_NO_THROW(deleteElement->handleRequest(context));

    EXPECT_EQ(context->m_serializedElement, R"({"id":"001_1234","operation":"DELETED"})");
}

TEST_F(SystemInventoryDeleteElement, invalidOriginTable)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Invalid));

    EXPECT_NO_THROW(deleteElement->handleRequest(context));
}
