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

/*
 * Test cases for SystemInventoryUpsertElement os scenario
 * These tests check the behavior of the SystemInventoryDeleteElement class when handling requests.
 */
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

/*
 * Test cases for SystemInventoryUpsertElement package scenario
 * These tests check the behavior of the SystemInventoryDeleteElement class when handling requests.
 */
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

/*
 * Test cases for SystemInventoryUpsertElement process scenario
 * These tests check the behavior of the SystemInventoryDeleteElement class when handling requests.
 */
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

/*
 * Test cases for SystemInventoryUpsertElement ports scenario
 * These tests check the behavior of the SystemInventoryDeleteElement class when handling requests.
 */
TEST_F(SystemInventoryDeleteElement, emptyAgentID_Ports)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Ports));
    EXPECT_ANY_THROW(deleteElement->handleRequest(context));
}

TEST_F(SystemInventoryDeleteElement, emptyIPAddress_Port)
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

/*
 * Test cases for SystemInventoryUpsertElement hardware scenario
 * These tests check the behavior of the SystemInventoryDeleteElement class when handling requests.
 */
TEST_F(SystemInventoryDeleteElement, emptyAgentID_Hardware)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));

    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Hw));
    EXPECT_ANY_THROW(deleteElement->handleRequest(context));
}

TEST_F(SystemInventoryDeleteElement, emptyBoardIdHw)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, boardInfo()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Hw));

    EXPECT_NO_THROW(deleteElement->handleRequest(context));

    EXPECT_EQ(context->m_serializedElement, R"({"id":"001_unknown","operation":"DELETED"})");
}

TEST_F(SystemInventoryDeleteElement, validAgentID_Hardware)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Hw));
    EXPECT_CALL(*context, boardInfo()).WillOnce(testing::Return("AA320"));

    EXPECT_NO_THROW(deleteElement->handleRequest(context));

    EXPECT_EQ(context->m_serializedElement, R"({"id":"001_AA320","operation":"DELETED"})");
}

/*
 * Test cases for SystemInventoryUpsertElement net address scenario
 * These tests check the behavior of the SystemInventoryDeleteElement class when handling requests.
 */
TEST_F(SystemInventoryDeleteElement, emptyAgentID_NetworkAddress)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetAddress));

    EXPECT_ANY_THROW(deleteElement->handleRequest(context));
}

TEST_F(SystemInventoryDeleteElement, validAgentIp_NetworkAddress)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, netAddressItemId()).WillOnce(testing::Return("ABC"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetAddress));

    EXPECT_NO_THROW(deleteElement->handleRequest(context));

    EXPECT_EQ(context->m_serializedElement, R"({"id":"001_ABC","operation":"DELETED"})");
}

TEST_F(SystemInventoryDeleteElement, emptyNetAddressItemId_NetworkAddress)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, netAddressItemId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetAddress));

    EXPECT_ANY_THROW(deleteElement->handleRequest(context));
}

/*
 * Test cases for SystemInventoryUpsertElement hotfix scenario
 * These tests check the behavior of the SystemInventoryDeleteElement class when handling requests.
 */
TEST_F(SystemInventoryDeleteElement, emptyAgentID_Hotfixes)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Hotfixes));
    EXPECT_ANY_THROW(deleteElement->handleRequest(context));
}

TEST_F(SystemInventoryDeleteElement, emptyHotfix_Hotfixes)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, hotfixName()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Hotfixes));

    EXPECT_ANY_THROW(deleteElement->handleRequest(context));
}

TEST_F(SystemInventoryDeleteElement, validAgentID_Hotfixes)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, hotfixName()).WillOnce(testing::Return("KB12345"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Hotfixes));

    EXPECT_NO_THROW(deleteElement->handleRequest(context));

    EXPECT_EQ(context->m_serializedElement, R"({"id":"001_KB12345","operation":"DELETED"})");
}

/*
 * Test cases for SystemInventoryUpsertElement net protocol scenario
 * These tests check the behavior of the SystemInventoryDeleteElement class when handling requests.
 */
TEST_F(SystemInventoryDeleteElement, emptyAgentID_NetworkProtocol)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetworkProtocol));

    EXPECT_ANY_THROW(deleteElement->handleRequest(context));
}

TEST_F(SystemInventoryDeleteElement, emptyNetProtoItemID_NetworkProtocol)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, netProtoItemId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetworkProtocol));

    EXPECT_ANY_THROW(deleteElement->handleRequest(context));
}

TEST_F(SystemInventoryDeleteElement, validAgentID_NetworkProtocol)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, netProtoItemId()).WillOnce(testing::Return("12345"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetworkProtocol));

    EXPECT_NO_THROW(deleteElement->handleRequest(context));

    EXPECT_EQ(context->m_serializedElement, R"({"id":"001_12345","operation":"DELETED"})");
}

/**
 * Test cases for SystemInventoryUpsertElement invalid scenario
 * These tests check the behavior of the SystemInventoryDeleteElement class when handling requests.
 */
TEST_F(SystemInventoryDeleteElement, invalidOriginTable)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Invalid));

    EXPECT_NO_THROW(deleteElement->handleRequest(context));
}

/**
 * Test cases for SystemInventoryUpsertElement netiface scenario
 * These tests check the behavior of the SystemInventoryDeleteElement class when handling requests.
 */
TEST_F(SystemInventoryDeleteElement, emptyAgentID_NetIface)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetIfaces));

    EXPECT_ANY_THROW(deleteElement->handleRequest(context));
}

TEST_F(SystemInventoryDeleteElement, emptyItemId_NetIface)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, netIfaceItemId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetIfaces));

    EXPECT_ANY_THROW(deleteElement->handleRequest(context));
}

TEST_F(SystemInventoryDeleteElement, validAgentID_NetIface)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, netIfaceItemId()).WillOnce(testing::Return("12345"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetIfaces));

    EXPECT_NO_THROW(deleteElement->handleRequest(context));

    EXPECT_EQ(context->m_serializedElement, R"({"id":"001_12345","operation":"DELETED"})");
}

/**
 * Test cases for SystemInventoryUpsertElement users scenario
 * These tests check the behavior of the SystemInventoryDeleteElement class when handling requests.
 */
TEST_F(SystemInventoryDeleteElement, emptyAgentID_Users)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Users));

    EXPECT_ANY_THROW(deleteElement->handleRequest(context));
}

TEST_F(SystemInventoryDeleteElement, emptyUserName_Users)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, userName()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Users));

    EXPECT_ANY_THROW(deleteElement->handleRequest(context));
}

TEST_F(SystemInventoryDeleteElement, validAgentID_Users)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, userName()).WillOnce(testing::Return("userName"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Users));

    EXPECT_NO_THROW(deleteElement->handleRequest(context));

    EXPECT_EQ(context->m_serializedElement, R"({"id":"001_userName","operation":"DELETED"})");
}

/**
 * Test cases for SystemInventoryUpsertElement groups scenario
 * These tests check the behavior of the SystemInventoryDeleteElement class when handling requests.
 */
TEST_F(SystemInventoryDeleteElement, emptyAgentID_Groups)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Groups));

    EXPECT_ANY_THROW(deleteElement->handleRequest(context));
}

TEST_F(SystemInventoryDeleteElement, emptyGroupName_Groups)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, groupName()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Groups));

    EXPECT_ANY_THROW(deleteElement->handleRequest(context));
}

TEST_F(SystemInventoryDeleteElement, validAgentID_Groups)
{
    auto context = std::make_shared<MockSystemContext>();
    auto deleteElement = std::make_shared<DeleteSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, groupName()).WillOnce(testing::Return("sudo"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Groups));

    EXPECT_NO_THROW(deleteElement->handleRequest(context));

    EXPECT_EQ(context->m_serializedElement, R"({"id":"001_sudo","operation":"DELETED"})");
}
