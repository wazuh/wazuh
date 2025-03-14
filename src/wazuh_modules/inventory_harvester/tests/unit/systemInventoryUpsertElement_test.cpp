/**
 * Wazuh Inventory Harvester - SystemInventoryUpsertElement Unit tests
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
#include "systemInventory/upsertElement.hpp"

class SystemInventoryUpsertElement : public ::testing::Test
{
protected:
    // LCOV_EXCL_START
    SystemInventoryUpsertElement() = default;
    ~SystemInventoryUpsertElement() override = default;
    // LCOV_EXCL_STOP
};

TEST_F(SystemInventoryUpsertElement, emptyAgentID_OS)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Os));

    EXPECT_ANY_THROW(upsertElement->handleRequest(context));
}

TEST_F(SystemInventoryUpsertElement, validAgentID_OS)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Os));
    EXPECT_CALL(*context, agentName()).WillOnce(testing::Return("agentName"));
    EXPECT_CALL(*context, agentVersion()).WillOnce(testing::Return("agentVersion"));
    EXPECT_CALL(*context, agentIp()).WillOnce(testing::Return("agentIp"));
    EXPECT_CALL(*context, osVersion()).WillOnce(testing::Return("osVersion"));
    EXPECT_CALL(*context, osName()).WillOnce(testing::Return("osName"));
    EXPECT_CALL(*context, osKernelRelease()).WillOnce(testing::Return("osKernelRelease"));
    EXPECT_CALL(*context, osPlatform()).WillOnce(testing::Return("osPlatform"));
    EXPECT_CALL(*context, osKernelSysName()).WillOnce(testing::Return("osKernelSysName"));
    EXPECT_CALL(*context, osArchitecture()).WillOnce(testing::Return("osArchitecture"));
    EXPECT_CALL(*context, osHostName()).WillOnce(testing::Return("osHostName"));

    EXPECT_NO_THROW(upsertElement->handleRequest(context));

    EXPECT_EQ(
        context->m_serializedElement,
        R"({"id":"001","operation":"INSERTED","data":{"agent":{"id":"001","name":"agentName","ip":"agentIp","version":"agentVersion"},"host":{"architecture":"osArchitecture","hostname":"osHostName","os":{"kernel":"osKernelRelease","name":"osName","platform":"osPlatform","version":"osVersion","type":"osKernelSysName"}}}})");
}

TEST_F(SystemInventoryUpsertElement, emptyAgentID_Packages)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Packages));

    EXPECT_ANY_THROW(upsertElement->handleRequest(context));
}

TEST_F(SystemInventoryUpsertElement, emptyPackageID_Packages)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, packageItemId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Packages));

    EXPECT_ANY_THROW(upsertElement->handleRequest(context));
}

TEST_F(SystemInventoryUpsertElement, validAgentID_Packages)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, packageItemId()).WillOnce(testing::Return("packageItemId"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Packages));
    EXPECT_CALL(*context, agentName()).WillOnce(testing::Return("agentName"));
    EXPECT_CALL(*context, agentVersion()).WillOnce(testing::Return("agentVersion"));
    EXPECT_CALL(*context, agentIp()).WillOnce(testing::Return("agentIp"));
    EXPECT_CALL(*context, packageArchitecture()).WillOnce(testing::Return("packageArchitecture"));
    EXPECT_CALL(*context, packageName()).WillOnce(testing::Return("packageName"));
    EXPECT_CALL(*context, packageVersion()).WillOnce(testing::Return("packageVersion"));
    EXPECT_CALL(*context, packageVendor()).WillOnce(testing::Return("packageVendor"));
    EXPECT_CALL(*context, packageInstallTime()).WillOnce(testing::Return("packageInstallTime"));
    EXPECT_CALL(*context, packageSize()).WillOnce(testing::Return(0));
    EXPECT_CALL(*context, packageFormat()).WillOnce(testing::Return("packageFormat"));
    EXPECT_CALL(*context, packageDescription()).WillOnce(testing::Return("packageDescription"));
    EXPECT_CALL(*context, packageLocation()).WillOnce(testing::Return("packageLocation"));

    EXPECT_NO_THROW(upsertElement->handleRequest(context));

    EXPECT_EQ(
        context->m_serializedElement,
        R"({"id":"001_packageItemId","operation":"INSERTED","data":{"package":{"architecture":"packageArchitecture","description":"packageDescription","installed":"packageInstallTime","name":"packageName","path":"packageLocation","size":0,"type":"packageFormat","version":"packageVersion","vendor":"packageVendor"},"agent":{"id":"001","name":"agentName","ip":"agentIp","version":"agentVersion"}}})");
}

TEST_F(SystemInventoryUpsertElement, emptyAgentID_Processes)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Processes));

    EXPECT_ANY_THROW(upsertElement->handleRequest(context));
}

TEST_F(SystemInventoryUpsertElement, validAgentID_Processes)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, processId()).WillOnce(testing::Return("1234"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Processes));
    EXPECT_CALL(*context, agentName()).WillOnce(testing::Return("agentName"));
    EXPECT_CALL(*context, agentVersion()).WillOnce(testing::Return("agentVersion"));
    EXPECT_CALL(*context, agentIp()).WillOnce(testing::Return("agentIp"));
    EXPECT_CALL(*context, processName()).WillOnce(testing::Return("processName"));
    EXPECT_CALL(*context, processArguments()).WillOnce(testing::Return(std::vector<std::string_view> {"processName"}));
    EXPECT_CALL(*context, processCmdline()).WillOnce(testing::Return("processCmdline"));
    EXPECT_CALL(*context, processStartISO8601()).WillOnce(testing::Return("processStartISO8601"));
    EXPECT_CALL(*context, processParentID()).WillOnce(testing::Return(1));

    EXPECT_NO_THROW(upsertElement->handleRequest(context));

    EXPECT_EQ(
        context->m_serializedElement,
        R"({"id":"001_1234","operation":"INSERTED","data":{"process":{"args":["processName"],"args_count":1,"command_line":"processCmdline","name":"processName","pid":1234,"start":"processStartISO8601","ppid":1},"agent":{"id":"001","name":"agentName","ip":"agentIp","version":"agentVersion"}}})");
}
