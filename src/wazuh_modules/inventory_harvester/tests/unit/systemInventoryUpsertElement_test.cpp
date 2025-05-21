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

/*
 * Test cases for SystemInventoryUpsertElement OS scenario
 * These tests check the behavior of the UpsertSystemElement class when handling requests.
 */
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
    EXPECT_CALL(*context, osKernelVersion()).WillOnce(testing::Return("osKernelVersion"));
    EXPECT_CALL(*context, osArchitecture()).WillOnce(testing::Return("osArchitecture"));
    EXPECT_CALL(*context, osCodeName()).WillOnce(testing::Return("osCodeName"));
    EXPECT_CALL(*context, osHostName()).WillOnce(testing::Return("osHostName"));

    EXPECT_NO_THROW(upsertElement->handleRequest(context));

    EXPECT_EQ(
        context->m_serializedElement,
        R"({"id":"001","operation":"INSERTED","data":{"agent":{"id":"001","name":"agentName","host":{"ip":"agentIp"},"version":"agentVersion"},"host":{"architecture":"osArchitecture","hostname":"osHostName","os":{"codename":"osCodeName","kernel":{"name":"osKernelSysName","release":"osKernelRelease","version":"osKernelVersion"},"name":"osName","platform":"osPlatform","version":"osVersion"}},"wazuh":{"cluster":{"name":"clusterName"},"schema":{"version":"1.0"}}}})");
}

TEST_F(SystemInventoryUpsertElement, validAgentIDAnyAgentIp_OS)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Os));
    EXPECT_CALL(*context, agentName()).WillOnce(testing::Return("agentName"));
    EXPECT_CALL(*context, agentVersion()).WillOnce(testing::Return("agentVersion"));
    // The expected value is always ip formatted string or "any". For this last case the field is not present in the
    // serialized JSON.
    EXPECT_CALL(*context, agentIp()).WillOnce(testing::Return("any"));
    EXPECT_CALL(*context, osVersion()).WillOnce(testing::Return("osVersion"));
    EXPECT_CALL(*context, osName()).WillOnce(testing::Return("osName"));
    EXPECT_CALL(*context, osKernelRelease()).WillOnce(testing::Return("osKernelRelease"));
    EXPECT_CALL(*context, osPlatform()).WillOnce(testing::Return("osPlatform"));
    EXPECT_CALL(*context, osKernelSysName()).WillOnce(testing::Return("osKernelSysName"));
    EXPECT_CALL(*context, osKernelVersion()).WillOnce(testing::Return("osKernelVersion"));
    EXPECT_CALL(*context, osArchitecture()).WillOnce(testing::Return("osArchitecture"));
    EXPECT_CALL(*context, osCodeName()).WillOnce(testing::Return("osCodeName"));
    EXPECT_CALL(*context, osHostName()).WillOnce(testing::Return("osHostName"));

    EXPECT_NO_THROW(upsertElement->handleRequest(context));

    EXPECT_EQ(
        context->m_serializedElement,
        R"({"id":"001","operation":"INSERTED","data":{"agent":{"id":"001","name":"agentName","version":"agentVersion"},"host":{"architecture":"osArchitecture","hostname":"osHostName","os":{"codename":"osCodeName","kernel":{"name":"osKernelSysName","release":"osKernelRelease","version":"osKernelVersion"},"name":"osName","platform":"osPlatform","version":"osVersion"}},"wazuh":{"cluster":{"name":"clusterName"},"schema":{"version":"1.0"}}}})");
}

/*
 * Test cases for SystemInventoryUpsertElement package scenario
 * These tests check the behavior of the UpsertSystemElement class when handling requests.
 */
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
        R"({"id":"001_packageItemId","operation":"INSERTED","data":{"package":{"architecture":"packageArchitecture","description":"packageDescription","installed":"packageInstallTime","name":"packageName","path":"packageLocation","size":0,"type":"packageFormat","version":"packageVersion","vendor":"packageVendor"},"agent":{"id":"001","name":"agentName","host":{"ip":"agentIp"},"version":"agentVersion"},"wazuh":{"cluster":{"name":"clusterName"},"schema":{"version":"1.0"}}}})");
}

/*
 * Test cases for SystemInventoryUpsertElement process scenario
 * These tests check the behavior of the UpsertSystemElement class when handling requests.
 */
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
        R"({"id":"001_1234","operation":"INSERTED","data":{"process":{"args":["processName"],"args_count":1,"command_line":"processCmdline","name":"processName","pid":1234,"start":"processStartISO8601","parent":{"pid":1}},"agent":{"id":"001","name":"agentName","host":{"ip":"agentIp"},"version":"agentVersion"},"wazuh":{"cluster":{"name":"clusterName"},"schema":{"version":"1.0"}}}})");
}

/*
 * Test cases for SystemInventoryUpsertElement ports scenario
 * These tests check the behavior of the UpsertSystemElement class when handling requests.
 */
TEST_F(SystemInventoryUpsertElement, validAgentID_Ports)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, portItemId()).WillOnce(testing::Return("portItemId"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Ports));
    EXPECT_CALL(*context, agentName()).WillOnce(testing::Return("agentName"));
    EXPECT_CALL(*context, agentVersion()).WillOnce(testing::Return("agentVersion"));
    EXPECT_CALL(*context, agentIp()).WillOnce(testing::Return("agentIp"));
    EXPECT_CALL(*context, portProtocol()).WillOnce(testing::Return("portProtocol"));
    EXPECT_CALL(*context, portRemoteIp()).WillOnce(testing::Return("portRemoteIp"));
    EXPECT_CALL(*context, portRemotePort()).WillOnce(testing::Return(1234));
    EXPECT_CALL(*context, portInode()).WillOnce(testing::Return(1111));
    EXPECT_CALL(*context, portTxQueue()).WillOnce(testing::Return(7000));
    EXPECT_CALL(*context, portRxQueue()).WillOnce(testing::Return(11000));
    EXPECT_CALL(*context, portState()).WillOnce(testing::Return("portState"));
    EXPECT_CALL(*context, portProcess()).WillOnce(testing::Return("portProcess"));
    EXPECT_CALL(*context, portPid()).WillOnce(testing::Return(4321));
    EXPECT_CALL(*context, portLocalIp()).WillOnce(testing::Return("portLocalIp"));
    EXPECT_CALL(*context, portLocalPort()).WillOnce(testing::Return(7777));

    EXPECT_NO_THROW(upsertElement->handleRequest(context));

    EXPECT_EQ(
        context->m_serializedElement,
        R"({"id":"001_portItemId","operation":"INSERTED","data":{"agent":{"id":"001","name":"agentName","host":{"ip":"agentIp"},"version":"agentVersion"},"destination":{"ip":"portRemoteIp","port":1234},"file":{"inode":"1111"},"host":{"network":{"egress":{"queue":7000},"ingress":{"queue":11000}}},"interface":{"state":"portState"},"network":{"transport":"portProtocol"},"process":{"name":"portProcess","pid":4321},"source":{"ip":"portLocalIp","port":7777},"wazuh":{"cluster":{"name":"clusterName"},"schema":{"version":"1.0"}}}})");
}

TEST_F(SystemInventoryUpsertElement, emptyAgentID_Ports)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Ports));

    EXPECT_ANY_THROW(upsertElement->handleRequest(context));
}

TEST_F(SystemInventoryUpsertElement, emptyItemId_Ports)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, portItemId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Ports));

    EXPECT_ANY_THROW(upsertElement->handleRequest(context));
}

/*
 * Test cases for SystemInventoryUpsertElement hotfixes scenario
 * These tests check the behavior of the UpsertSystemElement class when handling requests.
 */
TEST_F(SystemInventoryUpsertElement, emptyAgentID_Hotfixes)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Hotfixes));

    EXPECT_ANY_THROW(upsertElement->handleRequest(context));
}

TEST_F(SystemInventoryUpsertElement, emptyHotfix_Hotfixes)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, hotfixName()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Hotfixes));

    EXPECT_ANY_THROW(upsertElement->handleRequest(context));
}

TEST_F(SystemInventoryUpsertElement, validAgentID_Hotfixes)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, agentName()).WillOnce(testing::Return("agentName"));
    EXPECT_CALL(*context, agentVersion()).WillOnce(testing::Return("agentVersion"));
    EXPECT_CALL(*context, agentIp()).WillOnce(testing::Return("agentIp"));
    EXPECT_CALL(*context, hotfixName()).WillOnce(testing::Return("KB12345"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Hotfixes));
    EXPECT_NO_THROW(upsertElement->handleRequest(context));

    EXPECT_EQ(
        context->m_serializedElement,
        R"({"id":"001_KB12345","operation":"INSERTED","data":{"package":{"hotfix":{"name":"KB12345"}},"agent":{"id":"001","name":"agentName","host":{"ip":"agentIp"},"version":"agentVersion"},"wazuh":{"cluster":{"name":"clusterName"},"schema":{"version":"1.0"}}}})");
}

/*
 * Test cases for SystemInventoryUpsertElement hardware scenario
 * These tests check the behavior of the UpsertSystemElement class when handling requests.
 */
TEST_F(SystemInventoryUpsertElement, emptyAgentID_Hw)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Hw));

    EXPECT_ANY_THROW(upsertElement->handleRequest(context));
}

TEST_F(SystemInventoryUpsertElement, emptyBoardId_Hw)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, boardInfo()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Hw));
    EXPECT_CALL(*context, agentName()).WillOnce(testing::Return("agentName"));
    EXPECT_CALL(*context, agentVersion()).WillOnce(testing::Return("agentVersion"));
    EXPECT_CALL(*context, agentIp()).WillOnce(testing::Return("agentIp"));
    EXPECT_CALL(*context, cpuCores()).WillOnce(testing::Return(2));
    EXPECT_CALL(*context, cpuName()).WillOnce(testing::Return("cpuName"));
    EXPECT_CALL(*context, cpuFrequency()).WillOnce(testing::Return(2497));
    EXPECT_CALL(*context, freeMem()).WillOnce(testing::Return(0));
    EXPECT_CALL(*context, totalMem()).WillOnce(testing::Return(0));
    EXPECT_CALL(*context, usedMem()).WillOnce(testing::Return(0.1));

    EXPECT_NO_THROW(upsertElement->handleRequest(context));

    EXPECT_EQ(
        context->m_serializedElement,
        R"({"id":"001_unknown","operation":"INSERTED","data":{"host":{"cpu":{"cores":2,"name":"cpuName","speed":2497},"memory":{"free":0,"total":0,"used":0.1}},"agent":{"id":"001","name":"agentName","host":{"ip":"agentIp"},"version":"agentVersion"},"observer":{"serial_number":"unknown"},"wazuh":{"cluster":{"name":"clusterName"},"schema":{"version":"1.0"}}}})");
}

TEST_F(SystemInventoryUpsertElement, validAgentID_Hw)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::Hw));
    EXPECT_CALL(*context, agentName()).WillOnce(testing::Return("agentName"));
    EXPECT_CALL(*context, agentVersion()).WillOnce(testing::Return("agentVersion"));
    EXPECT_CALL(*context, agentIp()).WillOnce(testing::Return("agentIp"));
    EXPECT_CALL(*context, boardInfo()).WillOnce(testing::Return("boardInfo"));
    EXPECT_CALL(*context, cpuCores()).WillOnce(testing::Return(2));
    EXPECT_CALL(*context, cpuName()).WillOnce(testing::Return("cpuName"));
    EXPECT_CALL(*context, cpuFrequency()).WillOnce(testing::Return(2497));
    EXPECT_CALL(*context, freeMem()).WillOnce(testing::Return(0));
    EXPECT_CALL(*context, totalMem()).WillOnce(testing::Return(0));
    EXPECT_CALL(*context, usedMem()).WillOnce(testing::Return(0.1));

    EXPECT_NO_THROW(upsertElement->handleRequest(context));

    EXPECT_EQ(
        context->m_serializedElement,
        R"({"id":"001_boardInfo","operation":"INSERTED","data":{"host":{"cpu":{"cores":2,"name":"cpuName","speed":2497},"memory":{"free":0,"total":0,"used":0.1}},"agent":{"id":"001","name":"agentName","host":{"ip":"agentIp"},"version":"agentVersion"},"observer":{"serial_number":"boardInfo"},"wazuh":{"cluster":{"name":"clusterName"},"schema":{"version":"1.0"}}}})");
}

/*
 * Test cases for SystemInventoryUpsertElement net protocol scenario
 * These tests check the behavior of the UpsertSystemElement class when handling requests.
 */
TEST_F(SystemInventoryUpsertElement, emptyAgentID_NetworkProtocol)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetworkProtocol));
    EXPECT_ANY_THROW(upsertElement->handleRequest(context));
}

TEST_F(SystemInventoryUpsertElement, emptyNetProtoItemID_NetworkProtocol)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, netProtoItemId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetworkProtocol));

    EXPECT_ANY_THROW(upsertElement->handleRequest(context));
}

TEST_F(SystemInventoryUpsertElement, validAgentID_NetworkProtocol)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, agentName()).WillOnce(testing::Return("agentName"));
    EXPECT_CALL(*context, agentVersion()).WillOnce(testing::Return("agentVersion"));
    EXPECT_CALL(*context, agentIp()).WillOnce(testing::Return("agentIp"));
    EXPECT_CALL(*context, netProtoItemId()).WillOnce(testing::Return("netProtoItemId"));
    EXPECT_CALL(*context, netProtoIface()).WillOnce(testing::Return("netProtoIface"));
    EXPECT_CALL(*context, netProtoType()).WillOnce(testing::Return("netProtoType"));
    EXPECT_CALL(*context, netProtoGateway()).WillOnce(testing::Return("netProtoGateway"));
    EXPECT_CALL(*context, netProtoDhcp()).WillOnce(testing::Return("enabled"));
    EXPECT_CALL(*context, netProtoMetric()).WillOnce(testing::Return(150));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetworkProtocol));

    EXPECT_NO_THROW(upsertElement->handleRequest(context));

    EXPECT_EQ(
        context->m_serializedElement,
        R"({"id":"001_netProtoItemId","operation":"INSERTED","data":{"network":{"dhcp":true,"gateway":"netProtoGateway","metric":150,"type":"netProtoType"},"observer":{"ingress":{"interface":{"name":"netProtoIface"}}},"agent":{"id":"001","name":"agentName","host":{"ip":"agentIp"},"version":"agentVersion"},"wazuh":{"cluster":{"name":"clusterName"},"schema":{"version":"1.0"}}}})");
}

TEST_F(SystemInventoryUpsertElement, validAgentIDEmptyGateway_NetworkProtocol)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, agentName()).WillOnce(testing::Return("agentName"));
    EXPECT_CALL(*context, agentVersion()).WillOnce(testing::Return("agentVersion"));
    EXPECT_CALL(*context, agentIp()).WillOnce(testing::Return("agentIp"));
    EXPECT_CALL(*context, netProtoItemId()).WillOnce(testing::Return("netProtoItemId"));
    EXPECT_CALL(*context, netProtoIface()).WillOnce(testing::Return("netProtoIface"));
    EXPECT_CALL(*context, netProtoType()).WillOnce(testing::Return("netProtoType"));
    // The agent sets a default value for gateway " "
    EXPECT_CALL(*context, netProtoGateway()).WillOnce(testing::Return(" "));
    EXPECT_CALL(*context, netProtoDhcp()).WillOnce(testing::Return("enabled"));
    EXPECT_CALL(*context, netProtoMetric()).WillOnce(testing::Return(150));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetworkProtocol));

    EXPECT_NO_THROW(upsertElement->handleRequest(context));

    EXPECT_EQ(
        context->m_serializedElement,
        R"({"id":"001_netProtoItemId","operation":"INSERTED","data":{"network":{"dhcp":true,"metric":150,"type":"netProtoType"},"observer":{"ingress":{"interface":{"name":"netProtoIface"}}},"agent":{"id":"001","name":"agentName","host":{"ip":"agentIp"},"version":"agentVersion"},"wazuh":{"cluster":{"name":"clusterName"},"schema":{"version":"1.0"}}}})");
}

TEST_F(SystemInventoryUpsertElement, validAgentIDMultipleGateway_NetworkProtocol)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, agentName()).WillOnce(testing::Return("agentName"));
    EXPECT_CALL(*context, agentVersion()).WillOnce(testing::Return("agentVersion"));
    EXPECT_CALL(*context, agentIp()).WillOnce(testing::Return("agentIp"));
    EXPECT_CALL(*context, netProtoItemId()).WillOnce(testing::Return("netProtoItemId"));
    EXPECT_CALL(*context, netProtoIface()).WillOnce(testing::Return("netProtoIface"));
    EXPECT_CALL(*context, netProtoType()).WillOnce(testing::Return("netProtoType"));
    // The agent sends multiple gateway comma separated that can not be indexed.
    EXPECT_CALL(*context, netProtoGateway()).WillOnce(testing::Return("fe80::2,10.0.2.2"));
    EXPECT_CALL(*context, netProtoDhcp()).WillOnce(testing::Return("enabled"));
    EXPECT_CALL(*context, netProtoMetric()).WillOnce(testing::Return(150));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetworkProtocol));

    EXPECT_NO_THROW(upsertElement->handleRequest(context));

    EXPECT_EQ(
        context->m_serializedElement,
        R"({"id":"001_netProtoItemId","operation":"INSERTED","data":{"network":{"dhcp":true,"metric":150,"type":"netProtoType"},"observer":{"ingress":{"interface":{"name":"netProtoIface"}}},"agent":{"id":"001","name":"agentName","host":{"ip":"agentIp"},"version":"agentVersion"},"wazuh":{"cluster":{"name":"clusterName"},"schema":{"version":"1.0"}}}})");
}

/*
 * Test cases for SystemInventoryUpsertElement net interface scenario
 * These tests check the behavior of the UpsertSystemElement class when handling requests.
 */
TEST_F(SystemInventoryUpsertElement, emptyAgentID_NetIface)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetIfaces));

    EXPECT_ANY_THROW(upsertElement->handleRequest(context));
}

TEST_F(SystemInventoryUpsertElement, emptyItemId_NetIface)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, netIfaceItemId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetIfaces));

    EXPECT_ANY_THROW(upsertElement->handleRequest(context));
}

TEST_F(SystemInventoryUpsertElement, validAgentID_NetIface)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, agentIp()).WillOnce(testing::Return("agentIp"));
    EXPECT_CALL(*context, agentName()).WillOnce(testing::Return("agentName"));
    EXPECT_CALL(*context, agentVersion()).WillOnce(testing::Return("agentVersion"));

    EXPECT_CALL(*context, netIfaceItemId()).WillOnce(testing::Return("netIfaceItemId"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetIfaces));
    EXPECT_CALL(*context, netIfaceMac()).WillOnce(testing::Return("netIfaceMac"));
    EXPECT_CALL(*context, netIfaceRxBytes()).WillOnce(testing::Return(1));
    EXPECT_CALL(*context, netIfaceRxDrops()).WillOnce(testing::Return(2));
    EXPECT_CALL(*context, netIfaceRxErrors()).WillOnce(testing::Return(3));
    EXPECT_CALL(*context, netIfaceRxPackets()).WillOnce(testing::Return(4));
    EXPECT_CALL(*context, netIfaceTxBytes()).WillOnce(testing::Return(5));
    EXPECT_CALL(*context, netIfaceTxDrops()).WillOnce(testing::Return(6));
    EXPECT_CALL(*context, netIfaceTxErrors()).WillOnce(testing::Return(7));
    EXPECT_CALL(*context, netIfaceTxPackets()).WillOnce(testing::Return(8));

    EXPECT_CALL(*context, netIfaceAdapter()).WillOnce(testing::Return("netIfaceAdapter"));
    EXPECT_CALL(*context, netIfaceName()).WillOnce(testing::Return("netIfaceName"));
    EXPECT_CALL(*context, netIfaceMtu()).WillOnce(testing::Return(9));
    EXPECT_CALL(*context, netIfaceState()).WillOnce(testing::Return("netIfaceState"));
    EXPECT_CALL(*context, netIfaceType()).WillOnce(testing::Return("netIfaceType"));

    EXPECT_NO_THROW(upsertElement->handleRequest(context));

    EXPECT_EQ(
        context->m_serializedElement,
        R"({"id":"001_netIfaceItemId","operation":"INSERTED","data":{"agent":{"id":"001","name":"agentName","host":{"ip":"agentIp"},"version":"agentVersion"},"host":{"mac":"netIfaceMac","network":{"ingress":{"bytes":1,"drops":2,"errors":3,"packets":4},"egress":{"bytes":5,"drops":6,"errors":7,"packets":8}}},"observer":{"ingress":{"interface":{"alias":"netIfaceAdapter","mtu":9,"name":"netIfaceName","state":"netIfaceState","type":"netIfaceType"}}},"wazuh":{"cluster":{"name":"clusterName"},"schema":{"version":"1.0"}}}})");
}

/*
 * Test cases for SystemInventoryUpsertElement network address scenario
 * These tests check the behavior of the UpsertSystemElement class when handling requests.
 */
TEST_F(SystemInventoryUpsertElement, emptyAgentID_NetworkAddress)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetAddress));

    EXPECT_ANY_THROW(upsertElement->handleRequest(context));
}

TEST_F(SystemInventoryUpsertElement, emptyNetAddressID_NetworkAddress)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, netAddressItemId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetAddress));

    EXPECT_ANY_THROW(upsertElement->handleRequest(context));
}

TEST_F(SystemInventoryUpsertElement, validAgentID_NetworkAddress)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, netAddressItemId()).WillOnce(testing::Return("netAddressItemId"));
    EXPECT_CALL(*context, agentIp()).WillOnce(testing::Return("192.168.0.1"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetAddress));
    EXPECT_CALL(*context, agentName()).WillOnce(testing::Return("agentName"));
    EXPECT_CALL(*context, agentVersion()).WillOnce(testing::Return("agentVersion"));
    EXPECT_CALL(*context, broadcast()).WillOnce(testing::Return("192.168.0.255"));
    EXPECT_CALL(*context, netAddressName()).WillOnce(testing::Return("eth0"));
    EXPECT_CALL(*context, netmask()).WillOnce(testing::Return("255.255.255.0"));
    EXPECT_CALL(*context, address()).WillOnce(testing::Return("192.168.0.1"));
    EXPECT_CALL(*context, protocol()).WillOnce(testing::Return(0));

    EXPECT_NO_THROW(upsertElement->handleRequest(context));

    EXPECT_EQ(
        context->m_serializedElement,
        R"({"id":"001_netAddressItemId","operation":"INSERTED","data":{"network":{"broadcast":"192.168.0.255","ip":"192.168.0.1","name":"eth0","netmask":"255.255.255.0","protocol":"IPv4"},"agent":{"id":"001","name":"agentName","host":{"ip":"192.168.0.1"},"version":"agentVersion"},"wazuh":{"cluster":{"name":"clusterName"},"schema":{"version":"1.0"}}}})");
}

TEST_F(SystemInventoryUpsertElement, validAgentIDEmptyBroadcast_NetworkAddress)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, netAddressItemId()).WillOnce(testing::Return("netAddressItemId"));
    EXPECT_CALL(*context, agentIp()).WillOnce(testing::Return("192.168.0.1"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetAddress));
    EXPECT_CALL(*context, agentName()).WillOnce(testing::Return("agentName"));
    EXPECT_CALL(*context, agentVersion()).WillOnce(testing::Return("agentVersion"));
    // The agent sets a default value for broadcast " "
    EXPECT_CALL(*context, broadcast()).WillOnce(testing::Return(" "));
    EXPECT_CALL(*context, netAddressName()).WillOnce(testing::Return("eth0"));
    EXPECT_CALL(*context, netmask()).WillOnce(testing::Return("255.255.255.0"));
    EXPECT_CALL(*context, address()).WillOnce(testing::Return("192.168.0.1"));
    EXPECT_CALL(*context, protocol()).WillOnce(testing::Return(0));

    EXPECT_NO_THROW(upsertElement->handleRequest(context));

    EXPECT_EQ(
        context->m_serializedElement,
        R"({"id":"001_netAddressItemId","operation":"INSERTED","data":{"network":{"ip":"192.168.0.1","name":"eth0","netmask":"255.255.255.0","protocol":"IPv4"},"agent":{"id":"001","name":"agentName","host":{"ip":"192.168.0.1"},"version":"agentVersion"},"wazuh":{"cluster":{"name":"clusterName"},"schema":{"version":"1.0"}}}})");
}

TEST_F(SystemInventoryUpsertElement, validAgentIDEmptyNetmask_NetworkAddress)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, netAddressItemId()).WillOnce(testing::Return("netAddressItemId"));
    EXPECT_CALL(*context, agentIp()).WillOnce(testing::Return("192.168.0.1"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetAddress));
    EXPECT_CALL(*context, agentName()).WillOnce(testing::Return("agentName"));
    EXPECT_CALL(*context, agentVersion()).WillOnce(testing::Return("agentVersion"));
    EXPECT_CALL(*context, broadcast()).WillOnce(testing::Return("192.168.0.255"));
    EXPECT_CALL(*context, netAddressName()).WillOnce(testing::Return("eth0"));
    // Added for completeness I don't see the agent sending space strings
    EXPECT_CALL(*context, netmask()).WillOnce(testing::Return(" "));
    EXPECT_CALL(*context, address()).WillOnce(testing::Return("192.168.0.1"));
    EXPECT_CALL(*context, protocol()).WillOnce(testing::Return(0));

    EXPECT_NO_THROW(upsertElement->handleRequest(context));

    EXPECT_EQ(
        context->m_serializedElement,
        R"({"id":"001_netAddressItemId","operation":"INSERTED","data":{"network":{"broadcast":"192.168.0.255","ip":"192.168.0.1","name":"eth0","protocol":"IPv4"},"agent":{"id":"001","name":"agentName","host":{"ip":"192.168.0.1"},"version":"agentVersion"},"wazuh":{"cluster":{"name":"clusterName"},"schema":{"version":"1.0"}}}})");
}

TEST_F(SystemInventoryUpsertElement, validAgentIDEmptyAddress_NetworkAddress)
{
    auto context = std::make_shared<MockSystemContext>();
    auto upsertElement = std::make_shared<UpsertSystemElement<MockSystemContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return("001"));
    EXPECT_CALL(*context, netAddressItemId()).WillOnce(testing::Return("netAddressItemId"));
    EXPECT_CALL(*context, agentIp()).WillOnce(testing::Return("192.168.0.1"));
    EXPECT_CALL(*context, originTable()).WillOnce(testing::Return(MockSystemContext::OriginTable::NetAddress));
    EXPECT_CALL(*context, agentName()).WillOnce(testing::Return("agentName"));
    EXPECT_CALL(*context, agentVersion()).WillOnce(testing::Return("agentVersion"));
    EXPECT_CALL(*context, broadcast()).WillOnce(testing::Return("192.168.0.255"));
    EXPECT_CALL(*context, netAddressName()).WillOnce(testing::Return("eth0"));
    EXPECT_CALL(*context, netmask()).WillOnce(testing::Return("255.255.255.0"));
    // Added for completeness I don't see the agent sending space strings
    EXPECT_CALL(*context, address()).WillOnce(testing::Return(" "));
    EXPECT_CALL(*context, protocol()).WillOnce(testing::Return(0));

    EXPECT_NO_THROW(upsertElement->handleRequest(context));

    EXPECT_EQ(
        context->m_serializedElement,
        R"({"id":"001_netAddressItemId","operation":"INSERTED","data":{"network":{"broadcast":"192.168.0.255","name":"eth0","netmask":"255.255.255.0","protocol":"IPv4"},"agent":{"id":"001","name":"agentName","host":{"ip":"192.168.0.1"},"version":"agentVersion"},"wazuh":{"cluster":{"name":"clusterName"},"schema":{"version":"1.0"}}}})");
}
