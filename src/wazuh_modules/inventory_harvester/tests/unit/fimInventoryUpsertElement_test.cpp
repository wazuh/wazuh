/**
 * Wazuh Inventory Harvester - FimInventoryUpsertElement Unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * April 9, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "gmock/gmock-spec-builders.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iostream>

#include "MockFimContext.hpp"
#include "fimInventory/upsertElement.hpp"

class FimInventoryUpsertElement : public ::testing::Test
{
protected:
    // LCOV_EXCL_START
    FimInventoryUpsertElement() = default;
    ~FimInventoryUpsertElement() override = default;
    // LCOV_EXCL_STOP
};

/*
 * Test cases for FimInventoryUpsertElement registry scenario
 * These tests check the behavior of the UpsertSystemElement class when handling requests.
 */
TEST_F(FimInventoryUpsertElement, emptyAgentID_Registry)
{
    auto context = std::make_shared<MockFimContext>();
    auto upsertElement = std::make_shared<UpsertFimElement<MockFimContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillRepeatedly(testing::Return(MockFimContext::OriginTable::RegistryKey));

    EXPECT_ANY_THROW(upsertElement->handleRequest(context));
}

TEST_F(FimInventoryUpsertElement, valid_Registry)
{
    auto context = std::make_shared<MockFimContext>();
    auto upsertElement = std::make_shared<UpsertFimElement<MockFimContext>>();
    EXPECT_CALL(*context, originTable()).WillRepeatedly(testing::Return(MockFimContext::OriginTable::RegistryKey));

    EXPECT_CALL(*context, agentId()).WillRepeatedly(testing::Return("001"));
    EXPECT_CALL(*context, agentIp()).WillRepeatedly(testing::Return("agentIp"));
    EXPECT_CALL(*context, path()).WillRepeatedly(testing::Return("HKLM\\Software\\App"));
    EXPECT_CALL(*context, index()).WillRepeatedly(testing::Return("HASH_HASH"));
    EXPECT_CALL(*context, agentName()).WillRepeatedly(testing::Return("agent-reg"));
    EXPECT_CALL(*context, agentVersion()).WillRepeatedly(testing::Return("agentVersion"));
    EXPECT_CALL(*context, hive()).WillRepeatedly(testing::Return("HKLM"));
    EXPECT_CALL(*context, key()).WillRepeatedly(testing::Return("Software\\App"));
    EXPECT_CALL(*context, uid()).WillRepeatedly(testing::Return("uid"));
    EXPECT_CALL(*context, userName()).WillRepeatedly(testing::Return("userName"));
    EXPECT_CALL(*context, gid()).WillRepeatedly(testing::Return("gid"));
    EXPECT_CALL(*context, groupName()).WillRepeatedly(testing::Return("groupName"));
    EXPECT_CALL(*context, arch()).WillRepeatedly(testing::Return("x86"));
    EXPECT_CALL(*context, mtimeISO8601()).WillRepeatedly(testing::Return("2025-04-09T15:45:00Z"));
    EXPECT_CALL(*context, elementType()).WillRepeatedly(testing::Return("registry_key"));

    const auto& configJson = nlohmann::json::parse(R"({
        "clusterName": "clusterName",
        "clusterEnabled": false
    })");
    PolicyHarvesterManager::instance().initialize(configJson);

    EXPECT_NO_THROW(upsertElement->handleRequest(context));

    EXPECT_EQ(
        context->m_serializedElement,
        R"({"id":"001_HASH_HASH","operation":"INSERTED","data":{"agent":{"id":"001","name":"agent-reg","host":{"ip":"agentIp"},"version":"agentVersion"},"registry":{"key":"Software\\App","hive":"HKLM","path":"HKLM\\Software\\App","gid":"gid","group":"groupName","uid":"uid","owner":"userName","architecture":"x86","mtime":"2025-04-09T15:45:00Z"},"wazuh":{"cluster":{"name":"clusterName"},"schema":{"version":"1.0"}},"event":{"category":"registry_key"}}})");
}

/*
 * Test cases for FimInventoryUpsertElement file scenario
 * These tests check the behavior of the UpsertSystemElement class when handling requests.
 */

TEST_F(FimInventoryUpsertElement, emptyAgentID_File)
{
    auto context = std::make_shared<MockFimContext>();
    auto upsertElement = std::make_shared<UpsertFimElement<MockFimContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillRepeatedly(testing::Return(MockFimContext::OriginTable::File));

    EXPECT_ANY_THROW(upsertElement->handleRequest(context));
}

TEST_F(FimInventoryUpsertElement, valid_File)
{
    auto context = std::make_shared<MockFimContext>();
    auto upsertElement = std::make_shared<UpsertFimElement<MockFimContext>>();

    EXPECT_CALL(*context, originTable()).WillRepeatedly(testing::Return(MockFimContext::OriginTable::File));

    // Agent metadata
    EXPECT_CALL(*context, agentId()).WillRepeatedly(testing::Return("001"));
    EXPECT_CALL(*context, agentName()).WillRepeatedly(testing::Return("agent-file"));
    EXPECT_CALL(*context, agentVersion()).WillRepeatedly(testing::Return("v4.0.0"));
    EXPECT_CALL(*context, agentIp()).WillRepeatedly(testing::Return("192.168.1.20"));

    // File-specific fields
    EXPECT_CALL(*context, path()).WillRepeatedly(testing::Return("/etc/hosts"));
    EXPECT_CALL(*context, hashPath()).WillRepeatedly(testing::Return("HASH_HASH"));
    EXPECT_CALL(*context, sha1()).WillRepeatedly(testing::Return("sha1-file"));
    EXPECT_CALL(*context, sha256()).WillRepeatedly(testing::Return("sha256-file"));
    EXPECT_CALL(*context, md5()).WillRepeatedly(testing::Return("md5-file"));
    EXPECT_CALL(*context, gid()).WillRepeatedly(testing::Return("1000"));
    EXPECT_CALL(*context, groupName()).WillRepeatedly(testing::Return("root"));
    EXPECT_CALL(*context, uid()).WillRepeatedly(testing::Return("1000"));
    EXPECT_CALL(*context, userName()).WillRepeatedly(testing::Return("sysadmin"));
    EXPECT_CALL(*context, size()).WillRepeatedly(testing::Return(512));
    EXPECT_CALL(*context, mtimeISO8601()).WillRepeatedly(testing::Return("2025-04-09T12:00:00Z"));

    EXPECT_NO_THROW(upsertElement->handleRequest(context));

    EXPECT_EQ(
        context->m_serializedElement,
        R"({"id":"001_HASH_HASH","operation":"INSERTED","data":{"file":{"path":"/etc/hosts","gid":"1000","group":"root","mtime":"2025-04-09T12:00:00Z","size":512,"uid":"1000","owner":"sysadmin","hash":{"md5":"md5-file","sha1":"sha1-file","sha256":"sha256-file"}},"agent":{"id":"001","name":"agent-file","host":{"ip":"192.168.1.20"},"version":"v4.0.0"},"wazuh":{"schema":{"version":"1.0"}}}})");
}

/*
 * Test cases for FimInventoryUpsertElement registry value scenario
 * These tests check the behavior of the UpsertSystemElement class when handling requests.
 */
TEST_F(FimInventoryUpsertElement, emptyAgentID_RegistryWithValue)
{
    auto context = std::make_shared<MockFimContext>();
    auto upsertElement = std::make_shared<UpsertFimElement<MockFimContext>>();

    EXPECT_CALL(*context, agentId()).WillOnce(testing::Return(""));
    EXPECT_CALL(*context, originTable()).WillRepeatedly(testing::Return(MockFimContext::OriginTable::RegistryValue));

    EXPECT_ANY_THROW(upsertElement->handleRequest(context));
}

TEST_F(FimInventoryUpsertElement, valid_RegistryWithValue)
{
    auto context = std::make_shared<MockFimContext>();
    auto upsertElement = std::make_shared<UpsertFimElement<MockFimContext>>();

    EXPECT_CALL(*context, originTable()).WillRepeatedly(testing::Return(MockFimContext::OriginTable::RegistryValue));

    // Agent info
    EXPECT_CALL(*context, agentId()).WillRepeatedly(testing::Return("001"));
    EXPECT_CALL(*context, agentName()).WillRepeatedly(testing::Return("agent-reg"));
    EXPECT_CALL(*context, agentVersion()).WillRepeatedly(testing::Return("v4.9.0"));
    EXPECT_CALL(*context, agentIp()).WillRepeatedly(testing::Return("10.10.10.10"));

    // Registry info
    EXPECT_CALL(*context, path()).WillRepeatedly(testing::Return("HKLM\\Software\\App"));
    EXPECT_CALL(*context, index()).WillRepeatedly(testing::Return("HASH_HASH"));
    EXPECT_CALL(*context, key()).WillRepeatedly(testing::Return("Software\\App"));
    EXPECT_CALL(*context, arch()).WillRepeatedly(testing::Return("[x32]"));
    EXPECT_CALL(*context, hive()).WillRepeatedly(testing::Return("HKLM"));
    EXPECT_CALL(*context, valueName()).WillRepeatedly(testing::Return("InstallPath"));
    EXPECT_CALL(*context, valueType()).WillRepeatedly(testing::Return("REG_SZ"));

    // Hashes
    EXPECT_CALL(*context, md5()).WillRepeatedly(testing::Return("md5value"));
    EXPECT_CALL(*context, sha1()).WillRepeatedly(testing::Return("sha1value"));
    EXPECT_CALL(*context, sha256()).WillRepeatedly(testing::Return("sha256value"));

    EXPECT_CALL(*context, elementType()).WillRepeatedly(testing::Return("registry_value"));

    EXPECT_NO_THROW(upsertElement->handleRequest(context));

    EXPECT_EQ(
        context->m_serializedElement,
        R"({"id":"001_HASH_HASH","operation":"INSERTED","data":{"agent":{"id":"001","name":"agent-reg","host":{"ip":"10.10.10.10"},"version":"v4.9.0"},"registry":{"key":"Software\\App","value":"InstallPath","hive":"HKLM","path":"HKLM\\Software\\App","data":{"hash":{"md5":"md5value","sha1":"sha1value","sha256":"sha256value"},"type":"REG_SZ"},"architecture":"[x32]"},"wazuh":{"schema":{"version":"1.0"}},"event":{"category":"registry_value"}}})");
}
