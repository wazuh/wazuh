/*
 * Wazuh router - SchemaAdapter tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 24, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "schemaAdapter.hpp"
#include "shared_modules/utils/flatbuffers/include/rsync_schema.h"
#include "shared_modules/utils/flatbuffers/include/syscheck_deltas_schema.h"
#include "shared_modules/utils/flatbuffers/include/syscollector_deltas_schema.h"
#include <flatbuffers/flatbuffers.h>
#include <flatbuffers/idl.h>
#include <gtest/gtest.h>

/**
 * @brief Runs unit tests for Publisher class
 */
class SchemaAdapterTest : public ::testing::Test
{
protected:
    SchemaAdapterTest() = default;

    ~SchemaAdapterTest() override = default;
};

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYNC_INTEGRITY_CHECK_GLOBAL)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"component":"syscollector_processes","data":{"begin":"0","checksum":"7d7940c887e1852073ae3721aee96a542de0bb9e","end":"99877","id":1753411466},"type":"integrity_check_global"})",
        MT_SYNC,
        &agentCtx,
        buffer));

    auto parserSync = flatbuffers::Parser();
    parserSync.opts.skip_unexpected_fields_in_json = true;
    parserSync.opts.zero_on_float_to_int =
        true; // Avoids issues with float to int conversion, custom option made for Wazuh.

    if (!parserSync.Parse(rsync_SCHEMA))
    {
        FAIL();
    }

    if (!parserSync.Parse(buffer.c_str()))
    {
        FAIL();
    }
}

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYNC_STATE_FIM_REGISTRY_VALUE)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"component":"fim_registry_value","data":{"arch":"[x32]","attributes":{"checksum":"960730110ca14ecebc9f7ce6f69d9e990c29f186","hash_md5":"12b71c158bf133b8c40947d187ec71a1","hash_sha1":"7972501790bb776bf85dd385776af6635b7df025","hash_sha256":"1dd8876a1d714865acc43beb281a4c709edf1e01f94dae35917210f38239ca66","size":591,"type":"registry_value","value_type":"REG_SZ"},"index":"fdd7119272969188216190a468f43591be698061","path":"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\RestrictedServices\\AppIso\\FirewallRules","timestamp":1753425114,"value_name":"{9539E036-BAF8-431F-8A2D-7512E7E3DB03}","version":3},"type":"state"})",
        MT_SYNC,
        &agentCtx,
        buffer));

    auto parserSync = flatbuffers::Parser();
    parserSync.opts.skip_unexpected_fields_in_json = true;
    parserSync.opts.zero_on_float_to_int =
        true; // Avoids issues with float to int conversion, custom option made for Wazuh.

    if (!parserSync.Parse(rsync_SCHEMA))
    {
        FAIL();
    }

    if (!parserSync.Parse(buffer.c_str()))
    {
        FAIL();
    }
}

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYNC_STATE_SYSCOLLECTOR_PACKAGES)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"component":"syscollector_packages","data":{"attributes":{"architecture":"x86_64","checksum":"f1dacf757eae384fff8a3a1a165f4c771869f89a","description":"","format":"win","groups":" ","install_time":"2025/07/2401:00:00","item_id":"e67ed1e9e938a46b8374ff5646a9fa7f25e077b2","location":" ","name":"Office 16 Click-to-Run Licensing Component","priority":" ","scan_time":"2025/07/25 06:31:55","size":0,"source":" ","vendor":"Microsoft Corporation","version":"16.0.14334.20136"},"index":"e67ed1e9e938a46b8374ff5646a9fa7f25e077b2","timestamp":""},"type":"state"})",
        MT_SYNC,
        &agentCtx,
        buffer));

    auto parserSync = flatbuffers::Parser();
    parserSync.opts.skip_unexpected_fields_in_json = true;
    parserSync.opts.zero_on_float_to_int =
        true; // Avoids issues with float to int conversion, custom option made for Wazuh.

    if (!parserSync.Parse(rsync_SCHEMA))
    {
        FAIL();
    }

    if (!parserSync.Parse(buffer.c_str()))
    {
        FAIL();
    }
}

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYNC_INTEGRITY_CLEAR_SYSCOLLECTOR_HOTFIXES)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"component":"syscollector_hotfixes","data":{"id":1753419057},"type":"integrity_clear"})",
        MT_SYNC,
        &agentCtx,
        buffer));

    auto parserSync = flatbuffers::Parser();
    parserSync.opts.skip_unexpected_fields_in_json = true;
    parserSync.opts.zero_on_float_to_int =
        true; // Avoids issues with float to int conversion, custom option made for Wazuh.

    if (!parserSync.Parse(rsync_SCHEMA))
    {
        FAIL();
    }

    if (!parserSync.Parse(buffer.c_str()))
    {
        FAIL();
    }
}

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYNC_DELTAS_DBSYNC_PROCESSES)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"data":{"checksum":"05c59d562af07139d0977d4c4c219fe0d6768be6","euser":"octaviovalle","name":"plugin-container","nice":0,"pid":"2545","ppid":84245,"priority":31,"rgroup":"staff","ruser":"octaviovalle","scan_time":"2025/07/25 04:37:54","start_time":1753415222,"state":" ","vm_size":412847200},"operation":"MODIFIED","type":"dbsync_processes"})",
        MT_SYS_DELTAS,
        &agentCtx,
        buffer));

    auto parserSync = flatbuffers::Parser();
    parserSync.opts.skip_unexpected_fields_in_json = true;
    parserSync.opts.zero_on_float_to_int =
        true; // Avoids issues with float to int conversion, custom option made for Wazuh.

    if (!parserSync.Parse(syscollector_deltas_SCHEMA))
    {
        FAIL();
    }

    if (!parserSync.Parse(buffer.c_str()))
    {
        FAIL();
    }
}
