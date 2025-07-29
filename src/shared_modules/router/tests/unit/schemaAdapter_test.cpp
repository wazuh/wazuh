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

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYNC_STATE_FIM_REGISTRY_VALUE_invalid_component_type)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_ANY_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"component":1,"data":{"arch":"[x32]","attributes":{"checksum":"960730110ca14ecebc9f7ce6f69d9e990c29f186","hash_md5":"12b71c158bf133b8c40947d187ec71a1","hash_sha1":"7972501790bb776bf85dd385776af6635b7df025","hash_sha256":"1dd8876a1d714865acc43beb281a4c709edf1e01f94dae35917210f38239ca66","size":591,"type":"registry_value","value_type":"REG_SZ"},"index":"fdd7119272969188216190a468f43591be698061","path":"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\RestrictedServices\\AppIso\\FirewallRules","timestamp":1753425114,"value_name":"{9539E036-BAF8-431F-8A2D-7512E7E3DB03}","version":3},"type":"state"})",
        MT_SYNC,
        &agentCtx,
        buffer));
}

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYS_DELTAS_INVALID_JSON_MESSAGE)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_ANY_THROW(SchemaAdapter::adaptJsonMessage(R"({"message":"not_valid"})", MT_SYS_DELTAS, &agentCtx, buffer));
}

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYS_DELTAS_INVALID_JSON)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_ANY_THROW(SchemaAdapter::adaptJsonMessage(R"({"message":)", MT_SYS_DELTAS, &agentCtx, buffer));
}

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYNC_INTEGRITY_CHECK_GLOBAL_OLD)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"component":"syscollector_hwinfo","data":{"begin":"0","checksum":"b66d0703ee882571cd1865f393bd34f7d5940339","end":"0","id":1691259777},"type":"integrity_check_global"})",
        MT_SYNC,
        &agentCtx,
        buffer));

    EXPECT_EQ(
        buffer,
        R"({"agent_info":{"agent_id":"test","agent_name":"test","agent_ip":"test","agent_version":"test"},"data_type":"integrity_check_global","data":{"attributes_type":"syscollector_hwinfo","begin":"0","checksum":"b66d0703ee882571cd1865f393bd34f7d5940339","end":"0","id":1691259777}})");

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
        std::cout << "Error parsing buffer: " << parserSync.error_ << std::endl;
        FAIL();
    }
}

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYNC_INTEGRITY_CHECK_LEFT_OLD)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"component":"syscollector_packages","data":{"begin":"01113a00fcdafa43d111ecb669202119c946ebe5","checksum":"54c13892eb9ee18b0012086b76a89f41e73d64a1","end":"40795337f16a208e4d0a2280fbd5c794c9877dcb","id":1693338981,"tail":"408cb243d2d52ad6414ba602e375b3b6b5f5cd77"},"type":"integrity_check_left"})",
        MT_SYNC,
        &agentCtx,
        buffer));

    EXPECT_EQ(buffer, R"()");
}

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYNC_INTEGRITY_CHECK_RIGHT_OLD)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"component":"syscollector_packages","data":{"begin":"01113a00fcdafa43d111ecb669202119c946ebe5","checksum":"54c13892eb9ee18b0012086b76a89f41e73d64a1","end":"40795337f16a208e4d0a2280fbd5c794c9877dcb","id":1693338981,"tail":"408cb243d2d52ad6414ba602e375b3b6b5f5cd77"},"type":"integrity_check_right"})",
        MT_SYNC,
        &agentCtx,
        buffer));

    EXPECT_EQ(buffer, R"()");
}

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYNC_INTEGRITY_CLEAR_SYSCOLLECTOR_HWINFO)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"component":"syscollector_hwinfo","data":{"id":1693338619},"type":"integrity_clear"})",
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

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYNC_INTEGRITY_CLEAR_SYSCOLLECTOR_OSINFO)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"component":"syscollector_osinfo","data":{"id":1693338619},"type":"integrity_clear"})",
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

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYNC_INTEGRITY_CLEAR_SYSCOLLECTOR_PACKAGES)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"component":"syscollector_packages","data":{"id":1693338619},"type":"integrity_clear"})",
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

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYNC_INTEGRITY_CLEAR_SYSCOLLECTOR_PROCESSES)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"component":"syscollector_processes","data":{"id":1693338619},"type":"integrity_clear"})",
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

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYS_DELTAS_DBSYNC_PACKAGES)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"type":"dbsync_packages","data":{"architecture":"amd64","checksum":"1e6ce14f97f57d1bbd46ff8e5d3e133171a1bbce","description":"library for GIF images library","format":"deb","groups":"libs","item_id":"ec465b7eb5fa011a336e95614072e4c7f1a65a53","multiarch":"same","name":"libgif7","priority":"optional","scan_time":"2023/08/04 19:56:11","size":72,"source":"giflib","vendor":"Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>","version":"5.1.9-1"}, "operation" : "INSERTED"})",
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

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYS_DELTAS_DBSYNC_NETWORK_IFACE)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"type":"dbsync_network_iface","data":{"adapter":null,"checksum":"078143285c1aff98e196c8fe7e01f5677f44bd44","item_id":"7a60750dd3c25c53f21ff7f44b4743664ddbb66a","mac":"02:bf:67:45:e4:dd","mtu":1500,"name":"enp0s3","rx_bytes":972800985,"rx_dropped":0,"rx_errors":0,"rx_packets":670863,"scan_time":"2023/08/04 19:56:11","state":"up","tx_bytes":6151606,"tx_dropped":0,"tx_errors":0,"tx_packets":84746,"type":"ethernet"},"operation":"MODIFIED"})",
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

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYS_DELTAS_DBSYNC_NETWORK_PROTOCOL)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"type":"dbsync_network_protocol","data":{"checksum":"ddd971d57316a79738a2cf93143966a4e51ede08","dhcp":"unknown","gateway":" ","iface":"enp0s9","item_id":"33228317ee8778628d0f2f4fde53b75b92f15f1d","metric":"0","scan_time":"2023/08/07 15:02:36","type":"ipv4"},"operation":"DELETED"})",
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

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYS_DELTAS_DBSYNC_NETWORK_ADDRESS)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"type":"dbsync_network_address","data":{"address":"192.168.0.80","broadcast":"192.168.0.255","checksum":"c1f9511fa37815d19cee496f21524725ba84ab10","iface":"enp0s9","item_id":"b333013c47d28eb3878068dd59c42e00178bd475","netmask":"255.255.255.0","proto":0,"scan_time":"2023/08/07 15:02:36"},"operation":"DELETED"})",
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

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYS_DELTAS_DBSYNC_HWINFO)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"type":"dbsync_hwinfo","data":{"board_serial":"0","checksum":"f6eea592bc11465ecacc92ddaea188ef3faf0a1f","cpu_cores":8,"cpu_mhz":2592.0,"cpu_name":"Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz","ram_free":11547184,"ram_total":12251492,"ram_usage":6,"scan_time":"2023/08/04 19:56:11"},"operation":"MODIFIED"})",
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

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYS_DELTAS_DBSYNC_PORTS)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"type":"dbsync_ports","data":{"checksum":"03f522cdccc8dfbab964981db59b176b178b9dfd","inode":39968,"item_id":"7f98c21162b40ca7871a8292d177a1812ca97547","local_ip":"10.0.2.15","local_port":68,"pid":0,"process":null,"protocol":"udp","remote_ip":"0.0.0.0","remote_port":0,"rx_queue":0,"scan_time":"2023/08/07 12:42:41","state":null,"tx_queue":0},"operation":"INSERTED"})",
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

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYS_DELTAS_DBSYNC_HOTFIXES)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"type":"dbsync_hotfixes","data":{"checksum":"f6eea592bc11465ecacc92ddaea188ef3faf0a1f","hotfix":"KB4502496","scan_time":"2023/08/0419:56:11"},"operation":"MODIFIED"})",
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

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYS_DELTAS_LEGACY_AGENT_MESSAGE)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"type":"program","ID":710378877,"timestamp":"2024/01/12 22:47:29","program":{"format":"deb","name":"isc-dhcp-common","priority":"important","group":"net","size":163,"vendor":"Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>","architecture":"amd64","source":"isc-dhcp","version":"4.4.1-2.1ubuntu9","description":"common manpages relevant to all of the isc-dhcp packages"}})",
        MT_SYS_DELTAS,
        &agentCtx,
        buffer));

    // This type of message must be discarded, so buffer should be empty
    EXPECT_EQ(buffer, "");
}

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYS_DELTAS_LEGACY_AGENT_END_MESSAGE)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(
        SchemaAdapter::adaptJsonMessage(R"({"type":"process_end","ID":1998297930,"timestamp":"2024/01/13 00:08:55"})",
                                        MT_SYS_DELTAS,
                                        &agentCtx,
                                        buffer));

    // This type of message must be discarded, so buffer should be empty
    EXPECT_EQ(buffer, "");
}

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYS_DELTAS_DBSYNC_PACKAGES_HUGE_SIZE)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"type":"dbsync_packages","data":{"architecture":"amd64","checksum":"1e6ce14f97f57d1bbd46ff8e5d3e133171a1bbce","description":"library for GIF images library","format":"deb","groups":"libs","item_id":"ec465b7eb5fa011a336e95614072e4c7f1a65a53","multiarch":"same","name":"libgif7","priority":"optional","scan_time":"2023/08/04 19:56:11","size":3686061793,"source":"giflib","vendor":"Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>","version":"5.1.9-1"}, "operation" : "INSERTED"})",
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

TEST_F(SchemaAdapterTest, TestSchemaAdapterMT_SYNC_STATE_SYSCOLLECTOR_PACKAGES_NEGATIVE_SIZE)
{
    std::string buffer;
    agent_ctx agentCtx = {.agent_id = "test", .agent_name = "test", .agent_ip = "test", .agent_version = "test"};

    EXPECT_NO_THROW(SchemaAdapter::adaptJsonMessage(
        R"({"component":"syscollector_packages","data":{"architecture":"amd64","checksum":"1e6ce14f97f57d1bbd46ff8e5d3e133171a1bbce","description":"library for GIF images library","format":"deb","groups":"libs","item_id":"ec465b7eb5fa011a336e95614072e4c7f1a65a53","multiarch":"same","name":"libgif7","priority":"optional","scan_time":"2023/08/04 19:56:11","size":-608905503,"source":"giflib","vendor":"Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>","version":"5.1.9-1"}, "type" : "state"})",
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
