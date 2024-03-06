/*
 * Wazuh SyscollectorImp
 * Copyright (C) 2015, Wazuh Inc.
 * August 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "syscollectorDeltas_test.h"
#include "flatbuffers/idl.h"

bool parseJSON(const std::string& schemaStr, const std::string& jsonStr)
{
    flatbuffers::Parser parser;

    if (!(parser.Parse(schemaStr.c_str()) && parser.Parse(jsonStr.c_str())))
    {
        std::cerr << parser.error_ << std::endl;
        return false;
    }

    return true;
}

TEST_F(SyscollectorDeltasTest, NetIfaceParsingSuccess)
{
    const std::string deltaNetIface {"{\"agent_info\":{\"agent_id\":\"001\",\"node_name\":\"node01\"},\"data_type\":\"dbsync_network_iface\",\"data\":{\"adapter\":null,\"checksum\":\"078143285c1aff98e196c8fe7e01f5677f44bd44\""
                                     ",\"item_id\":\"7a60750dd3c25c53f21ff7f44b4743664ddbb66a\",\"mac\":\"02:bf:67:45:e4:dd\",\"mtu\":1500,\"name\":\"enp0s3\",\"rx_bytes\":972800985"
                                     ",\"rx_dropped\":0,\"rx_errors\":0,\"rx_packets\":670863,\"scan_time\":\"2023/08/04 19:56:11\",\"state\":\"up\",\"tx_bytes\":6151606,\"tx_dropped\":0"
                                     ",\"tx_errors\":0,\"tx_packets\":84746,\"type\":\"ethernet\"},\"operation\":\"MODIFIED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaNetIface);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorDeltasTest, NetIfaceParsingInvalid)
{
    // mtu is a string that represents an invalid number.
    const std::string deltaNetIface {"{\"agent_info\":{\"agent_id\":\"001\",\"node_name\":\"node01\"},\"data_type\":\"dbsync_network_iface\",\"data\":{\"adapter\":null,\"checksum\":\"078143285c1aff98e196c8fe7e01f5677f44bd44\""
                                     ",\"item_id\":\"7a60750dd3c25c53f21ff7f44b4743664ddbb66a\",\"mac\":\"02:bf:67:45:e4:dd\",\"mtu\":\"150x\",\"name\":\"enp0s3\",\"rx_bytes\":972800985"
                                     ",\"rx_dropped\":0,\"rx_errors\":0,\"rx_packets\":670863,\"scan_time\":\"2023/08/04 19:56:11\",\"state\":\"up\",\"tx_bytes\":6151606,\"tx_dropped\":0"
                                     ",\"tx_errors\":0,\"tx_packets\":84746,\"type\":\"ethernet\"},\"operation\":\"MODIFIED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaNetIface);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorDeltasTest, NetProtoParsingSuccess)
{
    const std::string deltaNetProto {"{\"agent_info\":{\"agent_id\":\"001\",\"node_name\":\"node01\"},\"data_type\":\"dbsync_network_protocol\",\"data\":{\"checksum\":\"ddd971d57316a79738a2cf93143966a4e51ede08\",\"dhcp\":\"unknown\""
                                     ",\"gateway\":\" \",\"iface\":\"enp0s9\",\"item_id\":\"33228317ee8778628d0f2f4fde53b75b92f15f1d\",\"metric\":\"0\",\"scan_time\":\"2023/08/07 15:02:36\""
                                     ",\"type\":\"ipv4\"},\"operation\":\"DELETED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaNetProto);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorDeltasTest, NetProtoParsingInvalid)
{
    // metric is a number.
    const std::string deltaNetProto {"{\"agent_info\":{\"agent_id\":\"001\",\"node_name\":\"node01\"},\"data_type\":\"dbsync_network_protocol\",\"data\":{\"checksum\":\"ddd971d57316a79738a2cf93143966a4e51ede08\",\"dhcp\":\"unknown\""
                                     ",\"gateway\":\" \",\"iface\":\"enp0s9\",\"item_id\":\"33228317ee8778628d0f2f4fde53b75b92f15f1d\",\"metric\":0,\"scan_time\":\"2023/08/07 15:02:36\""
                                     ",\"type\":\"ipv4\"},\"operation\":\"DELETED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaNetProto);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorDeltasTest, NetAddrParsingSuccess)
{
    // For delta events, syscollector network address provider sends metric and dhcp information.
    const std::string deltaNetAddr {"{\"agent_info\":{\"agent_id\":\"001\",\"node_name\":\"node01\"},\"data_type\":\"dbsync_network_address\",\"data\":{\"address\":\"192.168.0.80\",\"broadcast\":\"192.168.0.255\""
                                    ",\"checksum\":\"c1f9511fa37815d19cee496f21524725ba84ab10\",\"metric\":\"100\",\"dhcp\":\"unknown\",\"iface\":\"enp0s9\",\"item_id\":\"b333013c47d28eb3878068dd59c42e00178bd475\""
                                    ",\"netmask\":\"255.255.255.0\",\"proto\":0,\"scan_time\":\"2023/08/07 15:02:36\"},\"operation\":\"DELETED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaNetAddr);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorDeltasTest, NetAddrParsingInvalid)
{
    // Invalid field "oface".
    const std::string deltaNetAddr {"{\"agent_info\":{\"agent_id\":\"001\",\"node_name\":\"node01\"},\"data_type\":\"dbsync_network_address\",\"data\":{\"address\":\"192.168.0.80\",\"broadcast\":\"192.168.0.255\""
                                    ",\"checksum\":\"c1f9511fa37815d19cee496f21524725ba84ab10\",\"oface\":\"enp0s9\",\"item_id\":\"b333013c47d28eb3878068dd59c42e00178bd475\""
                                    ",\"netmask\":\"255.255.255.0\",\"proto\":0,\"scan_time\":\"2023/08/07 15:02:36\"},\"operation\":\"DELETED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaNetAddr);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorDeltasTest, OsInfoParsingSuccess)
{
    const std::string deltaOsInfo {"{\"agent_info\":{\"agent_id\":\"001\",\"node_name\":\"node01\"},\"data_type\":\"dbsync_osinfo\",\"data\":{\"architecture\":\"x86_64\",\"checksum\":\"1691178971959743855\",\"hostname\":\"focal\",\"os_codename\":\"focal\""
                                   ",\"os_major\":\"20\",\"os_minor\":\"04\",\"os_name\":\"Ubuntu\",\"os_patch\":\"6\",\"os_platform\":\"ubuntu\",\"os_version\":\"20.04.6 LTS (Focal Fossa)\""
                                   ",\"release\":\"5.4.0-155-generic\",\"scan_time\":\"2023/08/04 19:56:11\",\"sysname\":\"Linux\",\"version\":\"#172-Ubuntu SMP Fri Jul 7 16:10:02 UTC 2023\"}"
                                   ",\"operation\":\"MODIFIED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaOsInfo);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorDeltasTest, OsInfoParsingInvalid)
{
    // os_major is an integer.
    const std::string deltaOsInfo {"{\"agent_info\":{\"agent_id\":\"001\",\"node_name\":\"node01\"},\"data_type\":\"dbsync_osinfo\",\"data\":{\"architecture\":\"x86_64\",\"checksum\":\"1691178971959743855\",\"hostname\":\"focal\",\"os_codename\":\"focal\""
                                   ",\"os_major\":20,\"os_minor\":\"04\",\"os_name\":\"Ubuntu\",\"os_patch\":\"6\",\"os_platform\":\"ubuntu\",\"os_version\":\"20.04.6 LTS (Focal Fossa)\""
                                   ",\"release\":\"5.4.0-155-generic\",\"scan_time\":\"2023/08/04 19:56:11\",\"sysname\":\"Linux\",\"version\":\"#172-Ubuntu SMP Fri Jul 7 16:10:02 UTC 2023\"}"
                                   ",\"operation\":\"MODIFIED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaOsInfo);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorDeltasTest, HwInfoParsingSuccess)
{
    const std::string deltaHwInfo {"{\"agent_info\":{\"agent_id\":\"001\",\"node_name\":\"node01\"},\"data_type\":\"dbsync_hwinfo\",\"data\":{\"board_serial\":\"0\",\"checksum\":\"f6eea592bc11465ecacc92ddaea188ef3faf0a1f\",\"cpu_cores\":8"
                                   ",\"cpu_mhz\":2592.0,\"cpu_name\":\"Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz\",\"ram_free\":11547184,\"ram_total\":12251492,\"ram_usage\":6"
                                   ",\"scan_time\":\"2023/08/04 19:56:11\"},\"operation\":\"MODIFIED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaHwInfo);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorDeltasTest, HwInfoParsingInvalid)
{
    // cpu_mhz is a string that represents an invalid number.
    const std::string deltaHwInfo {"{\"agent_info\":{\"agent_id\":\"001\",\"node_name\":\"node01\"},\"data_type\":\"dbsync_hwinfo\",\"data\":{\"board_serial\":\"0\",\"checksum\":\"f6eea592bc11465ecacc92ddaea188ef3faf0a1f\",\"cpu_cores\":8"
                                   ",\"cpu_mhz\":\"2592.x\",\"cpu_name\":\"Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz\",\"ram_free\":11547184,\"ram_total\":12251492,\"ram_usage\":6"
                                   ",\"scan_time\":\"2023/08/04 19:56:11\"},\"operation\":\"MODIFIED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaHwInfo);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorDeltasTest, PortsParsingSuccess)
{
    const std::string deltaPorts {"{\"agent_info\":{\"agent_id\":\"001\",\"node_name\":\"node01\"},\"data_type\":\"dbsync_ports\",\"data\":{\"checksum\":\"03f522cdccc8dfbab964981db59b176b178b9dfd\",\"inode\":39968"
                                  ",\"item_id\":\"7f98c21162b40ca7871a8292d177a1812ca97547\",\"local_ip\":\"10.0.2.15\",\"local_port\":68,\"pid\":0,\"process\":null,\"protocol\":\"udp\""
                                  ",\"remote_ip\":\"0.0.0.0\",\"remote_port\":0,\"rx_queue\":0,\"scan_time\":\"2023/08/07 12:42:41\",\"state\":null,\"tx_queue\":0},\"operation\":\"INSERTED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaPorts);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorDeltasTest, PortsParsingInvalid)
{
    // local_port is a string that represents an invalid number.
    const std::string deltaPorts {"{\"agent_info\":{\"agent_id\":\"001\",\"node_name\":\"node01\"},\"data_type\":\"dbsync_ports\",\"data\":{\"checksum\":\"03f522cdccc8dfbab964981db59b176b178b9dfd\",\"inode\":39968"
                                  ",\"item_id\":\"7f98c21162b40ca7871a8292d177a1812ca97547\",\"local_ip\":\"10.0.2.15\",\"local_port\":\"68x\",\"pid\":0,\"process\":null,\"protocol\":\"udp\""
                                  ",\"remote_ip\":\"0.0.0.0\",\"remote_port\":0,\"rx_queue\":0,\"scan_time\":\"2023/08/07 12:42:41\",\"state\":null,\"tx_queue\":0},\"operation\":\"INSERTED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaPorts);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorDeltasTest, PackagesParsingSuccess)
{
    const std::string deltaPackages {"{\"agent_info\":{\"agent_id\":\"001\",\"node_name\":\"node01\"},\"data_type\":\"dbsync_packages\",\"data\":{\"architecture\":\"amd64\",\"checksum\":\"1e6ce14f97f57d1bbd46ff8e5d3e133171a1bbce\""
                                     ",\"description\":\"library for GIF images (library)\",\"format\":\"deb\",\"groups\":\"libs\",\"item_id\":\"ec465b7eb5fa011a336e95614072e4c7f1a65a53\""
                                     ",\"multiarch\":\"same\",\"name\":\"libgif7\",\"priority\":\"optional\",\"scan_time\":\"2023/08/04 19:56:11\",\"size\":72,\"source\":\"giflib\""
                                     ",\"vendor\":\"Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\",\"version\":\"5.1.9-1\"},\"operation\":\"INSERTED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaPackages);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorDeltasTest, PackagesParsingInvalid)
{
    // Invalid field "arch"
    const std::string deltaPackages {"{\"agent_info\":{\"agent_id\":\"001\",\"node_name\":\"node01\"},\"data_type\":\"dbsync_packages\",\"data\":{\"arch\":\"amd64\",\"checksum\":\"1e6ce14f97f57d1bbd46ff8e5d3e133171a1bbce\""
                                     ",\"description\":\"library for GIF images (library)\",\"format\":\"deb\",\"groups\":\"libs\",\"item_id\":\"ec465b7eb5fa011a336e95614072e4c7f1a65a53\""
                                     ",\"multiarch\":\"same\",\"name\":\"libgif7\",\"priority\":\"optional\",\"scan_time\":\"2023/08/04 19:56:11\",\"size\":72,\"source\":\"giflib\""
                                     ",\"vendor\":\"Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\",\"version\":\"5.1.9-1\"},\"operation\":\"INSERTED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaPackages);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorDeltasTest, HotfixesParsingSuccess)
{
    const std::string deltaHotfixes {"{\"agent_info\":{\"agent_id\":\"001\",\"node_name\":\"node01\"},\"data_type\":\"dbsync_hotfixes\",\"data\":{\"checksum\":\"f6eea592bc11465ecacc92ddaea188ef3faf0a1f\",\"hotfix\":\"KB4502496\""
                                     ",\"scan_time\":\"2023/08/0419:56:11\"},\"operation\":\"MODIFIED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaHotfixes);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorDeltasTest, HotfixesParsingInvalid)
{
    // Invalid field "hitfix".
    const std::string deltaHotfixes {"{\"agent_info\":{\"agent_id\":\"001\",\"node_name\":\"node01\"},\"data_type\":\"dbsync_hotfixes\",\"data\":{\"checksum\":\"f6eea592bc11465ecacc92ddaea188ef3faf0a1f\",\"hitfix\":\"KB4502496\""
                                     ",\"scan_time\":\"2023/08/0419:56:11\"},\"operation\":\"MODIFIED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaHotfixes);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorDeltasTest, ProcessesParsingSuccess)
{
    // We should escape double backslashes the message from agent.
    const std::string deltaProcesses {"{\"agent_info\":{\"agent_id\":\"001\",\"node_name\":\"node01\"},\"data_type\":\"dbsync_processes\",\"data\":{\"checksum\":\"5ca21c17ae78a0ef7463b3b2454126848473cf5b\",\"cmd\":\"C:\\\\Windows\\\\System32\\\\winlogon.exe\""
                                      ",\"name\":\"winlogon.exe\",\"nlwp\":6,\"pid\":\"604\",\"ppid\":496,\"priority\":13,\"scan_time\":\"2023/08/07 15:01:57\",\"session\":1,\"size\":3387392"
                                      ",\"start_time\":1691420428,\"stime\":0,\"utime\":0,\"vm_size\":14348288},\"operation\":\"MODIFIED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaProcesses);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorDeltasTest, ProcessesParsingInvalid)
{
    // Double backslashes not escaped.
    const std::string deltaProcesses {"{\"agent_info\":{\"agent_id\":\"001\",\"node_name\":\"node01\"},\"data_type\":\"dbsync_processes\",\"data\":{\"checksum\":\"5ca21c17ae78a0ef7463b3b2454126848473cf5b\",\"cmd\":\"C:\\Windows\\\\System32\\\\winlogon.exe\""
                                      ",\"name\":\"winlogon.exe\",\"nlwp\":6,\"pid\":\"604\",\"ppid\":496,\"priority\":13,\"scan_time\":\"2023/08/07 15:01:57\",\"session\":1,\"size\":3387392"
                                      ",\"start_time\":1691420428,\"stime\":0,\"utime\":0,\"vm_size\":14348288},\"operation\":\"MODIFIED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaProcesses);

    EXPECT_FALSE(ret);
}
