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
    const std::string deltaNetIface {"{\"agent_info\":{\"agent_id\":\"001\"},\"data_type\":\"dbsync_network_iface\",\"data\":{\"interface_alias\":null,\"checksum\":\"078143285c1aff98e196c8fe7e01f5677f44bd44\""
                                     ",\"host_mac\":\"02:bf:67:45:e4:dd\",\"interface_mtu\":1500,\"interface_name\":\"enp0s3\",\"host_network_ingress_bytes\":972800985,\"host_network_ingress_drops\":0"
                                     ",\"host_network_ingress_errors\":0,\"host_network_ingress_packages\":670863,\"interface_state\":\"up\",\"host_network_egress_bytes\":6151606"
                                     ",\"host_network_egress_drops\":0,\"host_network_egress_errors\":0,\"host_network_egress_packages\":84746,\"interface_type\":\"ethernet\"},\"operation\":\"MODIFIED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaNetIface);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorDeltasTest, NetIfaceParsingInvalid)
{
    // interface_mtu is a string that represents an invalid number.
    const std::string deltaNetIface {"{\"agent_info\":{\"agent_id\":\"001\"},\"data_type\":\"dbsync_network_iface\",\"data\":{\"interface_alias\":null,\"checksum\":\"078143285c1aff98e196c8fe7e01f5677f44bd44\""
                                     ",\"host_mac\":\"02:bf:67:45:e4:dd\",\"interface_mtu\":\"150x\",\"interface_name\":\"enp0s3\",\"host_network_ingress_bytes\":972800985,\"host_network_ingress_drops\":0"
                                     ",\"host_network_ingress_errors\":0,\"host_network_ingress_packages\":670863,\"interface_state\":\"up\",\"host_network_egress_bytes\":6151606"
                                     ",\"host_network_egress_drops\":0,\"host_network_egress_errors\":0,\"host_network_egress_packages\":84746,\"interface_type\":\"ethernet\"},\"operation\":\"MODIFIED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaNetIface);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorDeltasTest, NetProtoParsingSuccess)
{
    const std::string deltaNetProto {"{\"agent_info\":{\"agent_id\":\"001\"},\"data_type\":\"dbsync_network_protocol\",\"data\":{\"checksum\":\"ddd971d57316a79738a2cf93143966a4e51ede08\",\"network_dhcp\":\"unknown\""
                                     ",\"network_gateway\":\" \",\"interface_name\":\"enp0s9\",\"network_metric\":\"0\""
                                     ",\"network_type\":\"ipv4\"},\"operation\":\"DELETED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaNetProto);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorDeltasTest, NetProtoParsingInvalid)
{
    // network_metric is a number.
    const std::string deltaNetProto {"{\"agent_info\":{\"agent_id\":\"001\"},\"data_type\":\"dbsync_network_protocol\",\"data\":{\"checksum\":\"ddd971d57316a79738a2cf93143966a4e51ede08\",\"network_dhcp\":\"unknown\""
                                     ",\"network_gateway\":\" \",\"interface_name\":\"enp0s9\",\"network_metric\":0"
                                     ",\"network_type\":\"ipv4\"},\"operation\":\"DELETED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaNetProto);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorDeltasTest, NetAddrParsingSuccess)
{
    // For delta events, syscollector network network_ip provider sends network_metric and network_dhcp information.
    const std::string deltaNetAddr {"{\"agent_info\":{\"agent_id\":\"001\"},\"data_type\":\"dbsync_network_address\",\"data\":{\"network_ip\":\"192.168.0.80\",\"network_broadcast\":\"192.168.0.255\""
                                    ",\"checksum\":\"c1f9511fa37815d19cee496f21524725ba84ab10\",\"network_metric\":\"100\",\"network_dhcp\":\"unknown\",\"interface_name\":\"enp0s9\""
                                    ",\"network_netmask\":\"255.255.255.0\",\"network_protocol\":0},\"operation\":\"DELETED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaNetAddr);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorDeltasTest, NetAddrParsingInvalid)
{
    // Invalid field "oface".
    const std::string deltaNetAddr {"{\"agent_info\":{\"agent_id\":\"001\"},\"data_type\":\"dbsync_network_address\",\"data\":{\"network_ip\":\"192.168.0.80\",\"network_broadcast\":\"192.168.0.255\""
                                    ",\"checksum\":\"c1f9511fa37815d19cee496f21524725ba84ab10\",\"oface\":\"enp0s9\""
                                    ",\"network_netmask\":\"255.255.255.0\",\"network_protocol\":0},\"operation\":\"DELETED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaNetAddr);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorDeltasTest, OsInfoParsingSuccess)
{
    const std::string deltaOsInfo {"{\"agent_info\":{\"agent_id\":\"001\"},\"data_type\":\"dbsync_osinfo\",\"data\":{\"architecture\":\"x86_64\",\"checksum\":\"1691178971959743855\",\"hostname\":\"focal\",\"os_codename\":\"focal\""
                                   ",\"os_major\":\"20\",\"os_minor\":\"04\",\"os_name\":\"Ubuntu\",\"os_patch\":\"6\",\"os_platform\":\"ubuntu\",\"os_version\":\"20.04.6 LTS (Focal Fossa)\""
                                   ",\"os_kernel_release\":\"5.4.0-155-generic\",\"os_kernel_name\":\"Linux\",\"os_kernel_version\":\"#172-Ubuntu SMP Fri Jul 7 16:10:02 UTC 2023\"}"
                                   ",\"operation\":\"MODIFIED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaOsInfo);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorDeltasTest, OsInfoParsingInvalid)
{
    // os_major is an integer.
    const std::string deltaOsInfo {"{\"agent_info\":{\"agent_id\":\"001\"},\"data_type\":\"dbsync_osinfo\",\"data\":{\"architecture\":\"x86_64\",\"checksum\":\"1691178971959743855\",\"hostname\":\"focal\",\"os_codename\":\"focal\""
                                   ",\"os_major\":20,\"os_minor\":\"04\",\"os_name\":\"Ubuntu\",\"os_patch\":\"6\",\"os_platform\":\"ubuntu\",\"os_version\":\"20.04.6 LTS (Focal Fossa)\""
                                   ",\"os_kernel_release\":\"5.4.0-155-generic\",\"os_kernel_name\":\"Linux\",\"os_kernel_version\":\"#172-Ubuntu SMP Fri Jul 7 16:10:02 UTC 2023\"}"
                                   ",\"operation\":\"MODIFIED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaOsInfo);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorDeltasTest, HwInfoParsingSuccess)
{
    const std::string deltaHwInfo {"{\"agent_info\":{\"agent_id\":\"001\"},\"data_type\":\"dbsync_hwinfo\",\"data\":{\"serial_number\":\"0\",\"checksum\":\"f6eea592bc11465ecacc92ddaea188ef3faf0a1f\",\"cpu_cores\":8"
                                   ",\"cpu_speed\":2592.0,\"cpu_name\":\"Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz\",\"memory_free\":11547184,\"memory_total\":12251492,\"memory_used\":6"
                                   "},\"operation\":\"MODIFIED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaHwInfo);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorDeltasTest, HwInfoParsingInvalid)
{
    // cpu_speed is a string that represents an invalid number.
    const std::string deltaHwInfo {"{\"agent_info\":{\"agent_id\":\"001\"},\"data_type\":\"dbsync_hwinfo\",\"data\":{\"serial_number\":\"0\",\"checksum\":\"f6eea592bc11465ecacc92ddaea188ef3faf0a1f\",\"cpu_cores\":8"
                                   ",\"cpu_speed\":\"2592.x\",\"cpu_name\":\"Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz\",\"memory_free\":11547184,\"memory_total\":12251492,\"memory_used\":6"
                                   "},\"operation\":\"MODIFIED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaHwInfo);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorDeltasTest, PortsParsingSuccess)
{
    const std::string deltaPorts {"{\"agent_info\":{\"agent_id\":\"001\"},\"data_type\":\"dbsync_ports\",\"data\":{\"checksum\":\"03f522cdccc8dfbab964981db59b176b178b9dfd\",\"file_inode\":39968"
                                  ",\"source_ip\":\"10.0.2.15\",\"source_port\":68,\"process_pid\":0,\"process_name\":null,\"network_transport\":\"udp\""
                                  ",\"destination_ip\":\"0.0.0.0\",\"destination_port\":0,\"host_network_ingress_queue\":0,\"interface_state\":null,\"host_network_egress_queue\":0},\"operation\":\"INSERTED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaPorts);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorDeltasTest, PortsParsingInvalid)
{
    // source_port is a string that represents an invalid number.
    const std::string deltaPorts {"{\"agent_info\":{\"agent_id\":\"001\"},\"data_type\":\"dbsync_ports\",\"data\":{\"checksum\":\"03f522cdccc8dfbab964981db59b176b178b9dfd\",\"file_inode\":39968"
                                  ",\"source_ip\":\"10.0.2.15\",\"source_port\":\"68x\",\"process_pid\":0,\"process_name\":null,\"network_transport\":\"udp\""
                                  ",\"destination_ip\":\"0.0.0.0\",\"destination_port\":0,\"host_network_ingress_queue\":0,\"interface_state\":null,\"host_network_egress_queue\":0},\"operation\":\"INSERTED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaPorts);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorDeltasTest, PackagesParsingSuccess)
{
    const std::string deltaPackages {"{\"agent_info\":{\"agent_id\":\"001\"},\"data_type\":\"dbsync_packages\",\"data\":{\"architecture\":\"amd64\",\"checksum\":\"1e6ce14f97f57d1bbd46ff8e5d3e133171a1bbce\""
                                     ",\"description\":\"library for GIF images (library)\",\"type\":\"deb\",\"category\":\"libs\""
                                     ",\"multiarch\":\"same\",\"name\":\"libgif7\",\"priority\":\"optional\",\"size\":72,\"source\":\"giflib\""
                                     ",\"vendor\":\"Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\",\"version\":\"5.1.9-1\"},\"operation\":\"INSERTED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaPackages);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorDeltasTest, PackagesParsingInvalid)
{
    // Invalid field "arch"
    const std::string deltaPackages {"{\"agent_info\":{\"agent_id\":\"001\"},\"data_type\":\"dbsync_packages\",\"data\":{\"arch\":\"amd64\",\"checksum\":\"1e6ce14f97f57d1bbd46ff8e5d3e133171a1bbce\""
                                     ",\"description\":\"library for GIF images (library)\",\"type\":\"deb\",\"category\":\"libs\""
                                     ",\"multiarch\":\"same\",\"name\":\"libgif7\",\"priority\":\"optional\",\"size\":72,\"source\":\"giflib\""
                                     ",\"vendor\":\"Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\",\"version\":\"5.1.9-1\"},\"operation\":\"INSERTED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaPackages);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorDeltasTest, HotfixesParsingSuccess)
{
    const std::string deltaHotfixes {"{\"agent_info\":{\"agent_id\":\"001\"},\"data_type\":\"dbsync_hotfixes\",\"data\":{\"checksum\":\"f6eea592bc11465ecacc92ddaea188ef3faf0a1f\",\"hotfix_name\":\"KB4502496\""
                                     "},\"operation\":\"MODIFIED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaHotfixes);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorDeltasTest, HotfixesParsingInvalid)
{
    // Invalid field "hitfix".
    const std::string deltaHotfixes {"{\"agent_info\":{\"agent_id\":\"001\"},\"data_type\":\"dbsync_hotfixes\",\"data\":{\"checksum\":\"f6eea592bc11465ecacc92ddaea188ef3faf0a1f\",\"hitfix\":\"KB4502496\""
                                     "},\"operation\":\"MODIFIED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaHotfixes);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorDeltasTest, ProcessesParsingSuccess)
{
    // We should escape double backslashes the message from agent.
    const std::string deltaProcesses {"{\"agent_info\":{\"agent_id\":\"001\"},\"data_type\":\"dbsync_processes\",\"data\":{\"checksum\":\"5ca21c17ae78a0ef7463b3b2454126848473cf5b\",\"command_line\":\"C:\\\\Windows\\\\System32\\\\winlogon.exe\""
                                      ",\"name\":\"winlogon.exe\",\"pid\":\"604\",\"parent_pid\":496"
                                      ",\"start\":1691420428,\"stime\":0,\"utime\":0},\"operation\":\"MODIFIED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaProcesses);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorDeltasTest, ProcessesParsingInvalid)
{
    // Double backslashes not escaped.
    const std::string deltaProcesses {"{\"agent_info\":{\"agent_id\":\"001\"},\"data_type\":\"dbsync_processes\",\"data\":{\"checksum\":\"5ca21c17ae78a0ef7463b3b2454126848473cf5b\",\"command_line\":\"C:\\Windows\\\\System32\\\\winlogon.exe\""
                                      ",\"name\":\"winlogon.exe\",\"pid\":\"604\",\"parent_pid\":496"
                                      ",\"start\":1691420428,\"stime\":0,\"utime\":0},\"operation\":\"MODIFIED\"}"};

    EXPECT_FALSE(flatbufferSchemaStr.empty());

    bool ret = parseJSON(flatbufferSchemaStr, deltaProcesses);

    EXPECT_FALSE(ret);
}
