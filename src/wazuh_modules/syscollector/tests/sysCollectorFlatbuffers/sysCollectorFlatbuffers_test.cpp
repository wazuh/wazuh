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

#include "sysCollectorFlatbuffers_test.h"
#include "flatbuffers/util.h"
#include "flatbuffers/idl.h"

const std::string netIfaceSchemaStr
{
    "namespace Syscollector;"
    "table Sys_netiface {"
    "    scan_time:string;"
    "    name:string;"
    "    adapter:string;"
    "    type:string;"
    "    state:string;"
    "    mtu:int;"
    "    mac:string;"
    "    tx_packets:int;"
    "    rx_packets:int;"
    "    tx_bytes:int;"
    "    rx_bytes:int;"
    "    tx_errors:int;"
    "    rx_errors:int;"
    "    tx_dropped:int;"
    "    rx_dropped:int;"
    "    item_id:string;"
    "    checksum:string;"
    "}"
    "root_type Sys_netiface;"};

const std::string netProtoSchemaStr
{
    "namespace Syscollector;"
    "table Sys_netproto {"
    "    iface:string;"
    "    type:string;"
    "    gateway:string;"
    "    dhcp:string;"
    "    metric:int;"
    "    item_id:string;"
    "    checksum:string;"
    "}"
    "root_type Sys_netproto;"};

const std::string netAddrSchemaStr
{
    "namespace Syscollector;"
    "table Sys_netaddr {"
    "    iface:string;"
    "    proto:string;"
    "    address:string;"
    "    netmask:string;"
    "    broadcast:string;"
    "    item_id:string;"
    "    checksum:string;"
    "}"
    "root_type Sys_netaddr;"};

const std::string osInfoSchemaStr
{
    "namespace Syscollector;"
    "table Sys_osinfo {"
    "    scan_time:string;"
    "    hostname:string;"
    "    architecture:string;"
    "    os_name:string;"
    "    os_version:string;"
    "    os_codename:string;"
    "    os_major:string;"
    "    os_minor:string;"
    "    os_patch:string;"
    "    os_build:string;"
    "    os_platform:string;"
    "    sysname:string;"
    "    release:string;"
    "    version:string;"
    "    os_release:string;"
    "    os_display_version:string;"
    "    triaged:int;"
    "    reference:string;"
    "    checksum:string;"
    "}"
    "root_type Sys_osinfo;"};

const std::string hwInfoSchemaStr
{
    "namespace Syscollector;"
    "table Sys_hwinfo {"
    "    scan_time:string;"
    "    board_serial:string;"
    "    cpu_name:string;"
    "    cpu_cores:int;"
    "    cpu_MHz:double;"
    "    ram_total:int;"
    "    ram_free:int;"
    "    ram_usage:int;"
    "    checksum:string;"
    "}"
    "root_type Sys_hwinfo;"};

const std::string portsSchemaStr
{
    "namespace Syscollector;"
    "table Sys_ports {"
    "    scan_time:string;"
    "    protocol:string;"
    "    local_ip:string;"
    "    local_port:int;"
    "    remote_ip:string;"
    "    remote_port:int;"
    "    tx_queue:int;"
    "    rx_queue:int;"
    "    inode:long;"
    "    state:string;"
    "    PID:int;"
    "    process:string;"
    "    item_id:string;"
    "    checksum:string;"
    "}"
    "root_type Sys_ports;"};

const std::string programsSchemaStr
{
    "namespace Syscollector;"
    "table Sys_programs {"
    "    scan_time:string;"
    "    format:string;"
    "    name:string;"
    "    priority:string;"
    "    section:string;"
    "    size:int;"
    "    vendor:string;"
    "    install_time:string;"
    "    version:string;"
    "    architecture:string;"
    "    multiarch:string;"
    "    source:string;"
    "    description:string;"
    "    location:string;"
    "    cpe:string;"
    "    msu_name:string;"
    "    checksum:string;"
    "    item_id:string;"
    "}"
    "root_type Sys_programs;"};

const std::string hotfixesSchemaStr
{
    "namespace Syscollector;"
    "table Sys_hotfixes {"
    "    scan_time:string;"
    "    hotfix:string;"
    "    checksum:string;"
    "}"
    "root_type Sys_hotfixes;"};

const std::string processesSchemaStr
{
    "namespace Syscollector;"
    "table Sys_processes {"
    "    scan_time:string;"
    "    pid:string;"
    "    name:string;"
    "    state:string;"
    "    ppid:int;"
    "    utime:int;"
    "    stime:int;"
    "    cmd:string;"
    "    argvs:string;"
    "    euser:string;"
    "    ruser:string;"
    "    suser:string;"
    "    egroup:string;"
    "    rgroup:string;"
    "    sgroup:string;"
    "    fgroup:string;"
    "    priority:int;"
    "    nice:int;"
    "    size:int;"
    "    vm_size:int;"
    "    resident:int;"
    "    share:int;"
    "    start_time:long;"
    "    pgrp:int;"
    "    session:int;"
    "    nlwp:int;"
    "    tgid:int;"
    "    tty:int;"
    "    processor:int;"
    "    checksum:string;"
    "}"
    "root_type Sys_processes;"};

bool parseJSON(const std::string& schemaPath, const std::string& jsonStr)
{
    flatbuffers::Parser parser;
    bool valid = parser.Parse(schemaPath.c_str()) && parser.Parse(jsonStr.c_str());

    if (!valid)
    {
        return valid;
    }

    std::string jsongen;

    if (GenText(parser, parser.builder_.GetBufferPointer(), &jsongen))
    {
        return false;
    }

    return true;
}

TEST_F(SyscollectorFlatbuffersTest, NetIfaceParsingSuccess)
{
    const std::string deltaNetIface {"{\"scan_time\":\"2023/08/0216:18:31\",\"name\":\"docker0\",\"adapter\":\"\",\"type\":\"ethernet\",\"state\":\"down\",\"mtu\":1500,\"mac\":\"02:42:47:a5:c3:ca\""
                                     ",\"tx_packets\":232513,\"rx_packets\":74846,\"tx_bytes\":532393715,\"rx_bytes\":3100345,\"tx_errors\":0,\"rx_errors\":0,\"tx_dropped\":0,\"rx_dropped\":0"
                                     ",\"checksum\":\"c4fdf3ad8ba4e3f01561f9fc13869c1bac1b683f\",\"item_id\":\"c3cbf3edb7c5565edb919ccb2475845270839642\"}"};

    bool ret = parseJSON(netIfaceSchemaStr, deltaNetIface);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorFlatbuffersTest, NetIfaceParsingInvalid)
{
    // mtu is a string that represents an invalid number.
    const std::string deltaNetIface  {"{\"scan_time\":\"2023/08/0216:18:31\",\"name\":\"docker0\",\"adapter\":\"\",\"type\":\"ethernet\",\"state\":\"down\",\"mtu\":\"150x\",\"mac\":\"02:42:47:a5:c3:ca\""
                                      ",\"tx_packets\":232513,\"rx_packets\":74846,\"tx_bytes\":532393715,\"rx_bytes\":3100345,\"tx_errors\":0,\"rx_errors\":0,\"tx_dropped\":0,\"rx_dropped\":0"
                                      ",\"checksum\":\"c4fdf3ad8ba4e3f01561f9fc13869c1bac1b683f\",\"item_id\":\"c3cbf3edb7c5565edb919ccb2475845270839642\"}"};

    bool ret = parseJSON(netIfaceSchemaStr, deltaNetIface);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorFlatbuffersTest, NetProtoParsingSuccess)
{
    const std::string deltaNetProto {"{\"iface\":\"enp4s0\",\"type\":\"ethernet\",\"gateway\":\"192.168.33.1\",\"dhcp\":\"unknown\",\"metric\":10"
                                     ",\"checksum\":\"52efff87f3ead7b93b1fb4dc41d79a01c0696d67\",\"item_id\":\"5d7838daf8d727f9493afed262d6adb37e2c990e\"}"};

    bool ret = parseJSON(netProtoSchemaStr, deltaNetProto);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorFlatbuffersTest, NetProtoParsingInvalid)
{
    // metric is a string that represents an invalid number.
    const std::string deltaNetProto {"{\"iface\":\"enp4s0\",\"type\":\"ethernet\",\"gateway\":\"192.168.33.1\",\"dhcp\":\"unknown\",\"metric\":\"1x\""
                                     ",\"checksum\":\"52efff87f3ead7b93b1fb4dc41d79a01c0696d67\",\"item_id\":\"5d7838daf8d727f9493afed262d6adb37e2c990e\"}"};

    bool ret = parseJSON(netProtoSchemaStr, deltaNetProto);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorFlatbuffersTest, NetAddrParsingSuccess)
{
    const std::string deltaNetAddr {"{\"iface\":\"enp0s9\",\"proto\":\"ipv4\",\"address\":\"192.168.33.10\",\"netmask\":\"255.0.0.0\",\"broadcast\":\"192.168.33.255\""
                                    ",\"checksum\":\"52efff87f3ead7b93b1fb4dc41d79a01c0696d67\",\"item_id\":\"5d7838daf8d727f9493afed262d6adb37e2c990e\"}"};

    bool ret = parseJSON(netAddrSchemaStr, deltaNetAddr);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorFlatbuffersTest, NetAddrParsingInvalid)
{
    // Invalid field "oface".
    const std::string deltaNetAddr {"{\"oface\":\"enp0s9\",\"proto\":\"ipv4\",\"address\":\"192.168.33.10\",\"netmask\":\"255.0.0.0\",\"broadcast\":\"192.168.33.255\""
                                    ",\"checksum\":\"52efff87f3ead7b93b1fb4dc41d79a01c0696d67\",\"item_id\":\"5d7838daf8d727f9493afed262d6adb37e2c990e\"}"};

    bool ret = parseJSON(netAddrSchemaStr, deltaNetAddr);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorFlatbuffersTest, OsInfoParsingSuccess)
{
    const std::string deltaOsInfo {"{\"scan_time\":\"2023/08/0216:19:50\",\"hostname\":\"jammy\",\"architecture\":\"x86_64\",\"os_name\":\"Ubuntu\",\"os_version\":\"22.04.2LTS(JammyJellyfish)\""
                                   ",\"os_codename\":\"jammy\",\"os_major\":\"22\",\"os_minor\":\"04\",\"os_patch\":\"2\",\"os_build\":\"13\",\"os_platform\":\"ubuntu\",\"sysname\":\"Linux\""
                                   ",\"release\":\"5.15.0-78-generic\",\"version\":\"#85-UbuntuSMPFriJul715:25:09UTC2023\",\"os_release\":\"\",\"checksum\":\"1690993189011033690\"}"};

    bool ret = parseJSON(osInfoSchemaStr, deltaOsInfo);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorFlatbuffersTest, OsInfoParsingInvalid)
{
    // os_major is an integer.
    const std::string deltaOsInfo {"{\"scan_time\":\"2023/08/0216:19:50\",\"hostname\":\"jammy\",\"architecture\":\"x86_64\",\"os_name\":\"Ubuntu\",\"os_version\":\"22.04.2LTS(JammyJellyfish)\""
                                   ",\"os_codename\":\"jammy\",\"os_major\":22,\"os_minor\":\"04\",\"os_patch\":\"2\",\"os_build\":\"13\",\"os_platform\":\"ubuntu\",\"sysname\":\"Linux\""
                                   ",\"release\":\"5.15.0-78-generic\",\"version\":\"#85-UbuntuSMPFriJul715:25:09UTC2023\",\"os_release\":\"\",\"checksum\":\"1690993189011033690\"}"};

    bool ret = parseJSON(osInfoSchemaStr, deltaOsInfo);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorFlatbuffersTest, HwInfoParsingSuccess)
{
    const std::string deltaHwInfo {"{\"scan_time\":\"0\",\"board_serial\":\"0\",\"cpu_name\":\"Intel\",\"cpu_cores\":12,\"cpu_MHz\":2592,\"ram_free\":9388884"
                                   ",\"ram_total\":12243552,\"ram_usage\":24,\"checksum\":\"0\"}"};

    bool ret = parseJSON(hwInfoSchemaStr, deltaHwInfo);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorFlatbuffersTest, HwInfoParsingInvalid)
{
    // scan_time is an integer.
    const std::string deltaHwInfo {"{\"scan_time\":0,\"board_serial\":\"0\",\"cpu_name\":\"Intel\",\"cpu_cores\":12,\"cpu_MHz\":2592,\"ram_free\":9388884"
                                   ",\"ram_total\":12243552,\"ram_usage\":24,\"checksum\":\"0\"}"};

    bool ret = parseJSON(hwInfoSchemaStr, deltaHwInfo);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorFlatbuffersTest, PortsParsingSuccess)
{
    const std::string deltaPorts {"{\"scan_time\":\"2023/08/0216:19:51\",\"protocol\":\"tcp\",\"local_ip\":\"0.0.0.0\",\"local_port\":1515,\"remote_ip\":\"0.0.0.0\",\"remote_port\":0"
                                  ",\"tx_queue\":0,\"rx_queue\":0,\"inode\":837631,\"state\":\"listening\",\"PID\":1001,\"process\":\"Wazuh\",\"checksum\":\"465f941549053027500e651229fc68bb91829731\""
                                  ",\"item_id\":\"31a0c3735e8e79ecd60d1bb7c86ca97892aac813\"}"};

    bool ret = parseJSON(portsSchemaStr, deltaPorts);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorFlatbuffersTest, PortsParsingInvalid)
{
    // local_port is a string that represents an invalid number.
    const std::string deltaPorts {"{\"scan_time\":\"2023/08/0216:19:51\",\"protocol\":\"tcp\",\"local_ip\":\"0.0.0.0\",\"local_port\":\"151x\",\"remote_ip\":\"0.0.0.0\",\"remote_port\":0"
                                  ",\"tx_queue\":0,\"rx_queue\":0,\"inode\":837631,\"state\":\"listening\",\"PID\":1001,\"process\":\"Wazuh\",\"checksum\":\"465f941549053027500e651229fc68bb91829731\""
                                  ",\"item_id\":\"31a0c3735e8e79ecd60d1bb7c86ca97892aac813\"}"};

    bool ret = parseJSON(portsSchemaStr, deltaPorts);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorFlatbuffersTest, PackagesParsingSuccess)
{
    const std::string deltaPackages {"{\"scan_time\":\"2023/08/0120:13:06\",\"format\":\"win\",\"name\":\"OpenSSL3.1.1Light(64-bit)\",\"priority\":\"\",\"section\":\"\",\"size\":0"
                                     ",\"vendor\":\"OpenSSLWin64InstallerTeam\",\"install_time\":\"2023/07/2119:13:32\",\"version\":\"3.1.1\",\"architecture\":\"x86_64\",\"multiarch\":\"\""
                                     ",\"source\":\"\",\"description\":\"\",\"location\":\"C:\\\\ProgramFiles\\\\OpenSSL-Win64\\\\\",\"cpe\":\"\",\"msu_name\":\"\""
                                     ",\"checksum\":\"de1307043a78c98219e48a14df520684b7859ef7\",\"item_id\":\"dab71c54d6ca3227f014da2ed3f60f3964c2bb79\"}"};

    bool ret = parseJSON(programsSchemaStr, deltaPackages);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorFlatbuffersTest, PackagesParsingInvalid)
{
    // Invalid field "arch"
    const std::string deltaPackages {"{\"scan_time\":\"2023/08/0120:13:06\",\"format\":\"win\",\"name\":\"OpenSSL3.1.1Light(64-bit)\",\"priority\":\"\",\"section\":\"\",\"size\":0"
                                     ",\"vendor\":\"OpenSSLWin64InstallerTeam\",\"install_time\":\"2023/07/2119:13:32\",\"version\":\"3.1.1\",\"arch\":\"x86_64\",\"multiarch\":\"\""
                                     ",\"source\":\"\",\"description\":\"\",\"location\":\"C:\\\\ProgramFiles\\\\OpenSSL-Win64\\\\\",\"cpe\":\"\",\"msu_name\":\"\""
                                     ",\"checksum\":\"de1307043a78c98219e48a14df520684b7859ef7\",\"item_id\":\"dab71c54d6ca3227f014da2ed3f60f3964c2bb79\"}"};


    bool ret = parseJSON(programsSchemaStr, deltaPackages);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorFlatbuffersTest, HotfixesParsingSuccess)
{
    const std::string deltaHotfixes {"{\"scan_time\":\"2023/08/0120:13:00\",\"hotfix\":\"KB982573\",\"checksum\":\"62a01d14af223e0ddeb5a5182e101ebfe1b12007\"}"};

    bool ret = parseJSON(hotfixesSchemaStr, deltaHotfixes);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorFlatbuffersTest, HotfixesParsingInvalid)
{
    // Invalid field "hitfix".
    const std::string deltaHotfixes {"{\"scan_time\":\"2023/08/0120:13:00\",\"hitfix\":\"KB982573\",\"checksum\":\"62a01d14af223e0ddeb5a5182e101ebfe1b12007\"}"};

    bool ret = parseJSON(hotfixesSchemaStr, deltaHotfixes);

    EXPECT_FALSE(ret);
}

TEST_F(SyscollectorFlatbuffersTest, ProcessesParsingSuccess)
{
    // We should escape double backslashes the message from agent.
    const std::string deltaProcesses {"{\"scan_time\":\"2023/08/0120:26:05\",\"pid\":\"680\",\"name\":\"winlogon.exe\",\"state\":\" \",\"ppid\":580,\"utime\":0,\"stime\":0"
                                      ",\"cmd\":\"C:\\\\Windows\\\\System32\\\\winlogon.exe\",\"argvs\":\"\",\"euser\":\"\",\"ruser\":\"\",\"suser\":\"\",\"egroup\":\"\",\"rgroup\":\"\",\"sgroup\":\"\",\"fgroup\":\"\""
                                      ",\"priority\":13,\"nice\":0,\"size\":2457600,\"vm_size\":13078528,\"resident\":0,\"share\":0,\"start_time\":1690932335,\"pgrp\":0,\"session\":1,\"nlwp\":7,\"tgid\":0,\"tty\":0"
                                      ",\"processor\":0,\"checksum\":\"47cce79a885fe33c5619cc8fdb73828340fe804b\"}"};

    bool ret = parseJSON(processesSchemaStr, deltaProcesses);

    EXPECT_TRUE(ret);
}

TEST_F(SyscollectorFlatbuffersTest, ProcessesParsingInvalid)
{
    // Double backslashed not escaped.
    const std::string deltaProcesses {"{\"scan_time\":\"2023/08/0120:26:05\",\"pid\":\"680\",\"name\":\"winlogon.exe\",\"state\":\" \",\"ppid\":580,\"utime\":0,\"stime\":0"
                                      ",\"cmd\":\"C:\\Windows\\\\System32\\\\winlogon.exe\",\"argvs\":\"\",\"euser\":\"\",\"ruser\":\"\",\"suser\":\"\",\"egroup\":\"\",\"rgroup\":\"\",\"sgroup\":\"\",\"fgroup\":\"\""
                                      ",\"priority\":13,\"nice\":0,\"size\":2457600,\"vm_size\":13078528,\"resident\":0,\"share\":0,\"start_time\":1690932335,\"pgrp\":0,\"session\":1,\"nlwp\":7,\"tgid\":0,\"tty\":0"
                                      ",\"processor\":0,\"checksum\":\"47cce79a885fe33c5619cc8fdb73828340fe804b\"}"};

    bool ret = parseJSON(processesSchemaStr, deltaProcesses);

    EXPECT_FALSE(ret);
}
