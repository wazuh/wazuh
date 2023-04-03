/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * March 31, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYSINFO_SOLARIS_PORTS_TEST_H
#define _SYSINFO_SOLARIS_PORTS_TEST_H

#include <fstream>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "ports/iportWrapper.h"
class SysInfoSolarisPortsTest : public ::testing::Test
{

    protected:
        SysInfoSolarisPortsTest() = default;
        virtual ~SysInfoSolarisPortsTest() = default;

        void SetUp() override;
        void TearDown() override;
};

typedef struct mib_item_test
{
    int group;
    int mib_id;
    int length;
    char    val[];
} mib_item_t;

/**
 * @brief declare some missing Solaris data types
 *
 */

typedef uint32_t        Gauge;
typedef uint32_t        IpAddress;
typedef uint32_t        DeviceIndex;

struct _solaris_in6_addr
{
    union
    {
        uint8_t         _S6_u8[16];
        uint32_t        _S6_u32[4];
        uint32_t        __S6_align;
    } _S6_un;
};
typedef struct _solaris_in6_addr Ip6Address;

typedef struct mib2_tcpConnEntry
{
    int             tcpConnState;
    IpAddress       tcpConnLocalAddress;
    int             tcpConnLocalPort;
    IpAddress       tcpConnRemAddress;
    int             tcpConnRemPort;
    struct tcpConnEntryInfo_s
    {
        Gauge           ce_snxt;
        Gauge           ce_suna;
        Gauge           ce_swnd;
        Gauge           ce_rnxt;
        Gauge           ce_rack;
        Gauge           ce_rwnd;
        Gauge           ce_rto;
        Gauge           ce_mss;
        int             ce_state;
    }               tcpConnEntryInfo;
    uint32_t        tcpConnCreationProcess;
    uint64_t        tcpConnCreationTime;
    uint32_t        tcpConnCreationRealUid;
} mib2_tcpConnEntry_t;

typedef struct mib2_tcp6ConnEntry
{
    Ip6Address      tcp6ConnLocalAddress;
    int             tcp6ConnLocalPort;
    Ip6Address      tcp6ConnRemAddress;
    int             tcp6ConnRemPort;
    DeviceIndex     tcp6ConnIfIndex;
    int             tcp6ConnState;
    struct tcp6ConnEntryInfo_s
    {
        Gauge           ce_snxt;
        Gauge           ce_suna;
        Gauge           ce_swnd;
        Gauge           ce_rnxt;
        Gauge           ce_rack;
        Gauge           ce_rwnd;
        Gauge           ce_rto;
        Gauge           ce_mss;
        int             ce_state;
    }               tcp6ConnEntryInfo;

    uint32_t        tcp6ConnCreationProcess;
    uint64_t        tcp6ConnCreationTime;
    uint32_t        tcp6ConnCreationRealUid;
} mib2_tcp6ConnEntry_t;

typedef struct mib2_udpEntry
{
    IpAddress       udpLocalAddress;
    int             udpLocalPort;
    struct udpEntryInfo_s
    {
        int             ue_state;
        IpAddress       ue_RemoteAddress;
        int             ue_RemotePort;
    }               udpEntryInfo;
    uint32_t        udpInstance;
    uint32_t        udpCreationProcess;
    uint64_t        udpCreationTime;
    uint32_t        udpCreationRealUid;
} mib2_udpEntry_t;

typedef struct mib2_udp6Entry
{
    Ip6Address      udp6LocalAddress;
    int             udp6LocalPort;
    DeviceIndex     udp6IfIndex;
    struct udp6EntryInfo_s
    {
        int     ue_state;
        Ip6Address      ue_RemoteAddress;
        int             ue_RemotePort;
    }               udp6EntryInfo;
    uint32_t        udp6Instance;
    uint32_t        udp6CreationProcess;
    uint64_t        udp6CreationTime;
    uint32_t        udp6CreationRealUid;
} mib2_udp6Entry_t;

/**
 * @brief binary dump of data generated in Solaris VM
 *
 */
const std::string testTCPbin
{
    '\x06', '\x01', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\xe4', '\x00', '\x00', '\x00',
    '\x04', '\x00', '\x00', '\x00', '\xc8', '\x00', '\x00', '\x00', '\x60', '\xea', '\x00', '\x00',
    '\xff', '\xff', '\xff', '\xff', '\xd0', '\xe5', '\x00', '\x00', '\xa0', '\xdc', '\x00', '\x00',
    '\xe0', '\x08', '\x00', '\x00', '\x09', '\x00', '\x00', '\x00', '\x03', '\x00', '\x00', '\x00',
    '\xfe', '\x4d', '\x41', '\x00', '\xad', '\x88', '\x50', '\x00', '\x65', '\x3f', '\x00', '\x00',
    '\x48', '\x00', '\x00', '\x00', '\x12', '\x00', '\x00', '\x00', '\x77', '\x32', '\x42', '\x00'
};

const std::string testTCP6bin
{
    '\x0e', '\x01', '\x00', '\x00', '\x0e', '\x00', '\x00', '\x00', '\xe8', '\x03', '\x00', '\x00',
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
    '\x00', '\x00', '\x00', '\x01', '\x6f', '\x17', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x02', '\x00', '\x00', '\x00',
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\xf4', '\x01', '\x00',
    '\x65', '\x04', '\x00', '\x00', '\xc4', '\x04', '\x00', '\x00', '\xfd', '\xff', '\xff', '\xff',
    '\x54', '\x00', '\x00', '\x00', '\xf9', '\x0a', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x6f', '\x00', '\x00', '\x00'
};

const std::string testUDPbin
{
    '\x07', '\x01', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x28', '\x00', '\x00', '\x00',
    '\xcc', '\x08', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\xb7', '\x08', '\x00', '\x00',
    '\x28', '\x00', '\x00', '\x00', '\x44', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
    '\xcc', '\x08', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\xb7', '\x08', '\x00', '\x00',
    '\x00', '\x00', '\x00', '\x00', '\x07', '\x01', '\x00', '\x00', '\x05', '\x00', '\x00', '\x00',
    '\x60', '\x04', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00'
};

const std::string testUDP6bin
{
    '\x0f', '\x01', '\x00', '\x00', '\x06', '\x00', '\x00', '\x00', '\x74', '\x03', '\x00', '\x00',
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
    '\x01', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
    '\x40', '\x5d', '\x5a', '\x04', '\x54', '\x00', '\x00', '\x00', '\xf9', '\x0a', '\x00', '\x00',
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x01', '\x00', '\x00', '\x00',
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x80', '\x98', '\x75', '\x04'
};

#endif //_SYSINFO_SOLARIS_PORTS_TEST_H
