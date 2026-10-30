/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * October 19, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <arpa/inet.h>
#include <filesystem>
#include <ifaddrs.h>
#include "sysInfoNetworkLinux_test.h"
#include "network/networkInterfaceLinux.h"
#include "network/networkFamilyDataAFactory.h"
#include "network/networkLinuxWrapper.h"

// Absent from kernel headers older than 3.14
#ifndef IFA_F_NOPREFIXROUTE
#define IFA_F_NOPREFIXROUTE 0x200
#endif

void SysInfoNetworkLinuxTest::SetUp() {};

void SysInfoNetworkLinuxTest::TearDown()
{
};

using ::testing::_;
using ::testing::Return;

class SysInfoNetworkLinuxWrapperMock: public INetworkInterfaceWrapper
{
    public:
        SysInfoNetworkLinuxWrapperMock() = default;
        virtual ~SysInfoNetworkLinuxWrapperMock() = default;
        MOCK_METHOD(int, family, (), (const override));
        MOCK_METHOD(std::string, name, (), (const override));
        MOCK_METHOD(std::string, address, (), (const override));
        MOCK_METHOD(std::string, netmask, (), (const override));
        MOCK_METHOD(std::string, broadcast, (), (const override));
        MOCK_METHOD(std::string, addressV6, (), (const override));
        MOCK_METHOD(std::string, netmaskV6, (), (const override));
        MOCK_METHOD(std::string, broadcastV6, (), (const override));
        MOCK_METHOD(std::string, gateway, (), (const override));
        MOCK_METHOD(std::string, gatewayV6, (), (const override));
        MOCK_METHOD(std::string, metrics, (), (const override));
        MOCK_METHOD(std::string, metricsV6, (), (const override));
        MOCK_METHOD(std::string, dhcp, (), (const override));
        MOCK_METHOD(uint32_t, mtu, (), (const override));
        MOCK_METHOD(LinkStats, stats, (), (const override));
        MOCK_METHOD(std::string, type, (), (const override));
        MOCK_METHOD(std::string, state, (), (const override));
        MOCK_METHOD(std::string, MAC, (), (const override));
        MOCK_METHOD(std::string, adapter, (), (const override));
};

TEST_F(SysInfoNetworkLinuxTest, Test_AF_INET_THROW)
{
    auto mock { std::make_shared<SysInfoNetworkLinuxWrapperMock>() };
    nlohmann::json ifaddr {};
    EXPECT_CALL(*mock, family()).Times(1).WillOnce(Return(AF_INET));
    EXPECT_CALL(*mock, address()).Times(1).WillOnce(Return(""));
    EXPECT_ANY_THROW(FactoryNetworkFamilyCreator<OSPlatformType::LINUX>::create(mock)->buildNetworkData(ifaddr));
}

TEST_F(SysInfoNetworkLinuxTest, Test_AF_INET)
{
    auto mock { std::make_shared<SysInfoNetworkLinuxWrapperMock>() };
    nlohmann::json ifaddr {};
    EXPECT_CALL(*mock, family()).Times(1).WillOnce(Return(AF_INET));
    EXPECT_CALL(*mock, address()).Times(1).WillOnce(Return("192.168.0.1"));
    EXPECT_CALL(*mock, netmask()).Times(1).WillOnce(Return("255.255.255.0"));
    EXPECT_CALL(*mock, broadcast()).Times(1).WillOnce(Return("192.168.0.255"));
    EXPECT_CALL(*mock, dhcp()).Times(1).WillOnce(Return("8.8.8.8"));
    EXPECT_CALL(*mock, metrics()).Times(1).WillOnce(Return("100"));
    EXPECT_NO_THROW(FactoryNetworkFamilyCreator<OSPlatformType::LINUX>::create(mock)->buildNetworkData(ifaddr));

    for (auto& element : ifaddr.at("IPv4"))
    {
        EXPECT_EQ("192.168.0.1", element.at("address").get_ref<const std::string&>());
        EXPECT_EQ("255.255.255.0", element.at("netmask").get_ref<const std::string&>());
        EXPECT_EQ("192.168.0.255", element.at("broadcast").get_ref<const std::string&>());
        EXPECT_EQ("8.8.8.8", element.at("dhcp").get_ref<const std::string&>());
        EXPECT_EQ("100", element.at("metric").get_ref<const std::string&>());
    }
}

TEST_F(SysInfoNetworkLinuxTest, Test_AF_INET6_THROW)
{
    auto mock { std::make_shared<SysInfoNetworkLinuxWrapperMock>() };
    nlohmann::json ifaddr {};
    EXPECT_CALL(*mock, family()).Times(1).WillOnce(Return(AF_INET6));
    EXPECT_CALL(*mock, addressV6()).Times(1).WillOnce(Return(""));
    EXPECT_ANY_THROW(FactoryNetworkFamilyCreator<OSPlatformType::LINUX>::create(mock)->buildNetworkData(ifaddr));
}

TEST_F(SysInfoNetworkLinuxTest, Test_AF_INET6)
{
    auto mock { std::make_shared<SysInfoNetworkLinuxWrapperMock>() };
    nlohmann::json ifaddr {};
    EXPECT_CALL(*mock, family()).Times(1).WillOnce(Return(AF_INET6));
    EXPECT_CALL(*mock, addressV6()).Times(1).WillOnce(Return("2001:db8:85a3:8d3:1319:8a2e:370:7348"));
    EXPECT_CALL(*mock, netmaskV6()).Times(1).WillOnce(Return("2001:db8:abcd:0012:ffff:ffff:ffff:ffff"));
    EXPECT_CALL(*mock, broadcastV6()).Times(1).WillOnce(Return("2001:db8:85a3:8d3:1319:8a2e:370:0000"));
    EXPECT_CALL(*mock, dhcp()).Times(1).WillOnce(Return("8.8.8.8"));
    EXPECT_CALL(*mock, metricsV6()).Times(1).WillOnce(Return("100"));
    EXPECT_NO_THROW(FactoryNetworkFamilyCreator<OSPlatformType::LINUX>::create(mock)->buildNetworkData(ifaddr));

    for (auto& element : ifaddr.at("IPv6"))
    {
        EXPECT_EQ("2001:db8:85a3:8d3:1319:8a2e:370:7348", element.at("address").get_ref<const std::string&>());
        EXPECT_EQ("2001:db8:abcd:0012:ffff:ffff:ffff:ffff", element.at("netmask").get_ref<const std::string&>());
        EXPECT_EQ("2001:db8:85a3:8d3:1319:8a2e:370:0000", element.at("broadcast").get_ref<const std::string&>());
        EXPECT_EQ("8.8.8.8", element.at("dhcp").get_ref<const std::string&>());
        EXPECT_EQ("100", element.at("metric").get_ref<const std::string&>());
    }
}


TEST_F(SysInfoNetworkLinuxTest, Test_AF_PACKET)
{
    auto mock { std::make_shared<SysInfoNetworkLinuxWrapperMock>() };
    nlohmann::json ifaddr {};
    EXPECT_CALL(*mock, family()).Times(1).WillOnce(Return(AF_PACKET));
    EXPECT_CALL(*mock, name()).Times(1).WillOnce(Return("eth01"));
    EXPECT_CALL(*mock, adapter()).Times(1).WillOnce(Return("adapter"));
    EXPECT_CALL(*mock, type()).Times(1).WillOnce(Return("ethernet"));
    EXPECT_CALL(*mock, state()).Times(1).WillOnce(Return("up"));
    EXPECT_CALL(*mock, MAC()).Times(1).WillOnce(Return("00:A0:C9:14:C8:29"));
    EXPECT_CALL(*mock, stats()).Times(1).WillOnce(Return(LinkStats{0, 1, 2, 3, 4, 5, 6, 7}));
    EXPECT_CALL(*mock, mtu()).Times(1).WillOnce(Return(1500));
    EXPECT_CALL(*mock, gateway()).Times(1).WillOnce(Return("10.2.2.50"));
    EXPECT_CALL(*mock, gatewayV6()).Times(1).WillOnce(Return("fe80::1"));

    EXPECT_NO_THROW(FactoryNetworkFamilyCreator<OSPlatformType::LINUX>::create(mock)->buildNetworkData(ifaddr));

    EXPECT_EQ("eth01", ifaddr.at("name").get_ref<const std::string&>());
    EXPECT_EQ("adapter", ifaddr.at("adapter").get_ref<const std::string&>());
    EXPECT_EQ("ethernet", ifaddr.at("type").get_ref<const std::string&>());
    EXPECT_EQ("up", ifaddr.at("state").get_ref<const std::string&>());
    EXPECT_EQ("00:A0:C9:14:C8:29", ifaddr.at("mac").get_ref<const std::string&>());

    EXPECT_EQ(1, ifaddr.at("tx_packets").get<int32_t>());
    EXPECT_EQ(0, ifaddr.at("rx_packets").get<int32_t>());
    EXPECT_EQ(3, ifaddr.at("tx_bytes").get<int32_t>());
    EXPECT_EQ(2, ifaddr.at("rx_bytes").get<int32_t>());
    EXPECT_EQ(5, ifaddr.at("tx_errors").get<int32_t>());
    EXPECT_EQ(4, ifaddr.at("rx_errors").get<int32_t>());
    EXPECT_EQ(7, ifaddr.at("tx_dropped").get<int32_t>());
    EXPECT_EQ(6, ifaddr.at("rx_dropped").get<int32_t>());

    EXPECT_EQ(1500u, ifaddr.at("mtu").get<uint32_t>());
    EXPECT_EQ("10.2.2.50", ifaddr.at("gateway").get_ref<const std::string&>());
    EXPECT_EQ("fe80::1", ifaddr.at("gateway6").get_ref<const std::string&>());
}

TEST_F(SysInfoNetworkLinuxTest, Test_AF_UNSPEC_THROW_NULLPTR)
{
    nlohmann::json ifaddr {};
    EXPECT_ANY_THROW(FactoryNetworkFamilyCreator<OSPlatformType::LINUX>::create(nullptr)->buildNetworkData(ifaddr));
}

TEST_F(SysInfoNetworkLinuxTest, Test_Gateway_7546)
{
    auto mock { std::make_shared<SysInfoNetworkLinuxWrapperMock>() };
    nlohmann::json ifaddr {};
    EXPECT_CALL(*mock, family()).Times(1).WillOnce(Return(AF_PACKET));
    EXPECT_CALL(*mock, name()).Times(1).WillOnce(Return("eth01"));
    EXPECT_CALL(*mock, adapter()).Times(1).WillOnce(Return("adapter"));
    EXPECT_CALL(*mock, type()).Times(1).WillOnce(Return("ethernet"));
    EXPECT_CALL(*mock, state()).Times(1).WillOnce(Return("up"));
    EXPECT_CALL(*mock, MAC()).Times(1).WillOnce(Return("00:A0:C9:14:C8:29"));
    EXPECT_CALL(*mock, stats()).Times(1).WillOnce(Return(LinkStats{0, 1, 2, 3, 4, 5, 6, 7}));
    EXPECT_CALL(*mock, mtu()).Times(1).WillOnce(Return(1500));
    EXPECT_CALL(*mock, gateway()).Times(1).WillOnce(Return("A12BA8C0")); // Gateway value in hexa: A12BA8C0
    EXPECT_CALL(*mock, gatewayV6()).Times(1).WillOnce(Return("fe80::1"));

    EXPECT_NO_THROW(FactoryNetworkFamilyCreator<OSPlatformType::LINUX>::create(mock)->buildNetworkData(ifaddr));

    EXPECT_EQ("eth01", ifaddr.at("name").get_ref<const std::string&>());
    EXPECT_EQ("adapter", ifaddr.at("adapter").get_ref<const std::string&>());
    EXPECT_EQ("ethernet", ifaddr.at("type").get_ref<const std::string&>());
    EXPECT_EQ("up", ifaddr.at("state").get_ref<const std::string&>());
    EXPECT_EQ("00:A0:C9:14:C8:29", ifaddr.at("mac").get_ref<const std::string&>());

    EXPECT_EQ(1, ifaddr.at("tx_packets").get<int32_t>());
    EXPECT_EQ(0, ifaddr.at("rx_packets").get<int32_t>());
    EXPECT_EQ(3, ifaddr.at("tx_bytes").get<int32_t>());
    EXPECT_EQ(2, ifaddr.at("rx_bytes").get<int32_t>());
    EXPECT_EQ(5, ifaddr.at("tx_errors").get<int32_t>());
    EXPECT_EQ(4, ifaddr.at("rx_errors").get<int32_t>());
    EXPECT_EQ(7, ifaddr.at("tx_dropped").get<int32_t>());
    EXPECT_EQ(6, ifaddr.at("rx_dropped").get<int32_t>());
    EXPECT_EQ(1500, ifaddr.at("mtu").get<int32_t>());
    EXPECT_EQ("A12BA8C0", ifaddr.at("gateway").get_ref<const std::string&>());
    EXPECT_EQ("fe80::1", ifaddr.at("gateway6").get_ref<const std::string&>());
}

// /proc/net/ipv6_route lines: a link route, reject routes on lo and an RA default route on eth0
static const std::string IPV6_ROUTE_TABLE
{
    "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n"
    "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n"
    "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00450003     eth0\n"
};

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV6_DefaultRoute)
{
    EXPECT_EQ("fe80::1", NetworkLinuxInterface::parseGatewayV6(IPV6_ROUTE_TABLE, "eth0"));
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV6_NoDefaultRoute)
{
    const std::string table
    {
        "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n"
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n"
    };
    EXPECT_EQ(" ", NetworkLinuxInterface::parseGatewayV6(table, "eth0"));
    EXPECT_EQ(" ", NetworkLinuxInterface::parseGatewayV6(table, "lo"));
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV6_OtherInterface)
{
    EXPECT_EQ(" ", NetworkLinuxInterface::parseGatewayV6(IPV6_ROUTE_TABLE, "eth1"));
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV6_GlobalNextHop)
{
    const std::string table
    {
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 20010db8000000000000000000000001 00000400 00000001 00000000 00000003     ens5\n"
    };
    EXPECT_EQ("2001:db8::1", NetworkLinuxInterface::parseGatewayV6(table, "ens5"));
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV6_NoGatewayFlag)
{
    const std::string table
    {
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000001     eth0\n"
    };
    EXPECT_EQ(" ", NetworkLinuxInterface::parseGatewayV6(table, "eth0"));
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV6_SourceSpecificRoute)
{
    const std::string table
    {
        "00000000000000000000000000000000 00 20010db8000000000000000000000000 40 fe800000000000000000000000000002 0000000a 00000001 00000000 00000003       d0\n"
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003       d0\n"
    };
    EXPECT_EQ("fe80::1", NetworkLinuxInterface::parseGatewayV6(table, "d0"));
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV6_MalformedInput)
{
    const std::string table
    {
        "\n"
        "garbage\n"
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe80000000000000000000000000zz01 00000400 00000001 00000000 00000003     eth0\n"
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 1000000000000000003     eth0\n"
    };
    EXPECT_NO_THROW(NetworkLinuxInterface::parseGatewayV6(table, "eth0"));
    EXPECT_EQ(" ", NetworkLinuxInterface::parseGatewayV6(table, "eth0"));
    EXPECT_EQ(" ", NetworkLinuxInterface::parseGatewayV6("", "eth0"));
}

TEST_F(SysInfoNetworkLinuxTest, Test_RedHatDhcpStatusStripsQuotes)
{
    EXPECT_EQ("disabled", NetworkLinuxInterface::getRedHatDHCPStatus({ "BOOTPROTO", "'static'" }));
    EXPECT_EQ("disabled", NetworkLinuxInterface::getRedHatDHCPStatus({ "BOOTPROTO", "\"none\"" }));
    EXPECT_EQ("enabled", NetworkLinuxInterface::getRedHatDHCPStatus({ "BOOTPROTO", "\"dhcp\"" }));
    EXPECT_EQ("BOOTP", NetworkLinuxInterface::getRedHatDHCPStatus({ "BOOTPROTO", "'bootp'" }));
}

TEST_F(SysInfoNetworkLinuxTest, Test_RedHatDhcpStatusUnquotedAndUnknownValues)
{
    EXPECT_EQ("disabled", NetworkLinuxInterface::getRedHatDHCPStatus({ "BOOTPROTO", "static" }));
    EXPECT_EQ("enabled", NetworkLinuxInterface::getRedHatDHCPStatus({ "BOOTPROTO", "dhcp" }));
    EXPECT_EQ("enabled", NetworkLinuxInterface::getRedHatDHCPStatus({ "BOOTPROTO", "something-else" }));
    EXPECT_EQ("enabled", NetworkLinuxInterface::getRedHatDHCPStatus({ "BOOTPROTO", "'dhcp" }));
}

TEST_F(SysInfoNetworkLinuxTest, Test_RedHatDhcpStatusIgnoresTrailingCarriageReturn)
{
    EXPECT_EQ("disabled", NetworkLinuxInterface::getRedHatDHCPStatus({ "BOOTPROTO", "static\r" }));
    EXPECT_EQ("disabled", NetworkLinuxInterface::getRedHatDHCPStatus({ "BOOTPROTO", " 'static' \r" }));
}

TEST_F(SysInfoNetworkLinuxTest, Test_ResolveDhcpFileResultWins)
{
    EXPECT_EQ("disabled", NetworkLinuxInterface::resolveDhcp("disabled", true, 0));
    EXPECT_EQ("enabled", NetworkLinuxInterface::resolveDhcp("enabled", true, IFA_F_PERMANENT));
    EXPECT_EQ("BOOTP", NetworkLinuxInterface::resolveDhcp("BOOTP", true, 0));
}

TEST_F(SysInfoNetworkLinuxTest, Test_ResolveDhcpUnknownAndNotPermanent)
{
    EXPECT_EQ("enabled", NetworkLinuxInterface::resolveDhcp("unknown", true, 0));
    EXPECT_EQ("enabled", NetworkLinuxInterface::resolveDhcp("unknown", true, IFA_F_NOPREFIXROUTE));
}

TEST_F(SysInfoNetworkLinuxTest, Test_ResolveDhcpUnknownAndPermanent)
{
    EXPECT_EQ("unknown", NetworkLinuxInterface::resolveDhcp("unknown", true, IFA_F_PERMANENT));
    EXPECT_EQ("unknown", NetworkLinuxInterface::resolveDhcp("unknown", true, IFA_F_PERMANENT | IFA_F_NOPREFIXROUTE));
}

TEST_F(SysInfoNetworkLinuxTest, Test_ResolveDhcpWithoutFlagsStaysUnknown)
{
    EXPECT_EQ("unknown", NetworkLinuxInterface::resolveDhcp("unknown", false, 0));
}

namespace
{
    // An IPv4 entry of a link that no configuration file knows, so the file checks answer "unknown".
    struct FakeIPv4Entry
    {
        sockaddr_in address {};
        ifaddrs entry {};
        std::string name;

        FakeIPv4Entry(const std::string& ifName, const char* ipv4)
            : name{ ifName }
        {
            address.sin_family = AF_INET;
            inet_pton(AF_INET, ipv4, &address.sin_addr);
            entry.ifa_name = const_cast<char*>(name.c_str());
            entry.ifa_addr = reinterpret_cast<sockaddr*>(&address);
        }
    };
}

TEST_F(SysInfoNetworkLinuxTest, Test_DhcpUsesTheFlagsOfTheAddress)
{
    FakeIPv4Entry leased { "wztest0:lease", "10.77.0.2" };
    FakeIPv4Entry fixed { "wztest0:fixed", "10.77.0.3" };
    FakeIPv4Entry other { "wztest0:other", "10.77.0.4" };
    const IPv4AddressFlags addressFlags
    {
        { { "wztest0", "10.77.0.2" }, 0 },
        { { "wztest0", "10.77.0.3" }, IFA_F_PERMANENT },
    };
    const auto flags { std::make_shared<const IPv4AddressFlags>(addressFlags) };

    EXPECT_EQ("enabled", NetworkLinuxInterface(&leased.entry, "wztest0", flags).dhcp());
    EXPECT_EQ("unknown", NetworkLinuxInterface(&fixed.entry, "wztest0", flags).dhcp());
    // Not in the dump, or no dump at all.
    EXPECT_EQ("unknown", NetworkLinuxInterface(&other.entry, "wztest0", flags).dhcp());
    EXPECT_EQ("unknown", NetworkLinuxInterface(&leased.entry, "wztest0").dhcp());
    // The flags belong to the link, not to the label.
    EXPECT_EQ("unknown", NetworkLinuxInterface(&leased.entry, "wztest1", flags).dhcp());
}

namespace
{
    // An entry with the addresses the wrapper decodes; each family fills only the fields it reads.
    struct FakeAddressEntry
    {
        sockaddr_in address {};
        sockaddr_in netmask {};
        sockaddr_in broadcast {};
        sockaddr_in6 address6 {};
        sockaddr_in6 netmask6 {};
        sockaddr_in6 broadcast6 {};
        ifaddrs entry {};
        std::string name;

        explicit FakeAddressEntry(const std::string& ifName)
            : name{ ifName }
        {
            entry.ifa_name = const_cast<char*>(name.c_str());
        }

        void setIPv4(const char* ip, const char* mask, const char* broadcastIp = nullptr)
        {
            address.sin_family = AF_INET;
            inet_pton(AF_INET, ip, &address.sin_addr);
            entry.ifa_addr = reinterpret_cast<sockaddr*>(&address);
            netmask.sin_family = AF_INET;
            inet_pton(AF_INET, mask, &netmask.sin_addr);
            entry.ifa_netmask = reinterpret_cast<sockaddr*>(&netmask);

            if (broadcastIp)
            {
                broadcast.sin_family = AF_INET;
                inet_pton(AF_INET, broadcastIp, &broadcast.sin_addr);
                entry.ifa_broadaddr = reinterpret_cast<sockaddr*>(&broadcast);
            }
        }

        void setIPv6(const char* ip, const char* mask, const char* broadcastIp = nullptr)
        {
            address6.sin6_family = AF_INET6;
            inet_pton(AF_INET6, ip, &address6.sin6_addr);
            entry.ifa_addr = reinterpret_cast<sockaddr*>(&address6);
            netmask6.sin6_family = AF_INET6;
            inet_pton(AF_INET6, mask, &netmask6.sin6_addr);
            entry.ifa_netmask = reinterpret_cast<sockaddr*>(&netmask6);

            if (broadcastIp)
            {
                broadcast6.sin6_family = AF_INET6;
                inet_pton(AF_INET6, broadcastIp, &broadcast6.sin6_addr);
                entry.ifa_broadaddr = reinterpret_cast<sockaddr*>(&broadcast6);
            }
        }
    };
}

TEST_F(SysInfoNetworkLinuxTest, Test_WrapperRejectsNullEntry)
{
    EXPECT_THROW(NetworkLinuxInterface(nullptr, "wztest0"), std::runtime_error);
}

TEST_F(SysInfoNetworkLinuxTest, Test_WrapperReadsIPv4Entry)
{
    FakeAddressEntry fake { "wztest0:lease" };
    fake.setIPv4("10.77.0.2", "255.255.255.0", "10.77.0.255");
    const NetworkLinuxInterface wrapper { &fake.entry, "wztest0" };

    // The link name is the one given, not the address label held by the entry.
    EXPECT_EQ("wztest0", wrapper.name());
    EXPECT_EQ("", wrapper.adapter());
    EXPECT_EQ(AF_INET, wrapper.family());
    EXPECT_EQ("10.77.0.2", wrapper.address());
    EXPECT_EQ("255.255.255.0", wrapper.netmask());
    EXPECT_EQ("10.77.0.255", wrapper.broadcast());
    EXPECT_EQ("", wrapper.metricsV6());
}

TEST_F(SysInfoNetworkLinuxTest, Test_WrapperDerivesBroadcastFromMask)
{
    FakeAddressEntry fake { "wztest0" };
    fake.setIPv4("10.77.1.5", "255.255.0.0");

    EXPECT_EQ("10.77.255.255", NetworkLinuxInterface(&fake.entry, "wztest0").broadcast());
}

TEST_F(SysInfoNetworkLinuxTest, Test_WrapperBroadcastUnknownWithoutMask)
{
    FakeAddressEntry fake { "wztest0" };
    fake.setIPv4("10.77.1.5", "255.255.0.0");
    fake.entry.ifa_netmask = nullptr;

    EXPECT_EQ(" ", NetworkLinuxInterface(&fake.entry, "wztest0").broadcast());
}

TEST_F(SysInfoNetworkLinuxTest, Test_WrapperReadsIPv6Entry)
{
    FakeAddressEntry fake { "wztest0" };
    fake.setIPv6("fd77::2", "ffff:ffff:ffff:ffff::", "fd77::ffff");
    const NetworkLinuxInterface wrapper { &fake.entry, "wztest0" };

    EXPECT_EQ(AF_INET6, wrapper.family());
    EXPECT_EQ("fd77::2", wrapper.addressV6());
    EXPECT_EQ("ffff:ffff:ffff:ffff::", wrapper.netmaskV6());
    EXPECT_EQ("fd77::ffff", wrapper.broadcastV6());
}

TEST_F(SysInfoNetworkLinuxTest, Test_WrapperIPv6WithoutBroadcast)
{
    FakeAddressEntry fake { "wztest0" };
    fake.setIPv6("fd77::2", "ffff:ffff:ffff:ffff::");

    EXPECT_EQ("", NetworkLinuxInterface(&fake.entry, "wztest0").broadcastV6());
}

TEST_F(SysInfoNetworkLinuxTest, Test_WrapperEntryWithoutAddresses)
{
    FakeAddressEntry fake { "wztest0" };
    const NetworkLinuxInterface wrapper { &fake.entry, "wztest0" };

    EXPECT_EQ(AF_PACKET, wrapper.family());
    EXPECT_EQ("", wrapper.address());
    EXPECT_EQ("", wrapper.netmask());
    EXPECT_EQ("", wrapper.addressV6());
    EXPECT_EQ("", wrapper.netmaskV6());
    EXPECT_EQ("", wrapper.broadcastV6());
}

TEST_F(SysInfoNetworkLinuxTest, Test_WrapperLinkWithoutSystemData)
{
    FakeAddressEntry fake { "wztest0" };
    fake.setIPv4("10.77.0.2", "255.255.255.0");
    const NetworkLinuxInterface wrapper { &fake.entry, "wztest0" };

    // A link the system does not list has no route, counters or sysfs attributes.
    EXPECT_EQ(" ", wrapper.gateway());
    EXPECT_EQ(" ", wrapper.gatewayV6());
    EXPECT_EQ("", wrapper.metrics());
    EXPECT_EQ(0u, wrapper.mtu());
    EXPECT_EQ(" ", wrapper.type());
    EXPECT_EQ(" ", wrapper.state());
    EXPECT_EQ(" ", wrapper.MAC());

    const auto stats { wrapper.stats() };
    EXPECT_EQ(0u, stats.rxBytes);
    EXPECT_EQ(0u, stats.txBytes);
    EXPECT_EQ(0u, stats.rxPackets);
    EXPECT_EQ(0u, stats.txPackets);
    EXPECT_EQ(0u, stats.rxErrors);
    EXPECT_EQ(0u, stats.txErrors);
    EXPECT_EQ(0u, stats.rxDropped);
    EXPECT_EQ(0u, stats.txDropped);
}

TEST_F(SysInfoNetworkLinuxTest, Test_WrapperReadsLoopbackAttributes)
{
    if (!std::filesystem::exists("/sys/class/net/lo/mtu") || !std::filesystem::exists("/proc/net/dev"))
    {
        GTEST_SKIP() << "Loopback attributes are not exposed by this system";
    }

    FakeAddressEntry fake { "lo" };
    fake.setIPv4("127.0.0.1", "255.0.0.0");
    const NetworkLinuxInterface wrapper { &fake.entry, "lo" };

    EXPECT_GT(wrapper.mtu(), 0u);
    EXPECT_EQ("00:00:00:00:00:00", wrapper.MAC());
    EXPECT_NE(" ", wrapper.state());
    EXPECT_NO_THROW(wrapper.type());
    // The loopback interface is always listed in /proc/net/dev; reading it must not throw.
    EXPECT_NO_THROW(wrapper.stats());
}
