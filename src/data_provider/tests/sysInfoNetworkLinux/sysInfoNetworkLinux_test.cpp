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
#include <fstream>
#include <ifaddrs.h>
#include <sstream>
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

static std::string gatewayV6Of(const std::string& routeTable, const std::string& ifName)
{
    const auto gateways { NetworkLinuxInterface::parseGatewaysV6(routeTable) };
    const auto it { gateways.find(ifName) };
    return gateways.end() != it ? it->second : UNKNOWN_VALUE;
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV6_DefaultRoute)
{
    EXPECT_EQ("fe80::1", gatewayV6Of(IPV6_ROUTE_TABLE, "eth0"));
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV6_NoDefaultRoute)
{
    const std::string table
    {
        "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n"
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n"
    };
    EXPECT_EQ(" ", gatewayV6Of(table, "eth0"));
    EXPECT_EQ(" ", gatewayV6Of(table, "lo"));
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV6_OtherInterface)
{
    EXPECT_EQ(" ", gatewayV6Of(IPV6_ROUTE_TABLE, "eth1"));
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV6_GlobalNextHop)
{
    const std::string table
    {
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 20010db8000000000000000000000001 00000400 00000001 00000000 00000003     ens5\n"
    };
    EXPECT_EQ("2001:db8::1", gatewayV6Of(table, "ens5"));
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV6_NoGatewayFlag)
{
    const std::string table
    {
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000001     eth0\n"
    };
    EXPECT_EQ(" ", gatewayV6Of(table, "eth0"));
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV6_SourceSpecificRoute)
{
    const std::string table
    {
        "00000000000000000000000000000000 00 20010db8000000000000000000000000 40 fe800000000000000000000000000002 0000000a 00000001 00000000 00000003       d0\n"
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003       d0\n"
    };
    EXPECT_EQ("fe80::1", gatewayV6Of(table, "d0"));
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV6_OneParseForAllInterfaces)
{
    const std::string table
    {
        "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n"
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n"
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000002 00000400 00000001 00000000 00000003     eth0\n"
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 20010db8000000000000000000000001 00000400 00000001 00000000 00000003     eth1\n"
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000003 00000400 00000001 00000000 00000001     eth2"
    };
    const auto gateways { NetworkLinuxInterface::parseGatewaysV6(table) };

    ASSERT_EQ(2u, gateways.size());
    EXPECT_EQ("fe80::1", gateways.at("eth0"));
    EXPECT_EQ("2001:db8::1", gateways.at("eth1"));
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
    EXPECT_NO_THROW(gatewayV6Of(table, "eth0"));
    EXPECT_EQ(" ", gatewayV6Of(table, "eth0"));
    EXPECT_EQ(" ", gatewayV6Of("", "eth0"));

    // A destination longer than 32 zeros is not ::, even if the rest of the line is a valid gateway route.
    const std::string longDestination
    {
        "000000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n"
    };
    EXPECT_EQ(" ", gatewayV6Of(longDestination, "eth0"));
    // The destination ends at a tab as well as at a space.
    EXPECT_EQ("fe80::1", gatewayV6Of("00000000000000000000000000000000\t00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n", "eth0"));
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
    // A value outside the table leaves the answer to the runtime check.
    EXPECT_EQ("unknown", NetworkLinuxInterface::getRedHatDHCPStatus({ "BOOTPROTO", "something-else" }));
    EXPECT_EQ("unknown", NetworkLinuxInterface::getRedHatDHCPStatus({ "BOOTPROTO", "'dhcp" }));
    EXPECT_EQ("unknown", NetworkLinuxInterface::getRedHatDHCPStatus({ "BOOTPROTO", "" }));
    EXPECT_EQ("unknown", NetworkLinuxInterface::getRedHatDHCPStatus({ "BOOTPROTO", "\"\"" }));
}

TEST_F(SysInfoNetworkLinuxTest, Test_RedHatDhcpStatusIgnoresCase)
{
    EXPECT_EQ("disabled", NetworkLinuxInterface::getRedHatDHCPStatus({ "BOOTPROTO", "NONE" }));
    EXPECT_EQ("disabled", NetworkLinuxInterface::getRedHatDHCPStatus({ "BOOTPROTO", "Static" }));
    EXPECT_EQ("enabled", NetworkLinuxInterface::getRedHatDHCPStatus({ "BOOTPROTO", "'DHCP'" }));
    EXPECT_EQ("enabled", NetworkLinuxInterface::getRedHatDHCPStatus({ "DHCPV6C", "Yes" }));
}

TEST_F(SysInfoNetworkLinuxTest, Test_RedHatDhcpStatusSuseValues)
{
    EXPECT_EQ("enabled", NetworkLinuxInterface::getRedHatDHCPStatus({ "BOOTPROTO", "'dhcp4'" }));
    EXPECT_EQ("enabled", NetworkLinuxInterface::getRedHatDHCPStatus({ "BOOTPROTO", "dhcp+autoip" }));
}

TEST_F(SysInfoNetworkLinuxTest, Test_RedHatDhcpStatusBooleanSpellings)
{
    const std::vector<std::string> truthy { "1", "true", "y", "t", "TRUE" };
    const std::vector<std::string> falsy { "0", "false", "n", "f", "No" };

    for (const auto& value : truthy)
    {
        EXPECT_EQ("enabled", NetworkLinuxInterface::getRedHatDHCPStatus({ "DHCPV6C", value })) << value;
    }

    for (const auto& value : falsy)
    {
        EXPECT_EQ("disabled", NetworkLinuxInterface::getRedHatDHCPStatus({ "DHCPV6C", value })) << value;
    }
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

        sockaddr_in netmask {};

        FakeIPv4Entry(const std::string& ifName, const char* ipv4, const unsigned int prefixLength = 24)
            : name{ ifName }
        {
            address.sin_family = AF_INET;
            inet_pton(AF_INET, ipv4, &address.sin_addr);
            netmask.sin_family = AF_INET;
            netmask.sin_addr.s_addr = prefixLength ? htonl(~0u << (32 - prefixLength)) : 0;
            entry.ifa_name = const_cast<char*>(name.c_str());
            entry.ifa_addr = reinterpret_cast<sockaddr*>(&address);
            entry.ifa_netmask = reinterpret_cast<sockaddr*>(&netmask);
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
        { { "wztest0", "10.77.0.2", 24 }, 0 },
        { { "wztest0", "10.77.0.3", 24 }, IFA_F_PERMANENT },
    };
    const auto flags { std::make_shared<const IPv4AddressFlags>(addressFlags) };

    EXPECT_EQ("enabled", NetworkLinuxInterface(&leased.entry, "wztest0", flags, nullptr).dhcp());
    EXPECT_EQ("unknown", NetworkLinuxInterface(&fixed.entry, "wztest0", flags, nullptr).dhcp());
    // Not in the dump, or no dump at all.
    EXPECT_EQ("unknown", NetworkLinuxInterface(&other.entry, "wztest0", flags, nullptr).dhcp());
    EXPECT_EQ("unknown", NetworkLinuxInterface(&leased.entry, "wztest0", nullptr, nullptr).dhcp());
    // The flags belong to the link, not to the label.
    EXPECT_EQ("unknown", NetworkLinuxInterface(&leased.entry, "wztest1", flags, nullptr).dhcp());
}

TEST_F(SysInfoNetworkLinuxTest, Test_DhcpTellsTheSameAddressApartByPrefix)
{
    // One link can hold the same address twice: a permanent /32 and a /24 lease.
    FakeIPv4Entry vip { "wztest0", "10.77.0.5", 32 };
    FakeIPv4Entry leased { "wztest0", "10.77.0.5", 24 };
    const auto flags
    {
        std::make_shared<const IPv4AddressFlags>(IPv4AddressFlags
        {
            { { "wztest0", "10.77.0.5", 32 }, IFA_F_PERMANENT },
            { { "wztest0", "10.77.0.5", 24 }, 0 },
        })
    };

    EXPECT_EQ("unknown", NetworkLinuxInterface(&vip.entry, "wztest0", flags, nullptr).dhcp());
    EXPECT_EQ("enabled", NetworkLinuxInterface(&leased.entry, "wztest0", flags, nullptr).dhcp());
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
    EXPECT_THROW(NetworkLinuxInterface(nullptr, "wztest0", nullptr, nullptr), std::runtime_error);
}

TEST_F(SysInfoNetworkLinuxTest, Test_WrapperReadsIPv4Entry)
{
    FakeAddressEntry fake { "wztest0:lease" };
    fake.setIPv4("10.77.0.2", "255.255.255.0", "10.77.0.255");
    const NetworkLinuxInterface wrapper { &fake.entry, "wztest0", nullptr, nullptr };

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

    EXPECT_EQ("10.77.255.255", NetworkLinuxInterface(&fake.entry, "wztest0", nullptr, nullptr).broadcast());
}

TEST_F(SysInfoNetworkLinuxTest, Test_WrapperBroadcastUnknownWithoutMask)
{
    FakeAddressEntry fake { "wztest0" };
    fake.setIPv4("10.77.1.5", "255.255.0.0");
    fake.entry.ifa_netmask = nullptr;

    EXPECT_EQ(" ", NetworkLinuxInterface(&fake.entry, "wztest0", nullptr, nullptr).broadcast());
}

TEST_F(SysInfoNetworkLinuxTest, Test_WrapperReadsIPv6Entry)
{
    FakeAddressEntry fake { "wztest0" };
    fake.setIPv6("fd77::2", "ffff:ffff:ffff:ffff::", "fd77::ffff");
    const NetworkLinuxInterface wrapper { &fake.entry, "wztest0", nullptr, nullptr };

    EXPECT_EQ(AF_INET6, wrapper.family());
    EXPECT_EQ("fd77::2", wrapper.addressV6());
    EXPECT_EQ("ffff:ffff:ffff:ffff::", wrapper.netmaskV6());
    EXPECT_EQ("fd77::ffff", wrapper.broadcastV6());
}

TEST_F(SysInfoNetworkLinuxTest, Test_WrapperIPv6WithoutBroadcast)
{
    FakeAddressEntry fake { "wztest0" };
    fake.setIPv6("fd77::2", "ffff:ffff:ffff:ffff::");

    EXPECT_EQ("", NetworkLinuxInterface(&fake.entry, "wztest0", nullptr, nullptr).broadcastV6());
}

TEST_F(SysInfoNetworkLinuxTest, Test_WrapperEntryWithoutAddresses)
{
    FakeAddressEntry fake { "wztest0" };
    const NetworkLinuxInterface wrapper { &fake.entry, "wztest0", nullptr, nullptr };

    EXPECT_EQ(AF_PACKET, wrapper.family());
    EXPECT_EQ("", wrapper.address());
    EXPECT_EQ("", wrapper.netmask());
    EXPECT_EQ("", wrapper.addressV6());
    EXPECT_EQ("", wrapper.netmaskV6());
    EXPECT_EQ("", wrapper.broadcastV6());
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV6_WrapperAnswersFromSharedMap)
{
    const auto gateways { std::make_shared<const IPv6Gateways>(IPv6Gateways { { "wztest0", "fe80::1" }, { "wztest1", "fe80::2" } }) };
    FakeAddressEntry first { "wztest0" };
    FakeAddressEntry second { "wztest1" };
    FakeAddressEntry third { "wztest2" };

    EXPECT_EQ("fe80::1", NetworkLinuxInterface(&first.entry, "wztest0", nullptr, nullptr, gateways).gatewayV6());
    EXPECT_EQ("fe80::2", NetworkLinuxInterface(&second.entry, "wztest1", nullptr, nullptr, gateways).gatewayV6());
    EXPECT_EQ(UNKNOWN_VALUE, NetworkLinuxInterface(&third.entry, "wztest2", nullptr, nullptr, gateways).gatewayV6());
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV6_WrapperWithSharedMapDoesNotReadTable)
{
    // A link with a ::/0 route on this host: only a read of the table could report its gateway.
    const auto hostGateways { NetworkLinuxInterface::parseGatewaysV6(Utils::getFileContent(std::string(WM_SYS_NET_DIR) + "ipv6_route")) };

    if (hostGateways.empty())
    {
        GTEST_SKIP() << "This host has no IPv6 default route";
    }

    const auto& ifName { hostGateways.begin()->first };
    FakeAddressEntry fake { ifName };

    EXPECT_EQ(hostGateways.begin()->second, NetworkLinuxInterface(&fake.entry, ifName, nullptr, nullptr).gatewayV6());
    EXPECT_EQ(UNKNOWN_VALUE, NetworkLinuxInterface(&fake.entry, ifName, nullptr, nullptr, std::make_shared<const IPv6Gateways>()).gatewayV6());
}

TEST_F(SysInfoNetworkLinuxTest, Test_LoadGatewaysV6_UsesTheNetlinkDump)
{
    const IPv6Gateways dumped { { "wztest0", "fe80::1" } };

    EXPECT_EQ(dumped, NetworkLinuxInterface::loadGatewaysV6([&dumped]
    {
        return dumped;
    }));
}

TEST_F(SysInfoNetworkLinuxTest, Test_LoadGatewaysV6_FallsBackToTheProcTableWhenTheDumpFails)
{
    const auto procGateways { NetworkLinuxInterface::parseGatewaysV6(Utils::getFileContent(std::string(WM_SYS_NET_DIR) + "ipv6_route")) };

    EXPECT_EQ(procGateways, NetworkLinuxInterface::loadGatewaysV6([]() -> IPv6Gateways
    {
        throw std::runtime_error { "Cannot open netlink socket" };
    }));
}

TEST_F(SysInfoNetworkLinuxTest, Test_LoadGatewaysV6_NetlinkDumpMatchesTheProcTable)
{
    const auto procPath { std::string(WM_SYS_NET_DIR) + "ipv6_route" };
    IPv6Gateways procGateways;
    IPv6Gateways dumpGateways;

    // A second read absorbs a route that changed between the two reads.
    for (auto attempt { 0 }; attempt < 2 && (0 == attempt || procGateways != dumpGateways); ++attempt)
    {
        try
        {
            // The dump reports every member of a nexthop group and /proc only the first: an intended difference.
            if (NetworkLinuxAddressResolver::usesNexthopObjects(NetworkLinuxAddressResolver::dumpIPv6Routes()))
            {
                GTEST_SKIP() << "This host routes its default through nexthop objects";
            }

            dumpGateways = NetworkLinuxAddressResolver::dumpIPv6DefaultGateways();
        }
        catch (const std::exception& error)
        {
            GTEST_SKIP() << "The netlink dump is not available: " << error.what();
        }

        procGateways = NetworkLinuxInterface::parseGatewaysV6(Utils::getFileContent(procPath));
    }

    EXPECT_EQ(procGateways, dumpGateways);
}

TEST_F(SysInfoNetworkLinuxTest, Test_WrapperLinkWithoutSystemData)
{
    FakeAddressEntry fake { "wztest0" };
    fake.setIPv4("10.77.0.2", "255.255.255.0");
    const NetworkLinuxInterface wrapper { &fake.entry, "wztest0", nullptr, nullptr };

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
    const NetworkLinuxInterface wrapper { &fake.entry, "lo", nullptr, nullptr };

    EXPECT_GT(wrapper.mtu(), 0u);
    EXPECT_EQ("00:00:00:00:00:00", wrapper.MAC());
    EXPECT_NE(" ", wrapper.state());
    EXPECT_NO_THROW(wrapper.type());
    // The loopback interface is always listed in /proc/net/dev; reading it must not throw.
    EXPECT_NO_THROW(wrapper.stats());
}

namespace
{
    // One /proc/net/route row, padded to 127 columns like the kernel prints it.
    std::string routeRow(const std::string& iface, const std::string& destination, const std::string& gateway, const std::string& metric)
    {
        auto row { iface + "\t" + destination + "\t" + gateway + "\t0003\t0\t0\t" + metric + "\t00000000\t0\t0\t0" };
        row.resize(127, ' ');
        return row + "\n";
    }

    const std::string ROUTE_HEADER
    {
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT                                                       \n"
    };

    IPv4Gateways parseTable(const std::string& table)
    {
        std::istringstream stream { table };
        return NetworkLinuxInterface::parseGatewaysV4(stream);
    }

    // The per-interface parse the wrapper constructor ran before the table was shared, with stoul so it also runs on 32-bit.
    IPv4Gateway parsePerInterface(const std::string& table, const std::string& ifName)
    {
        IPv4Gateway retVal;

        for (auto& line : Utils::split(table, '\n'))
        {
            line = Utils::rightTrim(line);
            Utils::replaceAll(line, "\t", " ");
            line = Utils::trimRepeated(line, ' ');
            const auto fields { Utils::split(line, ' ') };

            if (GatewayFileFields::Size == fields.size() &&
                    fields.at(GatewayFileFields::Iface).compare(ifName) == 0)
            {
                auto address { static_cast<uint32_t>(std::stoul(fields.at(GatewayFileFields::Gateway), 0, 16)) };
                retVal.metric = fields.at(GatewayFileFields::Metric);

                if (address)
                {
                    retVal.gateway = Utils::NetworkHelper::IAddressToBinary(AF_INET, reinterpret_cast<in_addr*>(&address));
                    break;
                }
            }
        }

        return retVal;
    }
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV4_FirstGatewayRowWins)
{
    const auto gateways { parseTable(ROUTE_HEADER +
                                     routeRow("eth0", "00000000", "010011AC", "100") +
                                     routeRow("eth0", "0000000A", "020011AC", "200")) };

    EXPECT_EQ("172.17.0.1", gateways.at("eth0").gateway);
    EXPECT_EQ("100", gateways.at("eth0").metric);
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV4_MetricOfLastRowWithoutGateway)
{
    const auto gateways { parseTable(ROUTE_HEADER +
                                     routeRow("eth0", "000011AC", "00000000", "100") +
                                     routeRow("eth0", "000012AC", "00000000", "200")) };

    EXPECT_EQ(" ", gateways.at("eth0").gateway);
    EXPECT_EQ("200", gateways.at("eth0").metric);
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV4_GatewayRowSetsItsMetric)
{
    const auto gateways { parseTable(ROUTE_HEADER +
                                     routeRow("eth0", "000011AC", "00000000", "0") +
                                     routeRow("eth0", "00000000", "010011AC", "100") +
                                     routeRow("eth0", "000012AC", "00000000", "200")) };

    EXPECT_EQ("172.17.0.1", gateways.at("eth0").gateway);
    EXPECT_EQ("100", gateways.at("eth0").metric);
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV4_OneParseForAllInterfaces)
{
    const auto gateways { parseTable(ROUTE_HEADER +
                                     routeRow("eth0", "00000000", "010011AC", "100") +
                                     routeRow("eth1", "0000A8C0", "00000000", "0") +
                                     routeRow("eth1", "00000000", "0101A8C0", "600") +
                                     routeRow("*", "0000000B", "00000000", "0") +
                                     routeRow("dum0", "0100000B", "00000000", "0")) };

    ASSERT_EQ(4u, gateways.size());
    EXPECT_EQ("172.17.0.1", gateways.at("eth0").gateway);
    EXPECT_EQ("192.168.1.1", gateways.at("eth1").gateway);
    EXPECT_EQ("600", gateways.at("eth1").metric);
    EXPECT_EQ(" ", gateways.at("*").gateway);
    EXPECT_EQ(" ", gateways.at("dum0").gateway);
    EXPECT_EQ("0", gateways.at("dum0").metric);
    EXPECT_EQ(0u, gateways.count("lo"));
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV4_SkipsHeaderAndMalformedLines)
{
    const std::string table
    {
        ROUTE_HEADER +
        "\n" +
        "eth0\t00000000\t010011AC\t0003\n" +
        "eth0\t00000000\tZZ0011AC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
        "eth0\t00000000\t1010011AC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
        "eth0\t00000000\t010011AC\t0003\t0\t0\t100\t00000000\t0\t0\t0\textra\n" +
        "eth1 00000000  0101A8C0 0003 0 0 50 00000000 0 0 0\r\n"
    };

    IPv4Gateways gateways;
    ASSERT_NO_THROW(gateways = parseTable(table));

    EXPECT_EQ(1u, gateways.size());
    EXPECT_EQ("192.168.1.1", gateways.at("eth1").gateway);
    EXPECT_EQ("50", gateways.at("eth1").metric);
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV4_HighLastOctet)
{
    // Larger than a 32-bit long can hold, which made 32-bit agents fail the whole listing.
    const auto gateways { parseTable(ROUTE_HEADER + routeRow("eth0", "00000000", "FE00000A", "0")) };

    EXPECT_EQ("10.0.0.254", gateways.at("eth0").gateway);
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV4_EmptyInput)
{
    EXPECT_TRUE(parseTable("").empty());
    EXPECT_TRUE(parseTable(ROUTE_HEADER).empty());
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV4_MatchesPerInterfaceParse)
{
    std::vector<std::string> tables
    {
        ROUTE_HEADER +
        routeRow("eth0", "000011AC", "00000000", "0") +
        routeRow("eth0", "00000000", "010011AC", "100") +
        routeRow("eth1", "0000A8C0", "00000000", "5") +
        routeRow("eth1", "0001A8C0", "00000000", "7") +
        routeRow("eth2", "00000000", "0102A8C0", "1") +
        routeRow("eth2", "00000000", "0202A8C0", "2") +
        routeRow("eth0", "0000000A", "020011AC", "300")
    };

    std::ifstream hostTable { "/proc/net/route" };

    if (hostTable.is_open())
    {
        tables.emplace_back(std::string { std::istreambuf_iterator<char> { hostTable }, std::istreambuf_iterator<char> {} });
    }

    const std::vector<std::string> names { "eth0", "eth1", "eth2", "eth3", "lo", "wztest0" };

    for (const auto& table : tables)
    {
        const auto gateways { parseTable(table) };

        for (const auto& name : names)
        {
            const auto expected { parsePerInterface(table, name) };
            const auto it { gateways.find(name) };
            const auto actual { gateways.end() != it ? it->second : IPv4Gateway {} };

            EXPECT_EQ(expected.gateway, actual.gateway) << name;
            EXPECT_EQ(expected.metric, actual.metric) << name;
        }

        for (const auto& entry : gateways)
        {
            const auto expected { parsePerInterface(table, entry.first) };

            EXPECT_EQ(expected.gateway, entry.second.gateway) << entry.first;
            EXPECT_EQ(expected.metric, entry.second.metric) << entry.first;
        }
    }
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV4_WrapperAnswersFromSharedMap)
{
    FakeAddressEntry fake { "wztest0" };
    fake.setIPv4("10.77.0.2", "255.255.255.0");
    const auto gateways { std::make_shared<const IPv4Gateways>(IPv4Gateways { { "wztest0", { "10.77.0.1", "100" } } }) };
    const NetworkLinuxInterface wrapper { &fake.entry, "wztest0", nullptr, gateways };

    EXPECT_EQ("10.77.0.1", wrapper.gateway());
    EXPECT_EQ("100", wrapper.metrics());
}

TEST_F(SysInfoNetworkLinuxTest, Test_GatewayV4_WrapperWithoutRouteIsUnknown)
{
    FakeAddressEntry fake { "wztest0" };
    const auto otherInterface { std::make_shared<const IPv4Gateways>(IPv4Gateways { { "wztest1", { "10.77.0.1", "100" } } }) };

    // Without the map, with an empty one, or with only other interfaces in it, the entry has no IPv4 route.
    const std::vector<std::shared_ptr<const IPv4Gateways>> maps { nullptr, std::make_shared<const IPv4Gateways>(), otherInterface };

    for (const auto& gateways : maps)
    {
        const NetworkLinuxInterface wrapper { &fake.entry, "wztest0", nullptr, gateways };

        EXPECT_EQ(" ", wrapper.gateway());
        EXPECT_EQ("", wrapper.metrics());
    }
}
