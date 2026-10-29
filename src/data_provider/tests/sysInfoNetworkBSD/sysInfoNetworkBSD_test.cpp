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
#include <sys/socket.h>
#include <arpa/inet.h>
#include <vector>
#include "sysInfoNetworkBSD_test.h"
#include "network/networkInterfaceBSD.h"
#include "network/networkBSDWrapper.h"
#include "network/networkFamilyDataAFactory.h"

void SysInfoNetworkBSDTest::SetUp() {};

void SysInfoNetworkBSDTest::TearDown() {};

using ::testing::_;
using ::testing::Return;

class SysInfoNetworkBSDWrapperMock: public INetworkInterfaceWrapper
{
    public:
        SysInfoNetworkBSDWrapperMock() = default;
        virtual ~SysInfoNetworkBSDWrapperMock() = default;
        MOCK_METHOD(int, family, (), (const override));
        MOCK_METHOD(std::string, name, (), (const override));
        MOCK_METHOD(std::string, address, (), (const override));
        MOCK_METHOD(std::string, netmask, (), (const override));
        MOCK_METHOD(std::string, broadcast, (), (const override));
        MOCK_METHOD(std::string, addressV6, (), (const override));
        MOCK_METHOD(std::string, netmaskV6, (), (const override));
        MOCK_METHOD(std::string, broadcastV6, (), (const override));
        MOCK_METHOD(std::string, metrics, (), (const override));
        MOCK_METHOD(std::string, metricsV6, (), (const override));
        MOCK_METHOD(std::string, gateway, (), (const override));
        MOCK_METHOD(std::string, gatewayV6, (), (const override));
        MOCK_METHOD(std::string, dhcp, (), (const override));
        MOCK_METHOD(uint32_t, mtu, (), (const override));
        MOCK_METHOD(LinkStats, stats, (), (const override));
        MOCK_METHOD(std::string, type, (), (const override));
        MOCK_METHOD(std::string, state, (), (const override));
        MOCK_METHOD(std::string, MAC, (), (const override));
        MOCK_METHOD(std::string, adapter, (), (const override));
};

TEST_F(SysInfoNetworkBSDTest, Test_AF_INET_THROW)
{
    auto mock { std::make_shared<SysInfoNetworkBSDWrapperMock>() };
    nlohmann::json ifaddr {};
    EXPECT_CALL(*mock, family()).Times(1).WillOnce(Return(AF_INET));
    EXPECT_CALL(*mock, address()).Times(1).WillOnce(Return(""));
    EXPECT_ANY_THROW(FactoryNetworkFamilyCreator<OSPlatformType::BSDBASED>::create(mock)->buildNetworkData(ifaddr));
}

TEST_F(SysInfoNetworkBSDTest, Test_AF_INET)
{
    auto mock { std::make_shared<SysInfoNetworkBSDWrapperMock>() };
    nlohmann::json ifaddr {};
    EXPECT_CALL(*mock, family()).Times(1).WillOnce(Return(AF_INET));
    EXPECT_CALL(*mock, address()).Times(1).WillOnce(Return("192.168.0.1"));
    EXPECT_CALL(*mock, netmask()).Times(1).WillOnce(Return("255.255.255.0"));
    EXPECT_CALL(*mock, broadcast()).Times(1).WillOnce(Return("192.168.0.255"));
    EXPECT_CALL(*mock, metrics()).Times(1).WillOnce(Return(" "));
    EXPECT_CALL(*mock, dhcp()).Times(1).WillOnce(Return(" "));
    EXPECT_NO_THROW(FactoryNetworkFamilyCreator<OSPlatformType::BSDBASED>::create(mock)->buildNetworkData(ifaddr));

    for (auto& element : ifaddr.at("IPv4"))
    {
        EXPECT_EQ("192.168.0.1", element.at("address").get_ref<const std::string&>());
        EXPECT_EQ("255.255.255.0", element.at("netmask").get_ref<const std::string&>());
        EXPECT_EQ("192.168.0.255", element.at("broadcast").get_ref<const std::string&>());
        EXPECT_EQ(" ", element.at("dhcp").get_ref<const std::string&>());
        EXPECT_EQ(" ", element.at("metric").get_ref<const std::string&>());
    }
}

TEST_F(SysInfoNetworkBSDTest, Test_AF_INET6_THROW)
{
    auto mock { std::make_shared<SysInfoNetworkBSDWrapperMock>() };
    nlohmann::json ifaddr {};
    EXPECT_CALL(*mock, family()).Times(1).WillOnce(Return(AF_INET6));
    EXPECT_CALL(*mock, addressV6()).Times(1).WillOnce(Return(""));
    EXPECT_ANY_THROW(FactoryNetworkFamilyCreator<OSPlatformType::BSDBASED>::create(mock)->buildNetworkData(ifaddr));
}

TEST_F(SysInfoNetworkBSDTest, Test_AF_INET6)
{
    auto mock { std::make_shared<SysInfoNetworkBSDWrapperMock>() };
    nlohmann::json ifaddr {};
    EXPECT_CALL(*mock, family()).Times(1).WillOnce(Return(AF_INET6));
    EXPECT_CALL(*mock, addressV6()).Times(1).WillOnce(Return("2001:db8:85a3:8d3:1319:8a2e:370:7348"));
    EXPECT_CALL(*mock, netmaskV6()).Times(1).WillOnce(Return("2001:db8:abcd:0012:ffff:ffff:ffff:ffff"));
    EXPECT_CALL(*mock, broadcastV6()).Times(1).WillOnce(Return("2001:db8:85a3:8d3:1319:8a2e:370:0000"));
    EXPECT_CALL(*mock, metricsV6()).Times(1).WillOnce(Return(" "));
    EXPECT_CALL(*mock, dhcp()).Times(1).WillOnce(Return(" "));
    EXPECT_NO_THROW(FactoryNetworkFamilyCreator<OSPlatformType::BSDBASED>::create(mock)->buildNetworkData(ifaddr));

    for (auto& element : ifaddr.at("IPv6"))
    {
        EXPECT_EQ("2001:db8:85a3:8d3:1319:8a2e:370:7348", element.at("address").get_ref<const std::string&>());
        EXPECT_EQ("2001:db8:abcd:0012:ffff:ffff:ffff:ffff", element.at("netmask").get_ref<const std::string&>());
        EXPECT_EQ("2001:db8:85a3:8d3:1319:8a2e:370:0000", element.at("broadcast").get_ref<const std::string&>());
        EXPECT_EQ(" ", element.at("dhcp").get_ref<const std::string&>());
        EXPECT_EQ(" ", element.at("metric").get_ref<const std::string&>());
    }
}

TEST_F(SysInfoNetworkBSDTest, Test_AF_LINK)
{
    auto mock { std::make_shared<SysInfoNetworkBSDWrapperMock>() };
    nlohmann::json ifaddr {};
    EXPECT_CALL(*mock, family()).Times(1).WillOnce(Return(AF_LINK));
    EXPECT_CALL(*mock, name()).Times(1).WillOnce(Return("eth01"));
    EXPECT_CALL(*mock, type()).Times(1).WillOnce(Return("ethernet"));
    EXPECT_CALL(*mock, state()).Times(1).WillOnce(Return("up"));
    EXPECT_CALL(*mock, MAC()).Times(1).WillOnce(Return("00:A0:C9:14:C8:29"));
    EXPECT_CALL(*mock, stats()).Times(1).WillOnce(Return(LinkStats{0, 1, 2, 3, 4, 5, 6, 7}));
    EXPECT_CALL(*mock, mtu()).Times(1).WillOnce(Return(1500));
    EXPECT_CALL(*mock, gateway()).Times(1).WillOnce(Return("8.8.4.4"));
    EXPECT_CALL(*mock, gatewayV6()).Times(1).WillOnce(Return("fe80::1"));
    EXPECT_CALL(*mock, adapter()).Times(1).WillOnce(Return(""));

    EXPECT_NO_THROW(FactoryNetworkFamilyCreator<OSPlatformType::BSDBASED>::create(mock)->buildNetworkData(ifaddr));

    EXPECT_EQ("eth01", ifaddr.at("name").get_ref<const std::string&>());
    EXPECT_EQ("ethernet", ifaddr.at("type").get_ref<const std::string&>());
    EXPECT_EQ("up", ifaddr.at("state").get_ref<const std::string&>());
    EXPECT_EQ("00:A0:C9:14:C8:29", ifaddr.at("mac").get_ref<const std::string&>());

    EXPECT_EQ(1, ifaddr.at("tx_packets").get<int32_t>());
    EXPECT_EQ(0, ifaddr.at("rx_packets").get<int32_t>());
    EXPECT_EQ(3, ifaddr.at("tx_bytes").get<int32_t>());
    EXPECT_EQ(2, ifaddr.at("rx_bytes").get<int32_t>());
    EXPECT_EQ(5, ifaddr.at("tx_errors").get<int32_t>());
    EXPECT_EQ(4, ifaddr.at("rx_errors").get<int32_t>());
    EXPECT_EQ(6, ifaddr.at("rx_dropped").get<int32_t>());

    EXPECT_EQ(1500, ifaddr.at("mtu").get<int32_t>());

    EXPECT_EQ("8.8.4.4", ifaddr.at("gateway").get_ref<const std::string&>());

    EXPECT_EQ("fe80::1", ifaddr.at("gateway6").get_ref<const std::string&>());
}

TEST_F(SysInfoNetworkBSDTest, Test_AF_UNSPEC_THROW_NULLPTR)
{
    nlohmann::json ifaddr {};
    EXPECT_ANY_THROW(FactoryNetworkFamilyCreator<OSPlatformType::BSDBASED>::create(nullptr)->buildNetworkData(ifaddr));
}

namespace
{
    // Darwin pads each sockaddr of a routing message to 4 bytes, the other BSDs to sizeof(long)
#ifdef __APPLE__
    constexpr size_t SOCKADDR_ALIGN { 4 };
#else
    constexpr size_t SOCKADDR_ALIGN { sizeof(long) };
#endif

    std::vector<char> sockaddrIn(const char* address)
    {
        sockaddr_in sa {};
        sa.sin_len = sizeof(sa);
        sa.sin_family = AF_INET;
        inet_pton(AF_INET, address, &sa.sin_addr);
        const auto bytes { reinterpret_cast<const char*>(&sa) };
        return std::vector<char>(bytes, bytes + sizeof(sa));
    }

    std::vector<char> sockaddrIn6(const char* address, const uint8_t scope = 0)
    {
        sockaddr_in6 sa {};
        sa.sin6_len = sizeof(sa);
        sa.sin6_family = AF_INET6;
        inet_pton(AF_INET6, address, &sa.sin6_addr);

        // Link-local addresses carry the interface index embedded in bytes 2-3
        if (scope)
        {
            sa.sin6_addr.s6_addr[3] = scope;
        }

        const auto bytes { reinterpret_cast<const char*>(&sa) };
        return std::vector<char>(bytes, bytes + sizeof(sa));
    }

    // A netmask trimmed to its significant bytes, as the kernel sends it
    std::vector<char> netmask(const uint8_t length, const uint8_t family, const std::vector<char>& bytes = {})
    {
        std::vector<char> sa { static_cast<char>(length), static_cast<char>(family) };
        sa.insert(sa.end(), bytes.begin(), bytes.end());
        sa.resize(length);
        return sa;
    }

    void appendRoute(std::vector<char>& table,
                     const unsigned short ifIndex,
                     const int flags,
                     const std::vector<std::vector<char>>& addresses)
    {
        rt_msghdr msg {};
        std::vector<char> body;

        for (const auto& sa : addresses)
        {
            body.insert(body.end(), sa.begin(), sa.end());
            body.resize(body.size() + (sa.empty() ? SOCKADDR_ALIGN : (SOCKADDR_ALIGN - sa.size() % SOCKADDR_ALIGN) % SOCKADDR_ALIGN));
        }

        msg.rtm_msglen = static_cast<unsigned short>(sizeof(msg) + body.size());
        msg.rtm_index = ifIndex;
        msg.rtm_flags = flags;
        msg.rtm_addrs = RTA_DST | RTA_GATEWAY | (addresses.size() > 2 ? RTA_NETMASK : 0);

        const auto header { reinterpret_cast<const char*>(&msg) };
        table.insert(table.end(), header, header + sizeof(msg));
        table.insert(table.end(), body.begin(), body.end());
    }
}

TEST_F(SysInfoNetworkBSDTest, Test_ParseGateway_IPv6Default)
{
    std::vector<char> table;
    appendRoute(table, 4, RTF_UP | RTF_GATEWAY | RTF_HOST, { sockaddrIn6("2001:db8::5"), sockaddrIn6("fe80::1", 4) });
    appendRoute(table, 4, RTF_UP | RTF_GATEWAY | RTF_STATIC, { sockaddrIn6("::"), sockaddrIn6("fe80::1", 4), netmask(0, 0) });

    EXPECT_EQ("fe80::1", NetworkBSDInterface::parseGateway(table.data(), table.size(), 4, AF_INET6));
    EXPECT_EQ("", NetworkBSDInterface::parseGateway(table.data(), table.size(), 4, AF_INET));
}

TEST_F(SysInfoNetworkBSDTest, Test_ParseGateway_IPv6GlobalNextHop)
{
    std::vector<char> table;
    appendRoute(table, 4, RTF_UP | RTF_GATEWAY, { sockaddrIn6("::"), sockaddrIn6("2001:db8::1"), netmask(0, 0) });

    EXPECT_EQ("2001:db8::1", NetworkBSDInterface::parseGateway(table.data(), table.size(), 4, AF_INET6));
}

TEST_F(SysInfoNetworkBSDTest, Test_ParseGateway_IPv4Default)
{
    std::vector<char> table;
    appendRoute(table, 4, RTF_UP | RTF_GATEWAY | RTF_STATIC, { sockaddrIn("0.0.0.0"), sockaddrIn("10.211.55.1"), netmask(0, 0) });
    appendRoute(table, 4, RTF_UP | RTF_GATEWAY, { sockaddrIn6("::"), sockaddrIn6("fe80::1", 4), netmask(0, 0) });

    EXPECT_EQ("10.211.55.1", NetworkBSDInterface::parseGateway(table.data(), table.size(), 4, AF_INET));
    EXPECT_EQ("fe80::1", NetworkBSDInterface::parseGateway(table.data(), table.size(), 4, AF_INET6));
}

TEST_F(SysInfoNetworkBSDTest, Test_ParseGateway_OtherInterface)
{
    std::vector<char> table;
    appendRoute(table, 8, RTF_UP | RTF_GATEWAY, { sockaddrIn6("::"), sockaddrIn6("fe80::1", 8), netmask(0, 0) });

    EXPECT_EQ("", NetworkBSDInterface::parseGateway(table.data(), table.size(), 4, AF_INET6));
    EXPECT_EQ("fe80::1", NetworkBSDInterface::parseGateway(table.data(), table.size(), 8, AF_INET6));
}

TEST_F(SysInfoNetworkBSDTest, Test_ParseGateway_NotDefaultRoute)
{
    std::vector<char> table;
    const auto mask96 { netmask(16, AF_INET6, std::vector<char>(12, '\xff')) };
    // ::/96 reject route via ::1 on lo0, as FreeBSD installs it
    appendRoute(table, 1, RTF_UP | RTF_GATEWAY | RTF_REJECT | RTF_STATIC, { sockaddrIn6("::"), sockaddrIn6("::1"), mask96 });
    // Same destination with a non-zero netmask and no reject flag
    appendRoute(table, 1, RTF_UP | RTF_GATEWAY, { sockaddrIn6("::"), sockaddrIn6("::1"), mask96 });
    // Default route that discards traffic
    appendRoute(table, 1, RTF_UP | RTF_GATEWAY | RTF_BLACKHOLE, { sockaddrIn6("::"), sockaddrIn6("::1"), netmask(0, 0) });
    // Default route without RTF_GATEWAY
    appendRoute(table, 1, RTF_UP, { sockaddrIn6("::"), sockaddrIn6("::1"), netmask(0, 0) });
    // Default route that is not up
    appendRoute(table, 1, RTF_GATEWAY, { sockaddrIn6("::"), sockaddrIn6("::1"), netmask(0, 0) });

    EXPECT_EQ("", NetworkBSDInterface::parseGateway(table.data(), table.size(), 1, AF_INET6));
}

TEST_F(SysInfoNetworkBSDTest, Test_ParseGateway_MalformedInput)
{
    std::vector<char> table;
    appendRoute(table, 4, RTF_UP | RTF_GATEWAY, { sockaddrIn6("::"), sockaddrIn6("fe80::1", 4), netmask(0, 0) });

    // Message longer than the table
    EXPECT_EQ("", NetworkBSDInterface::parseGateway(table.data(), table.size() - 1, 4, AF_INET6));
    // Header only
    EXPECT_EQ("", NetworkBSDInterface::parseGateway(table.data(), sizeof(rt_msghdr) - 1, 4, AF_INET6));
    EXPECT_EQ("", NetworkBSDInterface::parseGateway(table.data(), 0, 4, AF_INET6));

    // Message length too short to hold its header
    auto zeroLength { table };
    reinterpret_cast<rt_msghdr*>(zeroLength.data())->rtm_msglen = 0;
    EXPECT_EQ("", NetworkBSDInterface::parseGateway(zeroLength.data(), zeroLength.size(), 4, AF_INET6));

    // Gateway address cut by the end of the message
    std::vector<char> cut;
    appendRoute(cut, 4, RTF_UP | RTF_GATEWAY, { sockaddrIn6("::"), sockaddrIn6("fe80::1", 4) });
    reinterpret_cast<rt_msghdr*>(cut.data())->rtm_msglen -= 8;
    EXPECT_EQ("", NetworkBSDInterface::parseGateway(cut.data(), cut.size() - 8, 4, AF_INET6));
}
