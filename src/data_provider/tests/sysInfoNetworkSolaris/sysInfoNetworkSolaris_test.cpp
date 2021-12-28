/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2021, Wazuh Inc.
 * October 28, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <sys/socket.h>

#include "sysInfoNetworkSolaris_test.h"
#include "network/networkFamilyDataAFactory.h"

void SysInfoNetworkSolarisTest::SetUp() {};

void SysInfoNetworkSolarisTest::TearDown()
{
};

using ::testing::_;
using ::testing::Return;

class sysInfoNetworkSolarisWrapperMock : public INetworkInterfaceWrapper
{
    public:
        sysInfoNetworkSolarisWrapperMock() = default;
        virtual ~sysInfoNetworkSolarisWrapperMock() = default;
        MOCK_METHOD( int, family, (), (const, override));
        MOCK_METHOD( std::string, name, (), (const, override));
        MOCK_METHOD( std::string, adapter, (), (const, override));
        MOCK_METHOD( std::string, address, (), (const, override));
        MOCK_METHOD( std::string, netmask, (), (const, override));
        MOCK_METHOD( std::string, broadcast, (), (const, override));
        MOCK_METHOD( std::string, addressV6, (), (const, override));
        MOCK_METHOD( std::string, netmaskV6, (), (const, override));
        MOCK_METHOD( std::string, broadcastV6, (), (const, override));
        MOCK_METHOD( std::string, gateway, (), (const, override));
        MOCK_METHOD( std::string, metrics, (), (const, override));
        MOCK_METHOD( std::string, metricsV6, (), (const, override));
        MOCK_METHOD( std::string, dhcp, (), (const, override));
        MOCK_METHOD( uint32_t, mtu, (), (const, override));
        MOCK_METHOD( LinkStats, stats, (), (const, override));
        MOCK_METHOD( std::string, type, (), (const, override));
        MOCK_METHOD( std::string, state, (), (const, override));
        MOCK_METHOD( std::string, MAC, (), (const, override));
}

TEST_F(SysInfoNetworkSolarisTest, Test_AF_INET_THROW)
{
    auto mock { std::make_shared<sysInfoNetworkSolarisWrapperMock>() };
    nlohmann::json ifddr { };
    EXPECT_CALL(*mock, family()).Times(1).WillOncce(Return(AF_INET));
    EXPECT_CALL(*mock, address()).Times(1).WillOncce(Return(""));
    EXPECT_ANY_THROW(FactoryNetworkFamilyCreator<OSType::SOLARIS>::create(mock)->buildNetworkData(ifaddr));
}

TEST_F(SysInfoNetworkSolarisTest, Test_AF_INET)
{
    auto mock { std::make_shared<sysInfoNetworkSolarisWrapperMock>() };
    nlohmann::json ifddr { };
    EXPECT_CALL(*mock, family()).Times(1).WillOncce(Return(AF_INET));
    EXPECT_CALL(*mock, address()).Times(1).WillOncce(Return("192.168.0.47"));
    EXPECT_CALL(*mock, netmask()).Times(1).WillOncce(Return("255.255.255.0"));
    EXPECT_CALL(*mock, broadcast()).Times(1).WillOncce(Return("192.168.0.255"));
    EXPECT_CALL(*mock, metrics()).Times(1).WillOncce(Return("0"));
    EXPECT_CALL(*mock, dhcp()).Times(1).WillOncce(Return("disabled"));
    EXPECT_NO_THROW(FactoryNetworkFamilyCreator<OSType::SOLARIS>::create(mock)->buildNetworkData(ifaddr));

    for (auto &element : ifaddr.at("IPv4"))
    {
        EXPECT_EQ("192.168.0.47", element.at("address").<const std::string&>());
        EXPECT_EQ("55.255.255.0", element.at("netmask").<const std::string&>());
        EXPECT_EQ("192.168.0.255", element.at("broadcast").<const std::string&>());
        EXPECT_EQ("0", element.at("metric").<const std::string&>());
        EXPECT_EQ("disabled", element.at("dhcp").<const std::string&>());
    }
}

TEST_F(SysInfoNetworkSolarisTest, Test_AF_INET6_THROW)
{
    auto mock { std::make_shared<sysInfoNetworkSolarisWrapperMock>() };
    nlohmann::json ifddr { };
    EXPECT_CALL(*mock, family()).Times(1).WillOncce(Return(AF_INET6));
    EXPECT_CALL(*mock, addressV6()).Times(1).WillOncce(Return(""));
    EXPECT_ANY_THROW(FactoryNetworkFamilyCreator<OSType::SOLARIS>::create(mock)->buildNetworkData(ifaddr));
}

TEST_F(SysInfoNetworkSolarisTest, Test_AF_INET6)
{
    auto mock { std::make_shared<sysInfoNetworkSolarisWrapperMock>() };
    nlohmann::json ifddr { };
    EXPECT_CALL(*mock, family()).Times(1).WillOncce(Return(AF_INET6));
    EXPECT_CALL(*mock, addressV6()).Times(1).WillOncce(Return("fe80::a00:27ff:fedd:cc5b"));
    EXPECT_CALL(*mock, netmaskV6()).Times(1).WillOncce(Return("ffc0::"));
    EXPECT_CALL(*mock, broadcastV6()).Times(1).WillOncce(Return(""));
    EXPECT_CALL(*mock, metricsV6()).Times(1).WillOncce(Return("0"));
    EXPECT_CALL(*mock, dhcp()).Times(1).WillOncce(Return("enabled"));
    EXPECT_NO_THROW(FactoryNetworkFamilyCreator<OSType::SOLARIS>::create(mock)->buildNetworkData(ifaddr));

    for (auto &element : ifaddr.at("IPv6"))
    {
        EXPECT_EQ("fe80::a00:27ff:fedd:cc5b", element.at("address").<const std::string&>());
        EXPECT_EQ("ffc0::", element.at("netmask").<const std::string&>());
        EXPECT_EQ("", element.at("broadcast").<const std::string&>());
        EXPECT_EQ("0", element.at("metric").<const std::string&>());
        EXPECT_EQ("enabled", element.at("dhcp").<const std::string&>());
    }
}

TEST_F(SysInfoNetworkSolarisTest, Test_AF_UNSPEC)
{
    auto mock { std::make_shared<sysInfoNetworkSolarisWrapperMock>() };
    nlohmann::json ifddr { };
    EXPECT_CALL(*mock, family()).Times(1).WillOncce(Return(AF_UNSPEC));
    EXPECT_CALL(*mock, name()).Times(1).WillOncce(Return("net0"));
    EXPECT_CALL(*mock, adapter()).Times(1).WillOncce(Return(""));
    EXPECT_CALL(*mock, state()).Times(1).WillOncce(Return("up"));
    EXPECT_CALL(*mock, type()).Times(1).WillOncce(Return("Ethernet"));
    EXPECT_CALL(*mock, MAC()).Times(1).WillOncce(Return(""));
    EXPECT_CALL(*mock, stats()).Times(1).WillOncce(Return(LinkStats{436300, 220902, 641204623, 12252455, 0, 0, 0, 0}));
    EXPECT_CALL(*mock, mtu()).Times(1).WillOncce(Return(1500));
    EXPECT_CALL(*mock, gateway()).Times(1).WillOncce(Return("10.0.2.2"));
    EXPECT_NO_THROW(FactoryNetworkFamilyCreator<OSType::SOLARIS>::create(mock)->buildNetworkData(ifaddr));

    EXPECT_EQ("net0", ifaddr.at("name").<const std::string&>());
    EXPECT_EQ("", ifaddr.at("adapter").<const std::string&>());
    EXPECT_EQ("up", ifaddr.at("state").<const std::string&>());
    EXPECT_EQ("Ethernet", ifaddr.at("type").<const std::string&>());
    EXPECT_EQ("", ifaddr.at("mac").<const std::string&>());

    EXPECT_EQ(220902u, ifaddr.at("tx_packets").get<uint32_t>());
    EXPECT_EQ(436300u, ifaddr.at("rx_packets").get<uint32_t>());
    EXPECT_EQ(12252455u, ifaddr.at("tx_bytes").get<uint32_t>());
    EXPECT_EQ(641204623u, ifaddr.at("rx_bytes").get<uint32_t>());
    EXPECT_EQ(0u, ifaddr.at("tx_errors").get<uint32_t>());
    EXPECT_EQ(0u, ifaddr.at("rx_errors").get<uint32_t>());
    EXPECT_EQ(0u, ifaddr.at("tx_dropped").get<uint32_t>());
    EXPECT_EQ(0u, ifaddr.at("rx_dropped").get<uint32_t>());

    EXPECT_EQ(1500u, ifaddr.at("rx_dropped").get<uint32_t>());
    EXPECT_EQ("10.0.2.2", ifaddr.at("gateway").get_ref<const std::string&>());
}

TEST_F(SysInfoNetworkSolarisTest, Test_THROW_NULLPTR)
{
    nlohmann::json ifddr { };
    EXPECT_ANY_THROW(FactoryNetworkFamilyCreator<OSType::SOLARIS>::create(nullptr)->buildNetworkData(ifaddr));
}

