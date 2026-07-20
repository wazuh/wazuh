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
#include <ifaddrs.h>
#include "sysInfoNetworkLinux_test.h"
#include "network/networkInterfaceLinux.h"
#include "network/networkFamilyDataAFactory.h"

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
        MOCK_METHOD(std::string, metrics, (), (const override));
        MOCK_METHOD(std::string, metricsV6, (), (const override));
        MOCK_METHOD(uint32_t, dhcp, (), (const override));
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
    EXPECT_CALL(*mock, dhcp()).Times(1).WillOnce(Return(1));
    EXPECT_CALL(*mock, metrics()).Times(1).WillOnce(Return("100"));
    EXPECT_NO_THROW(FactoryNetworkFamilyCreator<OSPlatformType::LINUX>::create(mock)->buildNetworkData(ifaddr));

    for (auto& element : ifaddr.at("IPv4"))
    {
        EXPECT_EQ("192.168.0.1", element.at("network_ip").get_ref<const std::string&>());
        EXPECT_EQ("255.255.255.0", element.at("network_netmask").get_ref<const std::string&>());
        EXPECT_EQ("192.168.0.255", element.at("network_broadcast").get_ref<const std::string&>());
        EXPECT_EQ(1, element.at("network_dhcp").get<uint32_t>());
        EXPECT_EQ("100", element.at("network_metric").get_ref<const std::string&>());
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
    EXPECT_CALL(*mock, dhcp()).Times(1).WillOnce(Return(1));
    EXPECT_CALL(*mock, metricsV6()).Times(1).WillOnce(Return("100"));
    EXPECT_NO_THROW(FactoryNetworkFamilyCreator<OSPlatformType::LINUX>::create(mock)->buildNetworkData(ifaddr));

    for (auto& element : ifaddr.at("IPv6"))
    {
        EXPECT_EQ("2001:db8:85a3:8d3:1319:8a2e:370:7348", element.at("network_ip").get_ref<const std::string&>());
        EXPECT_EQ("2001:db8:abcd:0012:ffff:ffff:ffff:ffff", element.at("network_netmask").get_ref<const std::string&>());
        EXPECT_EQ("2001:db8:85a3:8d3:1319:8a2e:370:0000", element.at("network_broadcast").get_ref<const std::string&>());
        EXPECT_EQ(1, element.at("network_dhcp").get<uint32_t>());
        EXPECT_EQ("100", element.at("network_metric").get_ref<const std::string&>());
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

    EXPECT_NO_THROW(FactoryNetworkFamilyCreator<OSPlatformType::LINUX>::create(mock)->buildNetworkData(ifaddr));

    EXPECT_EQ("eth01", ifaddr.at("interface_name").get_ref<const std::string&>());
    EXPECT_EQ("adapter", ifaddr.at("interface_alias").get_ref<const std::string&>());
    EXPECT_EQ("ethernet", ifaddr.at("interface_type").get_ref<const std::string&>());
    EXPECT_EQ("up", ifaddr.at("interface_state").get_ref<const std::string&>());
    EXPECT_EQ("00:A0:C9:14:C8:29", ifaddr.at("host_mac").get_ref<const std::string&>());

    EXPECT_EQ(1, ifaddr.at("host_network_egress_packages").get<int32_t>());
    EXPECT_EQ(0, ifaddr.at("host_network_ingress_packages").get<int32_t>());
    EXPECT_EQ(3, ifaddr.at("host_network_egress_bytes").get<int32_t>());
    EXPECT_EQ(2, ifaddr.at("host_network_ingress_bytes").get<int32_t>());
    EXPECT_EQ(5, ifaddr.at("host_network_egress_errors").get<int32_t>());
    EXPECT_EQ(4, ifaddr.at("host_network_ingress_errors").get<int32_t>());
    EXPECT_EQ(7, ifaddr.at("host_network_egress_drops").get<int32_t>());
    EXPECT_EQ(6, ifaddr.at("host_network_ingress_drops").get<int32_t>());

    EXPECT_EQ(1500u, ifaddr.at("interface_mtu").get<uint32_t>());
    EXPECT_EQ("10.2.2.50", ifaddr.at("network_gateway").get_ref<const std::string&>());
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

    EXPECT_NO_THROW(FactoryNetworkFamilyCreator<OSPlatformType::LINUX>::create(mock)->buildNetworkData(ifaddr));

    EXPECT_EQ("eth01", ifaddr.at("interface_name").get_ref<const std::string&>());
    EXPECT_EQ("adapter", ifaddr.at("interface_alias").get_ref<const std::string&>());
    EXPECT_EQ("ethernet", ifaddr.at("interface_type").get_ref<const std::string&>());
    EXPECT_EQ("up", ifaddr.at("interface_state").get_ref<const std::string&>());
    EXPECT_EQ("00:A0:C9:14:C8:29", ifaddr.at("host_mac").get_ref<const std::string&>());

    EXPECT_EQ(1, ifaddr.at("host_network_egress_packages").get<int32_t>());
    EXPECT_EQ(0, ifaddr.at("host_network_ingress_packages").get<int32_t>());
    EXPECT_EQ(3, ifaddr.at("host_network_egress_bytes").get<int32_t>());
    EXPECT_EQ(2, ifaddr.at("host_network_ingress_bytes").get<int32_t>());
    EXPECT_EQ(5, ifaddr.at("host_network_egress_errors").get<int32_t>());
    EXPECT_EQ(4, ifaddr.at("host_network_ingress_errors").get<int32_t>());
    EXPECT_EQ(7, ifaddr.at("host_network_egress_drops").get<int32_t>());
    EXPECT_EQ(6, ifaddr.at("host_network_ingress_drops").get<int32_t>());
    EXPECT_EQ(1500, ifaddr.at("interface_mtu").get<int32_t>());
    EXPECT_EQ("A12BA8C0", ifaddr.at("network_gateway").get_ref<const std::string&>());
}
