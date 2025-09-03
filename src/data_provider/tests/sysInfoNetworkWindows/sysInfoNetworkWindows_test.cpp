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

#include "windowsHelper.h"
#include "sysInfoNetworkWindows_test.h"
#include "network/networkInterfaceWindows.h"
#include "network/networkFamilyDataAFactory.h"

void SysInfoNetworkWindowsTest::SetUp() {};

void SysInfoNetworkWindowsTest::TearDown() {};

using ::testing::_;
using ::testing::Return;

class SysInfoNetworkWindowsWrapperMock: public INetworkInterfaceWrapper
{
    public:
        SysInfoNetworkWindowsWrapperMock() = default;
        virtual ~SysInfoNetworkWindowsWrapperMock() = default;
        MOCK_METHOD(int, family, (), (const override));
        MOCK_METHOD(std::string, name, (), (const override));
        MOCK_METHOD(std::string, adapter, (), (const override));
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
};

TEST_F(SysInfoNetworkWindowsTest, Test_IPV4_THROW)
{
    auto mock { std::make_shared<SysInfoNetworkWindowsWrapperMock>() };
    nlohmann::json networkInfo {};
    EXPECT_CALL(*mock, family()).Times(1).WillOnce(Return(Utils::NetworkWindowsHelper::IPV4));
    EXPECT_CALL(*mock, address()).Times(1).WillOnce(Return(""));
    EXPECT_ANY_THROW(FactoryNetworkFamilyCreator<OSPlatformType::WINDOWS>::create(mock)->buildNetworkData(networkInfo));
}

TEST_F(SysInfoNetworkWindowsTest, Test_IPV6_THROW)
{
    auto mock { std::make_shared<SysInfoNetworkWindowsWrapperMock>() };
    nlohmann::json networkInfo {};
    EXPECT_CALL(*mock, family()).Times(1).WillOnce(Return(Utils::NetworkWindowsHelper::IPV6));
    EXPECT_CALL(*mock, addressV6()).Times(1).WillOnce(Return(""));
    EXPECT_ANY_THROW(FactoryNetworkFamilyCreator<OSPlatformType::WINDOWS>::create(mock)->buildNetworkData(networkInfo));
}

TEST_F(SysInfoNetworkWindowsTest, Test_AF_UNSPEC_THROW_NULLPTR)
{
    nlohmann::json networkInfo {};
    EXPECT_ANY_THROW(FactoryNetworkFamilyCreator<OSPlatformType::WINDOWS>::create(nullptr)->buildNetworkData(networkInfo));
}

TEST_F(SysInfoNetworkWindowsTest, Test_IPV4)
{
    auto mock { std::make_shared<SysInfoNetworkWindowsWrapperMock>() };
    nlohmann::json networkInfo {};
    const std::string address   { "192.168.0.1" };
    const std::string netmask   { "255.255.255.0" };
    const std::string broadcast { "192.168.0.255" };
    const uint32_t dhcp         { 1 };
    const std::string metrics   { "25" };
    EXPECT_CALL(*mock, family()).Times(1).WillOnce(Return(Utils::NetworkWindowsHelper::IPV4));
    EXPECT_CALL(*mock, address()).Times(1).WillOnce(Return(address));
    EXPECT_CALL(*mock, netmask()).Times(1).WillOnce(Return(netmask));
    EXPECT_CALL(*mock, broadcast()).Times(1).WillOnce(Return(broadcast));
    EXPECT_CALL(*mock, dhcp()).Times(1).WillOnce(Return(dhcp));
    EXPECT_CALL(*mock, metrics()).Times(1).WillOnce(Return(metrics));
    EXPECT_NO_THROW(FactoryNetworkFamilyCreator<OSPlatformType::WINDOWS>::create(mock)->buildNetworkData(networkInfo));

    for (auto& element : networkInfo.at("IPv4"))
    {
        EXPECT_EQ(address, element.at("network_ip").get_ref<const std::string&>());
        EXPECT_EQ(netmask, element.at("network_netmask").get_ref<const std::string&>());
        EXPECT_EQ(broadcast, element.at("network_broadcast").get_ref<const std::string&>());
        EXPECT_EQ(dhcp, element.at("network_dhcp").get<uint32_t>());
        EXPECT_EQ(metrics, element.at("network_metric").get_ref<const std::string&>());
    }
}

TEST_F(SysInfoNetworkWindowsTest, Test_IPV6)
{
    auto mock { std::make_shared<SysInfoNetworkWindowsWrapperMock>() };
    nlohmann::json networkInfo {};
    const std::string address   { "2001:db8:85a3:8d3:1319:8a2e:370:7348" };
    const std::string netmask   { "2001:db8:abcd:0012:ffff:ffff:ffff:ffff" };
    const std::string broadcast { "2001:db8:85a3:8d3:1319:8a2e:370:0000" };
    const uint32_t dhcp         { 1 };
    const std::string metrics   { "25" };
    EXPECT_CALL(*mock, family()).Times(1).WillOnce(Return(Utils::NetworkWindowsHelper::IPV6));
    EXPECT_CALL(*mock, addressV6()).Times(1).WillOnce(Return(address));
    EXPECT_CALL(*mock, netmaskV6()).Times(1).WillOnce(Return(netmask));
    EXPECT_CALL(*mock, broadcastV6()).Times(1).WillOnce(Return(broadcast));
    EXPECT_CALL(*mock, dhcp()).Times(1).WillOnce(Return(dhcp));
    EXPECT_CALL(*mock, metricsV6()).Times(1).WillOnce(Return(metrics));
    EXPECT_NO_THROW(FactoryNetworkFamilyCreator<OSPlatformType::WINDOWS>::create(mock)->buildNetworkData(networkInfo));

    for (auto& element : networkInfo.at("IPv6"))
    {
        EXPECT_EQ(address, element.at("network_ip").get_ref<const std::string&>());
        EXPECT_EQ(netmask, element.at("network_netmask").get_ref<const std::string&>());
        EXPECT_EQ(broadcast, element.at("network_broadcast").get_ref<const std::string&>());
        EXPECT_EQ(dhcp, element.at("network_dhcp").get<uint32_t>());
        EXPECT_EQ(metrics, element.at("network_metric").get_ref<const std::string&>());
    }
}

TEST_F(SysInfoNetworkWindowsTest, Test_COMMON_DATA)
{
    auto mock { std::make_shared<SysInfoNetworkWindowsWrapperMock>() };
    nlohmann::json networkInfo {};
    const std::string name      { "eth01" };
    const std::string type      { "2001:db8:abcd:0012:ffff:ffff:ffff:ffff" };
    const std::string state     { "up" };
    const std::string MAC       { "00:A0:C9:14:C8:29" };
    const uint32_t mtu          { 1500 };
    const std::string gateway   { "10.2.2.50" };
    EXPECT_CALL(*mock, family()).Times(1).WillOnce(Return(Utils::NetworkWindowsHelper::COMMON_DATA));
    EXPECT_CALL(*mock, name()).Times(1).WillOnce(Return(name));
    EXPECT_CALL(*mock, type()).Times(1).WillOnce(Return(type));
    EXPECT_CALL(*mock, state()).Times(1).WillOnce(Return(state));
    EXPECT_CALL(*mock, MAC()).Times(1).WillOnce(Return(MAC));
    EXPECT_CALL(*mock, stats()).Times(1).WillOnce(Return(LinkStats{0, 1, 2, 3, 4, 5, 6, 7}));
    EXPECT_CALL(*mock, mtu()).Times(1).WillOnce(Return(mtu));
    EXPECT_CALL(*mock, gateway()).Times(1).WillOnce(Return(gateway));

    EXPECT_NO_THROW(FactoryNetworkFamilyCreator<OSPlatformType::WINDOWS>::create(mock)->buildNetworkData(networkInfo));

    EXPECT_EQ(name, networkInfo.at("interface_name").get_ref<const std::string&>());
    EXPECT_EQ(type, networkInfo.at("interface_type").get_ref<const std::string&>());
    EXPECT_EQ(state, networkInfo.at("interface_state").get_ref<const std::string&>());
    EXPECT_EQ(MAC, networkInfo.at("host_mac").get_ref<const std::string&>());

    EXPECT_EQ(1, networkInfo.at("host_network_egress_packages").get<int32_t>());
    EXPECT_EQ(0, networkInfo.at("host_network_ingress_packages").get<int32_t>());
    EXPECT_EQ(3, networkInfo.at("host_network_egress_bytes").get<int32_t>());
    EXPECT_EQ(2, networkInfo.at("host_network_ingress_bytes").get<int32_t>());
    EXPECT_EQ(5, networkInfo.at("host_network_egress_errors").get<int32_t>());
    EXPECT_EQ(4, networkInfo.at("host_network_ingress_errors").get<int32_t>());
    EXPECT_EQ(7, networkInfo.at("host_network_egress_drops").get<int32_t>());
    EXPECT_EQ(6, networkInfo.at("host_network_ingress_drops").get<int32_t>());

    EXPECT_EQ(mtu, networkInfo.at("interface_mtu").get<uint32_t>());
    EXPECT_EQ(gateway, networkInfo.at("network_gateway").get_ref<const std::string&>());
}