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
#include <ifaddrs.h>
#include <memory>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include "sysInfoNetworkLinux_test.h"
#include "network/networkInterfaceLinux.h"
#include "network/networkFamilyDataAFactory.h"
#include "network/networkLinuxWrapper.h"

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

TEST_F(SysInfoNetworkLinuxTest, Test_LOOPBACK_INTERFACE_TYPE)
{
    EXPECT_EQ("loopback",
              Utils::NetworkHelper::getNetworkTypeStringCode(ARPHRD_LOOPBACK, NETWORK_INTERFACE_TYPE));
}

TEST_F(SysInfoNetworkLinuxTest, Test_ETHERNET_INTERFACE_TYPE_UNCHANGED)
{
    EXPECT_EQ("ethernet",
              Utils::NetworkHelper::getNetworkTypeStringCode(ARPHRD_ETHER, NETWORK_INTERFACE_TYPE));
}

TEST_F(SysInfoNetworkLinuxTest, Test_LOOPBACK_STATE_IS_UP)
{
    // The loopback driver has no carrier detection, so the kernel reports "unknown" as its
    // operational state. An administratively up interface in that condition is up.
    char ifaceName[] { "lo" };
    ifaddrs iface {};
    iface.ifa_name = ifaceName;
    iface.ifa_flags = IFF_UP;

    EXPECT_EQ("up", NetworkLinuxInterface(&iface).state());
}

TEST_F(SysInfoNetworkLinuxTest, Test_LOOPBACK_STATE_WITHOUT_ADMIN_FLAG_IS_DOWN)
{
    // Same "unknown" operational state, but the interface is administratively down.
    char ifaceName[] { "lo" };
    ifaddrs iface {};
    iface.ifa_name = ifaceName;
    iface.ifa_flags = 0;

    EXPECT_EQ("down", NetworkLinuxInterface(&iface).state());
}

TEST_F(SysInfoNetworkLinuxTest, Test_STATE_KEEPS_PLACEHOLDER_WHEN_OPERSTATE_UNREADABLE)
{
    // An interface with no /sys entry keeps the placeholder rather than being forced to "down".
    char ifaceName[] { "wazuh-test-iface" };
    ifaddrs iface {};
    iface.ifa_name = ifaceName;
    iface.ifa_flags = IFF_UP;

    EXPECT_EQ(UNKNOWN_VALUE, NetworkLinuxInterface(&iface).state());
}

TEST_F(SysInfoNetworkLinuxTest, Test_ACCESSORS_FALL_BACK_WHEN_THE_INTERFACE_HAS_NO_SYS_ENTRY)
{
    // The same interface with no /sys entry: every accessor that reads a file returns its
    // documented fallback instead of failing.
    char ifaceName[] { "wazuh-test-iface" };
    ifaddrs iface {};
    iface.ifa_name = ifaceName;
    iface.ifa_flags = IFF_UP;

    const NetworkLinuxInterface wrapper(&iface);

    EXPECT_EQ(UNKNOWN_VALUE, wrapper.type());
    EXPECT_EQ(UNKNOWN_VALUE, wrapper.MAC());
    EXPECT_EQ(0u, wrapper.mtu());
    EXPECT_EQ(0u, wrapper.dhcp());

    const auto stats { wrapper.stats() };
    EXPECT_EQ(0u, stats.rxBytes);
    EXPECT_EQ(0u, stats.txBytes);
}

TEST_F(SysInfoNetworkLinuxTest, Test_CONSTRUCTOR_REJECTS_A_NULL_INTERFACE)
{
    EXPECT_THROW(NetworkLinuxInterface(nullptr), std::runtime_error);
}

// The cases below drive NetworkLinuxInterface over the host's real interfaces. The wrapper reads
// /sys/class/net and /proc/net through compile-time paths that cannot be redirected, so real
// interfaces are the only way to exercise it. Assertions are limited to invariants that hold on
// any host.

class RealInterfaces
{
        ifaddrs* m_list { nullptr };

    public:
        RealInterfaces()
        {
            if (0 != getifaddrs(&m_list))
            {
                m_list = nullptr;
            }
        }
        ~RealInterfaces()
        {
            if (m_list)
            {
                freeifaddrs(m_list);
            }
        }
        ifaddrs* get() const
        {
            return m_list;
        }
};

TEST_F(SysInfoNetworkLinuxTest, Test_REAL_INTERFACES_EXPOSE_CONSISTENT_VALUES)
{
    const RealInterfaces interfaces;
    ASSERT_NE(nullptr, interfaces.get()) << "the host exposes no network interfaces";

    auto visited { 0u };

    for (auto* entry = interfaces.get(); entry; entry = entry->ifa_next)
    {
        if (!entry->ifa_name)
        {
            continue;
        }

        ++visited;
        NetworkLinuxInterface iface(entry);

        EXPECT_FALSE(iface.name().empty());
        EXPECT_TRUE(iface.adapter().empty());
        EXPECT_TRUE(iface.metricsV6().empty());

        const auto family { iface.family() };
        EXPECT_TRUE(AF_INET == family || AF_INET6 == family || AF_PACKET == family);

        // Every interface reported by getifaddrs has a /sys entry, so the state is always
        // resolved to one of the two values the field is meant to carry.
        const auto state { iface.state() };
        EXPECT_TRUE("up" == state || "down" == state) << iface.name() << " reported " << state;

        EXPECT_GT(iface.mtu(), 0u);

        const auto mac { iface.MAC() };
        EXPECT_FALSE(mac.empty());

        // The remaining accessors have no host-independent value; assert only that they are
        // reachable and do not throw.
        EXPECT_NO_THROW(iface.type());
        EXPECT_NO_THROW(iface.stats());
        EXPECT_NO_THROW(iface.gateway());
        EXPECT_NO_THROW(iface.metrics());
        EXPECT_NO_THROW(iface.dhcp());

        // The address accessors interpret the socket address according to the family, so each
        // one is only meaningful for the family the factory dispatches it to.
        if (AF_INET == family)
        {
            EXPECT_FALSE(iface.address().empty());
            EXPECT_FALSE(iface.netmask().empty());
            EXPECT_NO_THROW(iface.broadcast());
        }
        else if (AF_INET6 == family)
        {
            EXPECT_FALSE(iface.addressV6().empty());
            EXPECT_FALSE(iface.netmaskV6().empty());
            EXPECT_NO_THROW(iface.broadcastV6());
        }
    }

    EXPECT_GT(visited, 0u);
}

TEST_F(SysInfoNetworkLinuxTest, Test_LOOPBACK_IS_REPORTED_AS_A_LOOPBACK_INTERFACE)
{
    const RealInterfaces interfaces;
    ASSERT_NE(nullptr, interfaces.get());

    auto found { false };

    for (auto* entry = interfaces.get(); entry; entry = entry->ifa_next)
    {
        if (!entry->ifa_name || std::string("lo") != entry->ifa_name)
        {
            continue;
        }

        found = true;
        NetworkLinuxInterface iface(entry);

        EXPECT_EQ("loopback", iface.type());
        EXPECT_EQ("up", iface.state());
        EXPECT_EQ("00:00:00:00:00:00", iface.MAC());
        EXPECT_GT(iface.mtu(), 0u);
    }

    ASSERT_TRUE(found) << "the host exposes no loopback interface";
}

TEST_F(SysInfoNetworkLinuxTest, Test_STATS_ARE_READ_FOR_THE_LOOPBACK_INTERFACE)
{
    const RealInterfaces interfaces;
    ASSERT_NE(nullptr, interfaces.get());

    for (auto* entry = interfaces.get(); entry; entry = entry->ifa_next)
    {
        if (!entry->ifa_name || std::string("lo") != entry->ifa_name)
        {
            continue;
        }

        // Loopback sends exactly what it receives, which makes the counters self-checking.
        const auto stats { NetworkLinuxInterface(entry).stats() };
        EXPECT_EQ(stats.rxBytes, stats.txBytes);
        EXPECT_EQ(stats.rxPackets, stats.txPackets);
        EXPECT_EQ(0u, stats.rxErrors);
        EXPECT_EQ(0u, stats.txErrors);
        break;
    }
}

TEST_F(SysInfoNetworkLinuxTest, Test_BROADCAST_IS_DERIVED_WHEN_THE_INTERFACE_HAS_NONE)
{
    // An interface that carries no broadcast address has one computed from its address and mask.
    char ifaceName[] { "wazuh-test-iface" };
    sockaddr_in address {};
    sockaddr_in netmask {};
    address.sin_family = AF_INET;
    netmask.sin_family = AF_INET;
    ASSERT_EQ(1, inet_pton(AF_INET, "192.168.1.10", &address.sin_addr));
    ASSERT_EQ(1, inet_pton(AF_INET, "255.255.255.0", &netmask.sin_addr));

    ifaddrs iface {};
    iface.ifa_name = ifaceName;
    iface.ifa_addr = reinterpret_cast<sockaddr*>(&address);
    iface.ifa_netmask = reinterpret_cast<sockaddr*>(&netmask);
    iface.ifa_ifu.ifu_broadaddr = nullptr;

    EXPECT_EQ("192.168.1.255", NetworkLinuxInterface(&iface).broadcast());
}

TEST_F(SysInfoNetworkLinuxTest, Test_IPV6_ACCESSORS_READ_THE_SOCKET_ADDRESS)
{
    // Built explicitly rather than taken from the host, so the IPv6 accessors are exercised even
    // where the runner has no IPv6 interface.
    char ifaceName[] { "wazuh-test-iface" };
    sockaddr_in6 address {};
    sockaddr_in6 netmask {};
    sockaddr_in6 broadcast {};
    address.sin6_family = AF_INET6;
    netmask.sin6_family = AF_INET6;
    broadcast.sin6_family = AF_INET6;
    ASSERT_EQ(1, inet_pton(AF_INET6, "fe80::250:56ff:fec0:8", &address.sin6_addr));
    ASSERT_EQ(1, inet_pton(AF_INET6, "ffff:ffff:ffff:ffff::", &netmask.sin6_addr));
    ASSERT_EQ(1, inet_pton(AF_INET6, "fe80::ffff:ffff:ffff:ffff", &broadcast.sin6_addr));

    ifaddrs iface {};
    iface.ifa_name = ifaceName;
    iface.ifa_addr = reinterpret_cast<sockaddr*>(&address);
    iface.ifa_netmask = reinterpret_cast<sockaddr*>(&netmask);
    iface.ifa_ifu.ifu_broadaddr = reinterpret_cast<sockaddr*>(&broadcast);

    const NetworkLinuxInterface wrapper(&iface);

    EXPECT_EQ(AF_INET6, wrapper.family());
    EXPECT_EQ("fe80::250:56ff:fec0:8", wrapper.addressV6());
    EXPECT_EQ("ffff:ffff:ffff:ffff::", wrapper.netmaskV6());
    EXPECT_EQ("fe80::ffff:ffff:ffff:ffff", wrapper.broadcastV6());
}
