/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * October 29, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <deque>
#include "gtest/gtest.h"
#include "network/networkLinuxAddressResolver.h"

namespace
{
    struct Attribute
    {
        unsigned short type;
        std::vector<char> payload;
    };

    Attribute ipv4Attribute(const unsigned short type, const std::string& address)
    {
        in_addr value {};
        inet_pton(AF_INET, address.c_str(), &value);
        const auto bytes { reinterpret_cast<const char*>(&value) };
        return { type, std::vector<char>(bytes, bytes + sizeof(value)) };
    }

    Attribute labelAttribute(const std::string& label)
    {
        return { IFA_LABEL, std::vector<char>(label.c_str(), label.c_str() + label.size() + 1) };
    }

    void appendMessage(std::vector<char>& buffer,
                       const unsigned short type,
                       const unsigned char family = AF_INET,
                       const unsigned int index = 0,
                       const std::vector<Attribute>& attributes = {},
                       const unsigned short flags = NLM_F_MULTI)
    {
        auto length { NLMSG_LENGTH(sizeof(ifaddrmsg)) };

        for (const auto& attribute : attributes)
        {
            length = NLMSG_ALIGN(length) + RTA_LENGTH(attribute.payload.size());
        }

        const auto offset { buffer.size() };
        buffer.resize(offset + NLMSG_ALIGN(length), 0);

        auto header { reinterpret_cast<nlmsghdr*>(buffer.data() + offset) };
        header->nlmsg_len = length;
        header->nlmsg_type = type;
        header->nlmsg_flags = flags;

        auto message { static_cast<ifaddrmsg*>(NLMSG_DATA(header)) };
        message->ifa_family = family;
        message->ifa_index = index;

        auto position { NLMSG_LENGTH(sizeof(ifaddrmsg)) };

        for (const auto& attribute : attributes)
        {
            position = NLMSG_ALIGN(position);
            auto rta { reinterpret_cast<rtattr*>(buffer.data() + offset + position) };
            rta->rta_type = attribute.type;
            rta->rta_len = RTA_LENGTH(attribute.payload.size());
            std::copy(attribute.payload.begin(), attribute.payload.end(), static_cast<char*>(RTA_DATA(rta)));
            position += RTA_LENGTH(attribute.payload.size());
        }
    }

    // Builds a getifaddrs()-like list. The nodes live as long as the fixture.
    class IfaddrsList final
    {
            std::deque<ifaddrs> m_nodes;
            std::deque<std::string> m_names;
            std::deque<sockaddr_in> m_addresses;

        public:
            ifaddrs* add(const std::string& name, const unsigned int flags, const std::string& ipv4 = "")
            {
                m_names.push_back(name);
                m_nodes.push_back({});
                auto& node { m_nodes.back() };
                node.ifa_name = const_cast<char*>(m_names.back().c_str());
                node.ifa_flags = flags;

                if (!ipv4.empty())
                {
                    m_addresses.push_back({});
                    m_addresses.back().sin_family = AF_INET;
                    inet_pton(AF_INET, ipv4.c_str(), &m_addresses.back().sin_addr);
                    node.ifa_addr = reinterpret_cast<sockaddr*>(&m_addresses.back());
                }

                if (m_nodes.size() > 1)
                {
                    m_nodes[m_nodes.size() - 2].ifa_next = &node;
                }

                return &node;
            }

            ifaddrs* head()
            {
                return m_nodes.empty() ? nullptr : &m_nodes.front();
            }

            // Same selection and keys as NetworkUnixHelper::getNetworks().
            std::map<std::string, std::vector<ifaddrs*>> helperGroups()
            {
                std::map<std::string, std::vector<ifaddrs*>> groups;

                for (auto ifa { head() }; ifa; ifa = ifa->ifa_next)
                {
                    if (!(ifa->ifa_flags & IFF_LOOPBACK))
                    {
                        groups[Utils::substrOnFirstOccurrence(ifa->ifa_name, ":")].push_back(ifa);
                    }
                }

                return groups;
            }
    };
}

TEST(NetworkLinuxAddressResolverTest, ParsesLabelAndLocalAddress)
{
    std::vector<char> buffer;
    appendMessage(buffer, RTM_NEWADDR, AF_INET, 9, { ipv4Attribute(IFA_ADDRESS, "10.0.0.202"), ipv4Attribute(IFA_LOCAL, "10.0.0.202"), labelAttribute("vip") });
    appendMessage(buffer, NLMSG_DONE);

    std::vector<IPv4AddressRecord> records;
    EXPECT_FALSE(NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), records));

    ASSERT_EQ(1u, records.size());
    EXPECT_EQ(9u, records[0].index);
    EXPECT_EQ("vip", records[0].label);
    EXPECT_EQ("10.0.0.202", records[0].address);
}

TEST(NetworkLinuxAddressResolverTest, AddressWithoutLabel)
{
    std::vector<char> buffer;
    appendMessage(buffer, RTM_NEWADDR, AF_INET, 2, { ipv4Attribute(IFA_ADDRESS, "172.20.0.3"), ipv4Attribute(IFA_LOCAL, "172.20.0.3") });

    std::vector<IPv4AddressRecord> records;
    EXPECT_TRUE(NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), records));

    ASSERT_EQ(1u, records.size());
    EXPECT_EQ("", records[0].label);
    EXPECT_EQ("172.20.0.3", records[0].address);
}

TEST(NetworkLinuxAddressResolverTest, LocalAddressWinsOverPeer)
{
    std::vector<char> buffer;
    appendMessage(buffer, RTM_NEWADDR, AF_INET, 5, { ipv4Attribute(IFA_ADDRESS, "10.8.0.1"), ipv4Attribute(IFA_LOCAL, "10.8.0.2"), labelAttribute("tun0") });

    std::vector<IPv4AddressRecord> records;
    NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), records);

    ASSERT_EQ(1u, records.size());
    EXPECT_EQ("10.8.0.2", records[0].address);
}

TEST(NetworkLinuxAddressResolverTest, PeerAddressWhenNoLocal)
{
    std::vector<char> buffer;
    appendMessage(buffer, RTM_NEWADDR, AF_INET, 5, { ipv4Attribute(IFA_ADDRESS, "10.8.0.1") });

    std::vector<IPv4AddressRecord> records;
    NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), records);

    ASSERT_EQ(1u, records.size());
    EXPECT_EQ("10.8.0.1", records[0].address);
}

TEST(NetworkLinuxAddressResolverTest, SkipsNonIPv4AndIncompleteMessages)
{
    std::vector<char> buffer;
    appendMessage(buffer, RTM_NEWADDR, AF_INET6, 2);
    appendMessage(buffer, RTM_NEWADDR, AF_INET, 2, { labelAttribute("eth0") });
    appendMessage(buffer, RTM_NEWLINK, AF_INET, 2);
    appendMessage(buffer, RTM_NEWADDR, AF_INET, 3, { ipv4Attribute(IFA_LOCAL, "192.0.2.10"), labelAttribute("eth1") });

    std::vector<IPv4AddressRecord> records;
    EXPECT_TRUE(NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), records));

    ASSERT_EQ(1u, records.size());
    EXPECT_EQ(3u, records[0].index);
    EXPECT_EQ("eth1", records[0].label);
}

TEST(NetworkLinuxAddressResolverTest, AccumulatesAcrossBuffers)
{
    std::vector<char> first;
    appendMessage(first, RTM_NEWADDR, AF_INET, 2, { ipv4Attribute(IFA_LOCAL, "172.20.0.3") });
    std::vector<char> second;
    appendMessage(second, RTM_NEWADDR, AF_INET, 2, { ipv4Attribute(IFA_LOCAL, "192.0.2.10"), labelAttribute("vip") });
    appendMessage(second, NLMSG_DONE);

    std::vector<IPv4AddressRecord> records;
    EXPECT_TRUE(NetworkLinuxAddressResolver::parseAddressMessages(first.data(), first.size(), records));
    EXPECT_FALSE(NetworkLinuxAddressResolver::parseAddressMessages(second.data(), second.size(), records));
    EXPECT_EQ(2u, records.size());
}

TEST(NetworkLinuxAddressResolverTest, ErrorMessageThrows)
{
    std::vector<char> buffer;
    appendMessage(buffer, NLMSG_ERROR);

    std::vector<IPv4AddressRecord> records;
    EXPECT_THROW(NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), records), std::runtime_error);
}

TEST(NetworkLinuxAddressResolverTest, InterruptedDumpThrows)
{
    std::vector<char> buffer;
    appendMessage(buffer, RTM_NEWADDR, AF_INET, 2, { ipv4Attribute(IFA_LOCAL, "172.20.0.3") }, NLM_F_MULTI | NLM_F_DUMP_INTR);

    std::vector<IPv4AddressRecord> records;
    EXPECT_THROW(NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), records), std::runtime_error);
}

TEST(NetworkLinuxAddressResolverTest, GroupsLabelledAddressesByLink)
{
    IfaddrsList list;
    list.add("lo", IFF_LOOPBACK);
    const auto eth0 { list.add("eth0", 0) };
    const auto eth1 { list.add("eth1", 0) };
    list.add("lo", IFF_LOOPBACK, "127.0.0.1");
    const auto primary { list.add("eth0", 0, "172.20.0.3") };
    const auto alias { list.add("eth0:0", 0, "192.0.2.10") };
    const auto suffix { list.add("eth0:vip", 0, "192.0.2.11") };
    const auto vip { list.add("vip", 0, "192.0.2.12") };
    const auto zero { list.add("0", 0, "192.0.2.13") };
    const auto loLabel { list.add("lo", 0, "192.0.2.14") };
    const auto eth1Label { list.add("eth1", 0, "192.0.2.15") };
    const auto eth1Own { list.add("eth1", 0, "198.51.100.1") };
    const auto eth0V6 { list.add("eth0", 0) };

    const IPv4AddressLinks links
    {
        { { "lo", "127.0.0.1" }, "lo" },
        { { "eth0", "172.20.0.3" }, "eth0" },
        { { "eth0:0", "192.0.2.10" }, "eth0" },
        { { "eth0:vip", "192.0.2.11" }, "eth0" },
        { { "vip", "192.0.2.12" }, "eth0" },
        { { "0", "192.0.2.13" }, "eth0" },
        { { "lo", "192.0.2.14" }, "eth0" },
        { { "eth1", "192.0.2.15" }, "eth0" },
        { { "eth1", "198.51.100.1" }, "eth1" },
    };

    const auto groups { NetworkLinuxAddressResolver::groupByLink(list.head(), list.helperGroups(), links) };

    const std::map<std::string, std::vector<ifaddrs*>> expected
    {
        { "eth0", { eth0, primary, alias, suffix, vip, zero, loLabel, eth1Label, eth0V6 } },
        { "eth1", { eth1, eth1Own } },
    };
    EXPECT_EQ(expected, groups);
}

TEST(NetworkLinuxAddressResolverTest, KeepsLabelGroupingWithoutLinks)
{
    IfaddrsList list;
    const auto eth0 { list.add("eth0", 0) };
    const auto primary { list.add("eth0", 0, "172.20.0.3") };
    const auto alias { list.add("eth0:0", 0, "192.0.2.10") };
    const auto vip { list.add("vip", 0, "192.0.2.12") };

    const auto groups { NetworkLinuxAddressResolver::groupByLink(list.head(), list.helperGroups(), {}) };

    const std::map<std::string, std::vector<ifaddrs*>> expected
    {
        { "eth0", { eth0, primary, alias } },
        { "vip", { vip } },
    };
    EXPECT_EQ(expected, groups);
}

TEST(NetworkLinuxAddressResolverTest, ResolvesEveryHostIPv4Address)
{
    IPv4AddressLinks links;
    ASSERT_NO_THROW(links = NetworkLinuxAddressResolver::getIPv4AddressLinks());

    ifaddrs* addresses { nullptr };
    ASSERT_EQ(0, getifaddrs(&addresses));

    for (auto ifa { addresses }; ifa; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr && AF_INET == ifa->ifa_addr->sa_family)
        {
            char address[INET_ADDRSTRLEN] {};
            inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(ifa->ifa_addr)->sin_addr, address, sizeof(address));
            EXPECT_NE(links.end(), links.find(std::make_pair(std::string { ifa->ifa_name }, std::string { address })))
                    << ifa->ifa_name << " " << address;
        }
    }

    freeifaddrs(addresses);
}
