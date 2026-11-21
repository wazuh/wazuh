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
#include "networkUnixHelper.h"

// Absent from kernel headers older than 3.14
#ifndef IFA_F_NOPREFIXROUTE
#define IFA_F_NOPREFIXROUTE 0x200
#endif

namespace
{
    constexpr unsigned int SEQUENCE { 1 };

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

    Attribute flagsAttribute(const uint32_t flags)
    {
        const auto bytes { reinterpret_cast<const char*>(&flags) };
        return { IFA_FLAGS, std::vector<char>(bytes, bytes + sizeof(flags)) };
    }

    void appendDone(std::vector<char>& buffer, const int result, const unsigned short flags = NLM_F_MULTI)
    {
        const auto offset { buffer.size() };
        buffer.resize(offset + NLMSG_SPACE(sizeof(result)), 0);

        auto header { reinterpret_cast<nlmsghdr*>(buffer.data() + offset) };
        header->nlmsg_len = NLMSG_LENGTH(sizeof(result));
        header->nlmsg_type = NLMSG_DONE;
        header->nlmsg_flags = flags;
        header->nlmsg_seq = SEQUENCE;
        std::memcpy(NLMSG_DATA(header), &result, sizeof(result));
    }

    void appendMessage(std::vector<char>& buffer,
                       const unsigned short type,
                       const unsigned char family = AF_INET,
                       const unsigned int index = 0,
                       const std::vector<Attribute>& attributes = {},
                       const unsigned short flags = NLM_F_MULTI,
                       const unsigned int sequence = SEQUENCE,
                       const unsigned char addressFlags = 0,
                       const unsigned char prefixLength = 0)
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
        header->nlmsg_seq = sequence;

        auto message { static_cast<ifaddrmsg*>(NLMSG_DATA(header)) };
        message->ifa_family = family;
        message->ifa_index = index;
        message->ifa_flags = addressFlags;
        message->ifa_prefixlen = prefixLength;

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
            std::deque<sockaddr_ll> m_links;

            ifaddrs* append(const std::string& name, const unsigned int flags)
            {
                m_names.push_back(name);
                m_nodes.push_back({});
                auto& node { m_nodes.back() };
                node.ifa_name = const_cast<char*>(m_names.back().c_str());
                node.ifa_flags = flags;

                if (m_nodes.size() > 1)
                {
                    m_nodes[m_nodes.size() - 2].ifa_next = &node;
                }

                return &node;
            }

        public:
            ifaddrs* addLink(const std::string& name, const unsigned int flags, const int index)
            {
                auto node { append(name, flags) };
                m_links.push_back({});
                m_links.back().sll_family = AF_PACKET;
                m_links.back().sll_ifindex = index;
                node->ifa_addr = reinterpret_cast<sockaddr*>(&m_links.back());
                return node;
            }

            ifaddrs* addIPv4(const std::string& name, const unsigned int flags, const std::string& ipv4)
            {
                auto node { append(name, flags) };
                m_addresses.push_back({});
                m_addresses.back().sin_family = AF_INET;
                inet_pton(AF_INET, ipv4.c_str(), &m_addresses.back().sin_addr);
                node->ifa_addr = reinterpret_cast<sockaddr*>(&m_addresses.back());
                return node;
            }

            // IPv6 entries are only grouped by name, so their address is not needed.
            ifaddrs* addOther(const std::string& name, const unsigned int flags)
            {
                return append(name, flags);
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

    using IPv4Keys = std::vector<std::pair<std::string, std::string>>;

    // (label, address) of every host IPv4 address, in getifaddrs() order and in dump order.
    std::pair<IPv4Keys, IPv4Keys> hostIPv4Keys()
    {
        ifaddrs* list { nullptr };

        if (0 != getifaddrs(&list))
        {
            throw std::runtime_error { "getifaddrs() failed" };
        }

        const std::unique_ptr<ifaddrs, Utils::IfAddressSmartDeleter> addresses { list };
        IPv4Keys snapshot;

        for (auto ifa { addresses.get() }; ifa; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_name && ifa->ifa_addr && AF_INET == ifa->ifa_addr->sa_family)
            {
                snapshot.emplace_back(ifa->ifa_name, Utils::NetworkHelper::IAddressToBinary(AF_INET, &reinterpret_cast<sockaddr_in*>(ifa->ifa_addr)->sin_addr));
            }
        }

        IPv4Keys dump;

        for (const auto& record : NetworkLinuxAddressResolver::dumpIPv4Addresses())
        {
            char linkName[IF_NAMESIZE] {};
            dump.emplace_back(record.label.empty() && if_indextoname(record.index, linkName) ? linkName : record.label, record.address);
        }

        return { snapshot, dump };
    }
}

TEST(NetworkLinuxAddressResolverTest, ParsesLabelAndLocalAddress)
{
    std::vector<char> buffer;
    appendMessage(buffer, RTM_NEWADDR, AF_INET, 9, { ipv4Attribute(IFA_ADDRESS, "10.0.0.202"), ipv4Attribute(IFA_LOCAL, "10.0.0.202"), labelAttribute("vip") });
    appendMessage(buffer, NLMSG_DONE);

    std::vector<IPv4AddressRecord> records;
    EXPECT_FALSE(NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), SEQUENCE, records));

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
    EXPECT_TRUE(NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), SEQUENCE, records));

    ASSERT_EQ(1u, records.size());
    EXPECT_EQ("", records[0].label);
    EXPECT_EQ("172.20.0.3", records[0].address);
}

TEST(NetworkLinuxAddressResolverTest, LocalAddressWinsOverPeer)
{
    std::vector<char> buffer;
    appendMessage(buffer, RTM_NEWADDR, AF_INET, 5, { ipv4Attribute(IFA_ADDRESS, "10.8.0.1"), ipv4Attribute(IFA_LOCAL, "10.8.0.2"), labelAttribute("tun0") });

    std::vector<IPv4AddressRecord> records;
    NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), SEQUENCE, records);

    ASSERT_EQ(1u, records.size());
    EXPECT_EQ("10.8.0.2", records[0].address);
}

TEST(NetworkLinuxAddressResolverTest, PeerAddressWhenNoLocal)
{
    std::vector<char> buffer;
    appendMessage(buffer, RTM_NEWADDR, AF_INET, 5, { ipv4Attribute(IFA_ADDRESS, "10.8.0.1") });

    std::vector<IPv4AddressRecord> records;
    NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), SEQUENCE, records);

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
    EXPECT_TRUE(NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), SEQUENCE, records));

    ASSERT_EQ(1u, records.size());
    EXPECT_EQ(3u, records[0].index);
    EXPECT_EQ("eth1", records[0].label);
}

TEST(NetworkLinuxAddressResolverTest, SkipsMessagesOfAnotherSequence)
{
    std::vector<char> buffer;
    appendMessage(buffer, RTM_NEWADDR, AF_INET, 2, { ipv4Attribute(IFA_LOCAL, "203.0.113.1"), labelAttribute("eth0") }, NLM_F_MULTI, SEQUENCE + 1);
    appendMessage(buffer, NLMSG_DONE, AF_INET, 0, {}, NLM_F_MULTI, SEQUENCE + 1);
    appendMessage(buffer, RTM_NEWADDR, AF_INET, 2, { ipv4Attribute(IFA_LOCAL, "172.20.0.3") });

    std::vector<IPv4AddressRecord> records;
    EXPECT_TRUE(NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), SEQUENCE, records));

    ASSERT_EQ(1u, records.size());
    EXPECT_EQ("172.20.0.3", records[0].address);
}

TEST(NetworkLinuxAddressResolverTest, AccumulatesAcrossBuffers)
{
    std::vector<char> first;
    appendMessage(first, RTM_NEWADDR, AF_INET, 2, { ipv4Attribute(IFA_LOCAL, "172.20.0.3") });
    std::vector<char> second;
    appendMessage(second, RTM_NEWADDR, AF_INET, 2, { ipv4Attribute(IFA_LOCAL, "192.0.2.10"), labelAttribute("vip") });
    appendMessage(second, NLMSG_DONE);

    std::vector<IPv4AddressRecord> records;
    EXPECT_TRUE(NetworkLinuxAddressResolver::parseAddressMessages(first.data(), first.size(), SEQUENCE, records));
    EXPECT_FALSE(NetworkLinuxAddressResolver::parseAddressMessages(second.data(), second.size(), SEQUENCE, records));
    EXPECT_EQ(2u, records.size());
}

TEST(NetworkLinuxAddressResolverTest, ErrorMessageThrows)
{
    std::vector<char> buffer;
    appendMessage(buffer, NLMSG_ERROR);

    std::vector<IPv4AddressRecord> records;
    EXPECT_THROW(NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), SEQUENCE, records), std::runtime_error);
}

TEST(NetworkLinuxAddressResolverTest, InterruptedDumpThrows)
{
    std::vector<char> buffer;
    appendMessage(buffer, RTM_NEWADDR, AF_INET, 2, { ipv4Attribute(IFA_LOCAL, "172.20.0.3") }, NLM_F_MULTI | NLM_F_DUMP_INTR);

    std::vector<IPv4AddressRecord> records;
    EXPECT_THROW(NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), SEQUENCE, records), NetlinkDumpInterrupted);
}

TEST(NetworkLinuxAddressResolverTest, InterruptedDoneThrows)
{
    std::vector<char> buffer;
    appendMessage(buffer, RTM_NEWADDR, AF_INET, 2, { ipv4Attribute(IFA_LOCAL, "172.20.0.3") });
    appendDone(buffer, 0, NLM_F_MULTI | NLM_F_DUMP_INTR);

    std::vector<IPv4AddressRecord> records;
    EXPECT_THROW(NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), SEQUENCE, records), NetlinkDumpInterrupted);
}

TEST(NetworkLinuxAddressResolverTest, FailedDoneThrows)
{
    std::vector<char> buffer;
    appendDone(buffer, -ENOBUFS);

    std::vector<IPv4AddressRecord> records;

    try
    {
        NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), SEQUENCE, records);
        FAIL() << "A failed dump must throw";
    }
    catch (const NetlinkDumpInterrupted&)
    {
        FAIL() << "A failed dump must not be retried";
    }
    catch (const std::runtime_error&)
    {
    }
}

TEST(NetworkLinuxAddressResolverTest, SuccessfulDoneEndsTheDump)
{
    std::vector<char> buffer;
    appendDone(buffer, 0);

    std::vector<IPv4AddressRecord> records;
    EXPECT_FALSE(NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), SEQUENCE, records));
}

TEST(NetworkLinuxAddressResolverTest, ResolvesLinkNamesFromTheSnapshot)
{
    IfaddrsList list;
    list.addLink("eth0", 0, 2);
    list.addLink("br-ex", 0, 9);

    const std::vector<IPv4AddressRecord> records
    {
        { 2, "", "172.20.0.3" },
        { 9, "", "10.0.0.196" },
        { 9, "vip", "10.0.0.202" },
        { 9, "eth0", "192.0.2.15" },
    };

    const IPv4AddressLinks expected
    {
        { { "eth0", "172.20.0.3" }, { "eth0" } },
        { { "br-ex", "10.0.0.196" }, { "br-ex" } },
        { { "vip", "10.0.0.202" }, { "br-ex" } },
        { { "eth0", "192.0.2.15" }, { "br-ex" } },
    };
    EXPECT_EQ(expected, NetworkLinuxAddressResolver::resolveLinks(records, list.head()));
}

TEST(NetworkLinuxAddressResolverTest, KeepsEveryLinkOfASharedLabelAndAddress)
{
    IfaddrsList list;
    list.addLink("d0", 0, 4);
    list.addLink("d1", 0, 5);

    const std::vector<IPv4AddressRecord> records
    {
        { 4, "vip", "10.0.0.5" },
        { 5, "vip", "10.0.0.5" },
    };

    const IPv4AddressLinks expected
    {
        { { "vip", "10.0.0.5" }, { "d0", "d1" } },
    };
    EXPECT_EQ(expected, NetworkLinuxAddressResolver::resolveLinks(records, list.head()));
}

TEST(NetworkLinuxAddressResolverTest, KeepsTheSlotOfAnUnknownLink)
{
    IfaddrsList list;
    list.addLink("eth0", 0, 2);
    list.addLink("d1", 0, 5);

    const std::vector<IPv4AddressRecord> records
    {
        { 2, "", "172.20.0.3" },
        { 0, "vip", "192.0.2.10" },
        { 5, "vip", "192.0.2.10" },
        { 0, "", "198.51.100.1" },
    };

    const IPv4AddressLinks expected
    {
        { { "eth0", "172.20.0.3" }, { "eth0" } },
        { { "vip", "192.0.2.10" }, { "", "d1" } },
    };
    EXPECT_EQ(expected, NetworkLinuxAddressResolver::resolveLinks(records, list.head()));
}

TEST(NetworkLinuxAddressResolverTest, GroupsLabelledAddressesByLink)
{
    IfaddrsList list;
    list.addLink("lo", IFF_LOOPBACK, 1);
    const auto eth0 { list.addLink("eth0", 0, 2) };
    const auto eth1 { list.addLink("eth1", 0, 3) };
    list.addIPv4("lo", IFF_LOOPBACK, "127.0.0.1");
    const auto primary { list.addIPv4("eth0", 0, "172.20.0.3") };
    const auto alias { list.addIPv4("eth0:0", 0, "192.0.2.10") };
    const auto suffix { list.addIPv4("eth0:vip", 0, "192.0.2.11") };
    const auto vip { list.addIPv4("vip", 0, "192.0.2.12") };
    const auto zero { list.addIPv4("0", 0, "192.0.2.13") };
    const auto loLabel { list.addIPv4("lo", 0, "192.0.2.14") };
    const auto eth1Label { list.addIPv4("eth1", 0, "192.0.2.15") };
    const auto eth1Own { list.addIPv4("eth1", 0, "198.51.100.1") };
    const auto eth0V6 { list.addOther("eth0", 0) };

    const IPv4AddressLinks links
    {
        { { "lo", "127.0.0.1" }, { "lo" } },
        { { "eth0", "172.20.0.3" }, { "eth0" } },
        { { "eth0:0", "192.0.2.10" }, { "eth0" } },
        { { "eth0:vip", "192.0.2.11" }, { "eth0" } },
        { { "vip", "192.0.2.12" }, { "eth0" } },
        { { "0", "192.0.2.13" }, { "eth0" } },
        { { "lo", "192.0.2.14" }, { "eth0" } },
        { { "eth1", "192.0.2.15" }, { "eth0" } },
        { { "eth1", "198.51.100.1" }, { "eth1" } },
    };

    const auto groups { NetworkLinuxAddressResolver::groupByLink(list.head(), list.helperGroups(), links) };

    const std::map<std::string, std::vector<ifaddrs*>> expected
    {
        { "eth0", { eth0, primary, alias, suffix, vip, zero, loLabel, eth1Label, eth0V6 } },
        { "eth1", { eth1, eth1Own } },
    };
    EXPECT_EQ(expected, groups);
}

TEST(NetworkLinuxAddressResolverTest, SharedLabelAndAddressGoToEachLinkInTurn)
{
    IfaddrsList list;
    list.addLink("lo", IFF_LOOPBACK, 1);
    const auto d0 { list.addLink("d0", 0, 4) };
    const auto d1 { list.addLink("d1", 0, 5) };
    // Not selected by the helper, but it still takes the first link of the key.
    list.addIPv4("vip", IFF_LOOPBACK, "10.0.0.5");
    const auto d0Vip { list.addIPv4("vip", 0, "10.0.0.5") };
    const auto d1Vip { list.addIPv4("vip", 0, "10.0.0.5") };
    // Beyond the links in the dump: keeps its label.
    const auto extraVip { list.addIPv4("vip", 0, "10.0.0.5") };

    const IPv4AddressLinks links
    {
        { { "vip", "10.0.0.5" }, { "lo", "d0", "d1" } },
    };

    const auto groups { NetworkLinuxAddressResolver::groupByLink(list.head(), list.helperGroups(), links) };

    const std::map<std::string, std::vector<ifaddrs*>> expected
    {
        { "d0", { d0, d0Vip } },
        { "d1", { d1, d1Vip } },
        { "vip", { extraVip } },
    };
    EXPECT_EQ(expected, groups);
}

TEST(NetworkLinuxAddressResolverTest, UnnamedLinkKeepsLabelGrouping)
{
    IfaddrsList list;
    const auto d1 { list.addLink("d1", 0, 5) };
    const auto goneVip { list.addIPv4("vip", 0, "10.0.0.5") };
    const auto d1Vip { list.addIPv4("vip", 0, "10.0.0.5") };

    const IPv4AddressLinks links
    {
        { { "vip", "10.0.0.5" }, { "", "d1" } },
    };

    const auto groups { NetworkLinuxAddressResolver::groupByLink(list.head(), list.helperGroups(), links) };

    const std::map<std::string, std::vector<ifaddrs*>> expected
    {
        { "d1", { d1, d1Vip } },
        { "vip", { goneVip } },
    };
    EXPECT_EQ(expected, groups);
}

TEST(NetworkLinuxAddressResolverTest, KeepsLabelGroupingWithoutLinks)
{
    IfaddrsList list;
    const auto eth0 { list.addLink("eth0", 0, 2) };
    const auto primary { list.addIPv4("eth0", 0, "172.20.0.3") };
    const auto alias { list.addIPv4("eth0:0", 0, "192.0.2.10") };
    const auto vip { list.addIPv4("vip", 0, "192.0.2.12") };

    const auto groups { NetworkLinuxAddressResolver::groupByLink(list.head(), list.helperGroups(), {}) };

    const std::map<std::string, std::vector<ifaddrs*>> expected
    {
        { "eth0", { eth0, primary, alias } },
        { "vip", { vip } },
    };
    EXPECT_EQ(expected, groups);
}

TEST(NetworkLinuxAddressResolverTest, DumpListsHostIPv4AddressesInGetifaddrsOrder)
{
    // groupByLink() pairs both lists by position. They are two snapshots, so compare again
    // before failing in case an address changed in between.
    std::pair<IPv4Keys, IPv4Keys> keys;
    ASSERT_NO_THROW(keys = hostIPv4Keys());

    if (keys.first != keys.second)
    {
        ASSERT_NO_THROW(keys = hostIPv4Keys());
    }

    EXPECT_EQ(keys.first, keys.second);
}

TEST(NetworkLinuxAddressResolverTest, KeepsTheEightBitFlagsWithoutIfaFlags)
{
    std::vector<char> buffer;
    appendMessage(buffer, RTM_NEWADDR, AF_INET, 2, { ipv4Attribute(IFA_LOCAL, "172.20.0.3") }, NLM_F_MULTI, SEQUENCE, IFA_F_PERMANENT);
    appendMessage(buffer, RTM_NEWADDR, AF_INET, 2, { ipv4Attribute(IFA_LOCAL, "172.20.0.4") });

    std::vector<IPv4AddressRecord> records;
    EXPECT_TRUE(NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), SEQUENCE, records));

    ASSERT_EQ(2u, records.size());
    EXPECT_EQ(static_cast<uint32_t>(IFA_F_PERMANENT), records[0].flags);
    EXPECT_EQ(0u, records[1].flags);
}

TEST(NetworkLinuxAddressResolverTest, IfaFlagsOverridesTheEightBitFlags)
{
    // noprefixroute does not fit in the 8-bit field, so the kernel sends the whole value in IFA_FLAGS.
    const uint32_t wide { IFA_F_PERMANENT | IFA_F_NOPREFIXROUTE };
    std::vector<char> buffer;
    appendMessage(buffer, RTM_NEWADDR, AF_INET, 2, { ipv4Attribute(IFA_LOCAL, "172.20.0.3"), flagsAttribute(wide) }, NLM_F_MULTI, SEQUENCE, IFA_F_PERMANENT);

    std::vector<IPv4AddressRecord> records;
    EXPECT_TRUE(NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), SEQUENCE, records));

    ASSERT_EQ(1u, records.size());
    EXPECT_EQ(wide, records[0].flags);
}

TEST(NetworkLinuxAddressResolverTest, KeepsThePrefixLengthOfEachAddress)
{
    std::vector<char> buffer;
    appendMessage(buffer, RTM_NEWADDR, AF_INET, 2, { ipv4Attribute(IFA_LOCAL, "10.0.0.5") }, NLM_F_MULTI, SEQUENCE, IFA_F_PERMANENT, 32);
    appendMessage(buffer, RTM_NEWADDR, AF_INET, 2, { ipv4Attribute(IFA_LOCAL, "10.0.0.5") }, NLM_F_MULTI, SEQUENCE, 0, 24);

    std::vector<IPv4AddressRecord> records;
    EXPECT_TRUE(NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), SEQUENCE, records));

    ASSERT_EQ(2u, records.size());
    EXPECT_EQ(32u, records[0].prefixLength);
    EXPECT_EQ(24u, records[1].prefixLength);
}

TEST(NetworkLinuxAddressResolverTest, IgnoresATruncatedIfaFlags)
{
    std::vector<char> buffer;
    appendMessage(buffer, RTM_NEWADDR, AF_INET, 2, { ipv4Attribute(IFA_LOCAL, "172.20.0.3"), { IFA_FLAGS, std::vector<char>(2, '\xff') } }, NLM_F_MULTI, SEQUENCE, IFA_F_PERMANENT);

    std::vector<IPv4AddressRecord> records;
    EXPECT_TRUE(NetworkLinuxAddressResolver::parseAddressMessages(buffer.data(), buffer.size(), SEQUENCE, records));

    ASSERT_EQ(1u, records.size());
    EXPECT_EQ(static_cast<uint32_t>(IFA_F_PERMANENT), records[0].flags);
}

TEST(NetworkLinuxAddressResolverTest, ResolvesTheFlagsOfEachAddressByLinkName)
{
    IfaddrsList list;
    list.addLink("eth0", 0, 2);
    list.addLink("br-ex", 0, 9);

    const std::vector<IPv4AddressRecord> records
    {
        { 2, "", "172.20.0.3", 0, 16 },
        { 9, "vip", "10.0.0.202", IFA_F_PERMANENT, 32 },
        { 9, "", "10.0.0.196", IFA_F_PERMANENT | IFA_F_NOPREFIXROUTE, 24 },
        { 9, "", "10.0.0.202", 0, 24 },
        { 0, "", "198.51.100.1", 0, 24 },
    };

    IPv4AddressFlags flags;
    NetworkLinuxAddressResolver::resolveLinks(records, list.head(), &flags);

    // The label does not matter, the link does. The same address with two prefixes keeps two
    // entries. An address whose link has no name carries no flags.
    const IPv4AddressFlags expected
    {
        { { "eth0", "172.20.0.3", 16 }, 0 },
        { { "br-ex", "10.0.0.202", 32 }, IFA_F_PERMANENT },
        { { "br-ex", "10.0.0.196", 24 }, IFA_F_PERMANENT | IFA_F_NOPREFIXROUTE },
        { { "br-ex", "10.0.0.202", 24 }, 0 },
    };
    EXPECT_EQ(expected, flags);
}

namespace
{
    struct RouteOptions
    {
        unsigned char family { AF_INET6 };
        unsigned char destinationLength { 0 };
        unsigned char sourceLength { 0 };
        unsigned char type { RTN_UNICAST };
        unsigned char table { RT_TABLE_MAIN };
        unsigned int flags { 0 };
        unsigned int sequence { SEQUENCE };
    };

    Attribute ipv6Attribute(const unsigned short type, const std::string& address)
    {
        in6_addr value {};
        inet_pton(AF_INET6, address.c_str(), &value);
        const auto bytes { reinterpret_cast<const char*>(&value) };
        return { type, std::vector<char>(bytes, bytes + sizeof(value)) };
    }

    Attribute outputInterfaceAttribute(const unsigned int index)
    {
        const auto bytes { reinterpret_cast<const char*>(&index) };
        return { RTA_OIF, std::vector<char>(bytes, bytes + sizeof(index)) };
    }

    // One rtnexthop followed by its gateway attribute, as the kernel lays out RTA_MULTIPATH.
    void appendNexthop(std::vector<char>& payload, const unsigned int index, const std::string& gateway)
    {
        const auto attribute { ipv6Attribute(RTA_GATEWAY, gateway) };
        const auto offset { payload.size() };
        payload.resize(offset + RTNH_ALIGN(RTNH_LENGTH(RTA_LENGTH(attribute.payload.size()))), 0);

        auto nexthop { reinterpret_cast<rtnexthop*>(payload.data() + offset) };
        nexthop->rtnh_len = RTNH_LENGTH(RTA_LENGTH(attribute.payload.size()));
        nexthop->rtnh_ifindex = static_cast<int>(index);

        auto rta { RTNH_DATA(nexthop) };
        rta->rta_type = attribute.type;
        rta->rta_len = RTA_LENGTH(attribute.payload.size());
        std::copy(attribute.payload.begin(), attribute.payload.end(), static_cast<char*>(RTA_DATA(rta)));
    }

    Attribute multipathAttribute(const std::vector<std::pair<unsigned int, std::string>>& nexthops)
    {
        Attribute attribute { RTA_MULTIPATH, {} };

        for (const auto& nexthop : nexthops)
        {
            appendNexthop(attribute.payload, nexthop.first, nexthop.second);
        }

        return attribute;
    }

    void appendRoute(std::vector<char>& buffer, const std::vector<Attribute>& attributes, const RouteOptions& options = {})
    {
        auto length { NLMSG_LENGTH(sizeof(rtmsg)) };

        for (const auto& attribute : attributes)
        {
            length = NLMSG_ALIGN(length) + RTA_LENGTH(attribute.payload.size());
        }

        const auto offset { buffer.size() };
        buffer.resize(offset + NLMSG_ALIGN(length), 0);

        auto header { reinterpret_cast<nlmsghdr*>(buffer.data() + offset) };
        header->nlmsg_len = length;
        header->nlmsg_type = RTM_NEWROUTE;
        header->nlmsg_flags = NLM_F_MULTI;
        header->nlmsg_seq = options.sequence;

        auto message { static_cast<rtmsg*>(NLMSG_DATA(header)) };
        message->rtm_family = options.family;
        message->rtm_dst_len = options.destinationLength;
        message->rtm_src_len = options.sourceLength;
        message->rtm_table = options.table;
        message->rtm_type = options.type;
        message->rtm_flags = options.flags;

        auto position { NLMSG_LENGTH(sizeof(rtmsg)) };

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

    unsigned int loopbackIndex()
    {
        return if_nametoindex("lo");
    }

    // Name and index of a host interface other than lo, or an empty name when there is none.
    std::pair<std::string, unsigned int> otherInterface()
    {
        std::pair<std::string, unsigned int> other;
        const auto list { if_nameindex() };

        for (auto entry { list }; list && entry->if_index != 0; ++entry)
        {
            if (std::string { "lo" } != entry->if_name)
            {
                other = { entry->if_name, entry->if_index };
                break;
            }
        }

        if_freenameindex(list);
        return other;
    }

    bool parseRoutes(const std::vector<char>& buffer, std::vector<IPv6Route>& routes)
    {
        return NetworkLinuxAddressResolver::parseRouteMessages(buffer.data(), buffer.size(), SEQUENCE, routes);
    }

    // Routes that name no nexthop object: nothing to look up.
    bool parseRoutes(const std::vector<char>& buffer, IPv6Gateways& gateways)
    {
        std::vector<IPv6Route> routes;
        const auto pending { parseRoutes(buffer, routes) };
        gateways = NetworkLinuxAddressResolver::selectGateways(routes, {});
        return pending;
    }

    constexpr unsigned short NEXTHOP_ID { 1 };
    constexpr unsigned short NEXTHOP_GROUP { 2 };
    constexpr unsigned short NEXTHOP_BLACKHOLE { 4 };
    constexpr unsigned short NEXTHOP_OIF { 5 };
    constexpr unsigned short NEXTHOP_GATEWAY { 6 };
    constexpr unsigned short ROUTE_NEXTHOP_ID { 30 };
    constexpr unsigned short NEW_NEXTHOP { 104 };

    Attribute integerAttribute(const unsigned short type, const unsigned int value)
    {
        const auto bytes { reinterpret_cast<const char*>(&value) };
        return { type, std::vector<char>(bytes, bytes + sizeof(value)) };
    }

    // The members as the kernel lays out NHA_GROUP: id, weight, weight_high, reserved.
    Attribute groupAttribute(const std::vector<unsigned int>& members)
    {
        Attribute attribute { NEXTHOP_GROUP, {} };

        for (const auto member : members)
        {
            const auto bytes { reinterpret_cast<const char*>(&member) };
            attribute.payload.insert(attribute.payload.end(), bytes, bytes + sizeof(member));
            attribute.payload.insert(attribute.payload.end(), 4, 0);
        }

        return attribute;
    }

    void appendNexthopObject(std::vector<char>& buffer, const std::vector<Attribute>& attributes, const unsigned char family = AF_INET6, const unsigned int sequence = SEQUENCE)
    {
        // struct nhmsg is 8 bytes.
        const size_t messageSize { 8 };
        auto length { NLMSG_LENGTH(messageSize) };

        for (const auto& attribute : attributes)
        {
            length = NLMSG_ALIGN(length) + RTA_LENGTH(attribute.payload.size());
        }

        const auto offset { buffer.size() };
        buffer.resize(offset + NLMSG_ALIGN(length), 0);

        auto header { reinterpret_cast<nlmsghdr*>(buffer.data() + offset) };
        header->nlmsg_len = length;
        header->nlmsg_type = NEW_NEXTHOP;
        header->nlmsg_flags = NLM_F_MULTI;
        header->nlmsg_seq = sequence;
        buffer[offset + NLMSG_LENGTH(0)] = static_cast<char>(family);

        auto position { NLMSG_LENGTH(messageSize) };

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

    bool parseNexthops(const std::vector<char>& buffer, IPv6Nexthops& nexthops)
    {
        return NetworkLinuxAddressResolver::parseNexthopMessages(buffer.data(), buffer.size(), SEQUENCE, nexthops);
    }

    std::vector<Attribute> singleNexthop(const unsigned int id, const unsigned int index, const std::string& gateway)
    {
        return { integerAttribute(NEXTHOP_ID, id), ipv6Attribute(NEXTHOP_GATEWAY, gateway), integerAttribute(NEXTHOP_OIF, index) };
    }
}

TEST(NetworkLinuxAddressResolverTest, RouteDumpTakesTheGatewayOfADefaultRoute)
{
    ASSERT_NE(0u, loopbackIndex());
    std::vector<char> buffer;
    appendRoute(buffer, { ipv6Attribute(RTA_GATEWAY, "fe80::1"), outputInterfaceAttribute(loopbackIndex()) });
    appendDone(buffer, 0);

    IPv6Gateways gateways;
    EXPECT_FALSE(parseRoutes(buffer, gateways));
    EXPECT_EQ((IPv6Gateways { { "lo", "fe80::1" } }), gateways);
}

TEST(NetworkLinuxAddressResolverTest, RouteDumpKeepsReadingUntilDone)
{
    std::vector<char> buffer;
    appendRoute(buffer, { ipv6Attribute(RTA_GATEWAY, "fe80::1"), outputInterfaceAttribute(loopbackIndex()) });

    IPv6Gateways gateways;
    EXPECT_TRUE(parseRoutes(buffer, gateways));
    EXPECT_EQ(1u, gateways.size());
}

TEST(NetworkLinuxAddressResolverTest, RouteDumpIgnoresADefaultRouteWithoutGateway)
{
    std::vector<char> buffer;
    appendRoute(buffer, { outputInterfaceAttribute(loopbackIndex()) });
    appendRoute(buffer, { ipv6Attribute(RTA_GATEWAY, "::"), outputInterfaceAttribute(loopbackIndex()) });

    IPv6Gateways gateways;
    parseRoutes(buffer, gateways);
    EXPECT_TRUE(gateways.empty());
}

TEST(NetworkLinuxAddressResolverTest, RouteDumpIgnoresRoutesThatAreNotPlainDefaults)
{
    const std::vector<Attribute> via { ipv6Attribute(RTA_GATEWAY, "fe80::1"), outputInterfaceAttribute(loopbackIndex()) };
    std::vector<char> buffer;

    RouteOptions prefix;
    prefix.destinationLength = 64;
    appendRoute(buffer, via, prefix);

    RouteOptions source;
    source.sourceLength = 64;
    appendRoute(buffer, via, source);

    RouteOptions unreachable;
    unreachable.type = RTN_UNREACHABLE;
    appendRoute(buffer, via, unreachable);

    RouteOptions cached;
    cached.flags = RTM_F_CLONED;
    appendRoute(buffer, via, cached);

    RouteOptions otherFamily;
    otherFamily.family = AF_INET;
    appendRoute(buffer, via, otherFamily);

    IPv6Gateways gateways;
    parseRoutes(buffer, gateways);
    EXPECT_TRUE(gateways.empty());
}

TEST(NetworkLinuxAddressResolverTest, RouteDumpTakesTheFirstGatewayOfEachInterface)
{
    std::vector<char> buffer;
    appendRoute(buffer, { ipv6Attribute(RTA_GATEWAY, "fe80::1"), outputInterfaceAttribute(loopbackIndex()) });
    appendRoute(buffer, { ipv6Attribute(RTA_GATEWAY, "fe80::2"), outputInterfaceAttribute(loopbackIndex()) });

    IPv6Gateways gateways;
    parseRoutes(buffer, gateways);
    EXPECT_EQ((IPv6Gateways { { "lo", "fe80::1" } }), gateways);
}

TEST(NetworkLinuxAddressResolverTest, RouteDumpTakesDefaultRoutesOfEveryTable)
{
    RouteOptions other;
    other.table = 100;
    std::vector<char> buffer;
    appendRoute(buffer, { ipv6Attribute(RTA_GATEWAY, "fe80::7"), outputInterfaceAttribute(loopbackIndex()) }, other);

    IPv6Gateways gateways;
    parseRoutes(buffer, gateways);
    EXPECT_EQ((IPv6Gateways { { "lo", "fe80::7" } }), gateways);
}

TEST(NetworkLinuxAddressResolverTest, RouteDumpIgnoresAnUnknownInterfaceIndex)
{
    std::vector<char> buffer;
    appendRoute(buffer, { ipv6Attribute(RTA_GATEWAY, "fe80::1"), outputInterfaceAttribute(0x7ffffff0) });

    IPv6Gateways gateways;
    parseRoutes(buffer, gateways);
    EXPECT_TRUE(gateways.empty());
}

TEST(NetworkLinuxAddressResolverTest, RouteDumpTakesTheGatewayOfEachMultipathNexthop)
{
    const auto other { otherInterface() };

    if (other.first.empty())
    {
        GTEST_SKIP() << "This host has a single interface";
    }

    std::vector<char> buffer;
    appendRoute(buffer, { multipathAttribute({ { other.second, "fe80::a" }, { loopbackIndex(), "fe80::b" } }) });

    IPv6Gateways gateways;
    parseRoutes(buffer, gateways);
    EXPECT_EQ((IPv6Gateways { { other.first, "fe80::a" }, { "lo", "fe80::b" } }), gateways);
}

TEST(NetworkLinuxAddressResolverTest, RouteDumpTakesTheFirstMultipathNexthopOfAnInterface)
{
    std::vector<char> buffer;
    appendRoute(buffer, { multipathAttribute({ { loopbackIndex(), "fe80::a" }, { loopbackIndex(), "fe80::b" } }) });

    IPv6Gateways gateways;
    parseRoutes(buffer, gateways);
    EXPECT_EQ((IPv6Gateways { { "lo", "fe80::a" } }), gateways);
}

TEST(NetworkLinuxAddressResolverTest, RouteDumpStopsAtTheEndOfTheMultipathAttribute)
{
    const auto other { otherInterface() };

    if (other.first.empty())
    {
        GTEST_SKIP() << "This host has a single interface";
    }

    // The next attribute is laid out like one more nexthop with a gateway on another interface.
    const auto gateway { ipv6Attribute(RTA_GATEWAY, "fe80::bad") };
    Attribute trailing { 200, {} };
    trailing.payload.resize(sizeof(int) + RTA_LENGTH(gateway.payload.size()), 0);
    const auto index { static_cast<int>(other.second) };
    std::memcpy(trailing.payload.data(), &index, sizeof(index));
    auto rta { reinterpret_cast<rtattr*>(trailing.payload.data() + sizeof(int)) };
    rta->rta_type = gateway.type;
    rta->rta_len = RTA_LENGTH(gateway.payload.size());
    std::copy(gateway.payload.begin(), gateway.payload.end(), static_cast<char*>(RTA_DATA(rta)));

    std::vector<char> buffer;
    appendRoute(buffer, { multipathAttribute({ { loopbackIndex(), "fe80::a" } }), trailing });

    IPv6Gateways gateways;
    parseRoutes(buffer, gateways);
    EXPECT_EQ((IPv6Gateways { { "lo", "fe80::a" } }), gateways);
}

TEST(NetworkLinuxAddressResolverTest, RouteDumpIgnoresMessagesOfAnotherSequence)
{
    RouteOptions foreign;
    foreign.sequence = SEQUENCE + 1;
    std::vector<char> buffer;
    appendRoute(buffer, { ipv6Attribute(RTA_GATEWAY, "fe80::1"), outputInterfaceAttribute(loopbackIndex()) }, foreign);

    IPv6Gateways gateways;
    EXPECT_TRUE(parseRoutes(buffer, gateways));
    EXPECT_TRUE(gateways.empty());
}

TEST(NetworkLinuxAddressResolverTest, RouteDumpFailsOnAnErrorAndOnAnInterruptedDump)
{
    std::vector<char> failed;
    appendDone(failed, -ENOBUFS);

    std::vector<char> interrupted;
    appendDone(interrupted, 0, NLM_F_MULTI | NLM_F_DUMP_INTR);

    IPv6Gateways gateways;
    EXPECT_THROW(parseRoutes(failed, gateways), std::runtime_error);
    EXPECT_THROW(parseRoutes(interrupted, gateways), NetlinkDumpInterrupted);
}

TEST(NetworkLinuxAddressResolverTest, RouteDumpRecordsARouteThatOnlyNamesANexthop)
{
    std::vector<char> buffer;
    appendRoute(buffer, { integerAttribute(ROUTE_NEXTHOP_ID, 7) });

    std::vector<IPv6Route> routes;
    parseRoutes(buffer, routes);

    ASSERT_EQ(1u, routes.size());
    EXPECT_EQ(7u, routes[0].nexthopId);
    EXPECT_TRUE(routes[0].gateway.empty());
}

TEST(NetworkLinuxAddressResolverTest, RouteDumpPrefersTheCompatAttributesOverTheNexthopId)
{
    const auto other { otherInterface() };

    if (other.first.empty())
    {
        GTEST_SKIP() << "This host has a single interface";
    }

    std::vector<char> buffer;
    appendRoute(buffer, { integerAttribute(ROUTE_NEXTHOP_ID, 7), ipv6Attribute(RTA_GATEWAY, "fe80::1"), outputInterfaceAttribute(loopbackIndex()) });
    appendRoute(buffer, { integerAttribute(ROUTE_NEXTHOP_ID, 8), multipathAttribute({ { other.second, "fe80::a" } }) });

    std::vector<IPv6Route> routes;
    parseRoutes(buffer, routes);

    ASSERT_EQ(2u, routes.size());
    EXPECT_EQ(7u, routes[0].nexthopId);
    EXPECT_EQ("fe80::1", routes[0].gateway);
    EXPECT_EQ(8u, routes[1].nexthopId);
    EXPECT_EQ("fe80::a", routes[1].gateway);
    EXPECT_FALSE(NetworkLinuxAddressResolver::hasPendingRoute(routes));
    EXPECT_TRUE(NetworkLinuxAddressResolver::usesNexthopObjects(routes));
}

TEST(NetworkLinuxAddressResolverTest, NexthopDumpParsesASingleIPv6Nexthop)
{
    std::vector<char> buffer;
    appendNexthopObject(buffer, singleNexthop(5, loopbackIndex(), "fe80::1"));
    appendDone(buffer, 0);

    IPv6Nexthops nexthops;
    EXPECT_FALSE(parseNexthops(buffer, nexthops));

    ASSERT_EQ(1u, nexthops.size());
    EXPECT_FALSE(nexthops.at(5).isGroup);
    EXPECT_EQ("lo", nexthops.at(5).link);
    EXPECT_EQ("fe80::1", nexthops.at(5).gateway);
}

TEST(NetworkLinuxAddressResolverTest, NexthopDumpParsesAGroupAsItsMemberIds)
{
    std::vector<char> buffer;
    appendNexthopObject(buffer, { integerAttribute(NEXTHOP_ID, 9), groupAttribute({ 5, 6 }) }, AF_UNSPEC);

    IPv6Nexthops nexthops;
    EXPECT_TRUE(parseNexthops(buffer, nexthops));

    ASSERT_EQ(1u, nexthops.size());
    EXPECT_TRUE(nexthops.at(9).isGroup);
    EXPECT_EQ((std::vector<uint32_t> { 5, 6 }), nexthops.at(9).members);
}

TEST(NetworkLinuxAddressResolverTest, NexthopDumpIgnoresBlackholeAndIPv4Nexthops)
{
    std::vector<char> buffer;
    appendNexthopObject(buffer, { integerAttribute(NEXTHOP_ID, 1), { NEXTHOP_BLACKHOLE, {} } }, AF_INET6);
    appendNexthopObject(buffer, { integerAttribute(NEXTHOP_ID, 2), ipv4Attribute(NEXTHOP_GATEWAY, "192.0.2.1"), integerAttribute(NEXTHOP_OIF, loopbackIndex()) }, AF_INET);
    appendNexthopObject(buffer, { integerAttribute(NEXTHOP_ID, 3), integerAttribute(NEXTHOP_OIF, loopbackIndex()) });

    IPv6Nexthops nexthops;
    parseNexthops(buffer, nexthops);
    EXPECT_TRUE(nexthops.empty());
}

TEST(NetworkLinuxAddressResolverTest, NexthopDumpBoundsATruncatedGroup)
{
    auto group { groupAttribute({ 5, 6 }) };
    group.payload.resize(group.payload.size() - 3);

    std::vector<char> buffer;
    appendNexthopObject(buffer, { integerAttribute(NEXTHOP_ID, 9), group }, AF_UNSPEC);

    IPv6Nexthops nexthops;
    parseNexthops(buffer, nexthops);

    ASSERT_EQ(1u, nexthops.size());
    EXPECT_EQ((std::vector<uint32_t> { 5 }), nexthops.at(9).members);
}

TEST(NetworkLinuxAddressResolverTest, NexthopDumpFailsOnAnErrorAndOnAnInterruptedDump)
{
    std::vector<char> failed;
    appendDone(failed, -ENOBUFS);

    std::vector<char> interrupted;
    appendDone(interrupted, 0, NLM_F_MULTI | NLM_F_DUMP_INTR);

    IPv6Nexthops nexthops;
    EXPECT_THROW(parseNexthops(failed, nexthops), std::runtime_error);
    EXPECT_THROW(parseNexthops(interrupted, nexthops), NetlinkDumpInterrupted);
}

TEST(NetworkLinuxAddressResolverTest, PendingRouteTakesTheGatewayOfASingleNexthop)
{
    std::vector<char> routesBuffer;
    appendRoute(routesBuffer, { integerAttribute(ROUTE_NEXTHOP_ID, 5) });
    std::vector<char> nexthopsBuffer;
    appendNexthopObject(nexthopsBuffer, singleNexthop(5, loopbackIndex(), "fe80::1"));

    std::vector<IPv6Route> routes;
    IPv6Nexthops nexthops;
    parseRoutes(routesBuffer, routes);
    parseNexthops(nexthopsBuffer, nexthops);

    EXPECT_EQ((IPv6Gateways { { "lo", "fe80::1" } }), NetworkLinuxAddressResolver::selectGateways(routes, nexthops));
}

TEST(NetworkLinuxAddressResolverTest, PendingRouteTakesTheGatewayOfEveryGroupMember)
{
    const auto other { otherInterface() };

    if (other.first.empty())
    {
        GTEST_SKIP() << "This host has a single interface";
    }

    std::vector<char> routesBuffer;
    appendRoute(routesBuffer, { integerAttribute(ROUTE_NEXTHOP_ID, 9) });
    std::vector<char> nexthopsBuffer;
    appendNexthopObject(nexthopsBuffer, singleNexthop(5, other.second, "fe80::a"));
    appendNexthopObject(nexthopsBuffer, singleNexthop(6, loopbackIndex(), "fe80::b"));
    appendNexthopObject(nexthopsBuffer, { integerAttribute(NEXTHOP_ID, 9), groupAttribute({ 5, 6 }) }, AF_UNSPEC);

    std::vector<IPv6Route> routes;
    IPv6Nexthops nexthops;
    parseRoutes(routesBuffer, routes);
    parseNexthops(nexthopsBuffer, nexthops);

    EXPECT_EQ((IPv6Gateways { { other.first, "fe80::a" }, { "lo", "fe80::b" } }), NetworkLinuxAddressResolver::selectGateways(routes, nexthops));
}

TEST(NetworkLinuxAddressResolverTest, PendingRoutesKeepTheFirstGatewayOfEachInterfaceInRouteOrder)
{
    std::vector<char> routesBuffer;
    appendRoute(routesBuffer, { integerAttribute(ROUTE_NEXTHOP_ID, 5) });
    appendRoute(routesBuffer, { ipv6Attribute(RTA_GATEWAY, "fe80::c"), outputInterfaceAttribute(loopbackIndex()) });
    appendRoute(routesBuffer, { integerAttribute(ROUTE_NEXTHOP_ID, 6) });
    std::vector<char> nexthopsBuffer;
    appendNexthopObject(nexthopsBuffer, singleNexthop(5, loopbackIndex(), "fe80::a"));
    appendNexthopObject(nexthopsBuffer, singleNexthop(6, loopbackIndex(), "fe80::b"));

    std::vector<IPv6Route> routes;
    IPv6Nexthops nexthops;
    parseRoutes(routesBuffer, routes);
    parseNexthops(nexthopsBuffer, nexthops);

    EXPECT_EQ((IPv6Gateways { { "lo", "fe80::a" } }), NetworkLinuxAddressResolver::selectGateways(routes, nexthops));
}

TEST(NetworkLinuxAddressResolverTest, PendingRouteResolvesOneGroupLevelAndIgnoresAnUnknownId)
{
    std::vector<char> routesBuffer;
    appendRoute(routesBuffer, { integerAttribute(ROUTE_NEXTHOP_ID, 99) });
    appendRoute(routesBuffer, { integerAttribute(ROUTE_NEXTHOP_ID, 10) });
    std::vector<char> nexthopsBuffer;
    appendNexthopObject(nexthopsBuffer, singleNexthop(5, loopbackIndex(), "fe80::a"));
    appendNexthopObject(nexthopsBuffer, { integerAttribute(NEXTHOP_ID, 9), groupAttribute({ 5 }) }, AF_UNSPEC);
    appendNexthopObject(nexthopsBuffer, { integerAttribute(NEXTHOP_ID, 10), groupAttribute({ 9, 77 }) }, AF_UNSPEC);

    std::vector<IPv6Route> routes;
    IPv6Nexthops nexthops;
    parseRoutes(routesBuffer, routes);
    parseNexthops(nexthopsBuffer, nexthops);

    EXPECT_TRUE(NetworkLinuxAddressResolver::selectGateways(routes, nexthops).empty());
}

TEST(NetworkLinuxAddressResolverTest, DumpIsSkippedWhenIPv6IsDisabled)
{
    // The marker path is a parameter, so the host does not need ipv6.disable=1.
    EXPECT_TRUE(NetworkLinuxAddressResolver::dumpIPv6DefaultGatewaysIfEnabled("/nonexistent/net/if_inet6").empty());
}
