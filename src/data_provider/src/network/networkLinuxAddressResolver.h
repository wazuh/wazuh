/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * October 29, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _NETWORK_LINUX_ADDRESS_RESOLVER_H
#define _NETWORK_LINUX_ADDRESS_RESOLVER_H

#include <cerrno>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include "stringHelper.h"
#include "networkHelper.h"

// The kernel flags a dump when the addresses change while it runs; it is worth asking again.
class NetlinkDumpInterrupted final : public std::runtime_error
{
    public:
        using std::runtime_error::runtime_error;
};

struct IPv4AddressRecord
{
    unsigned int index;
    std::string label;
    std::string address;
};

// (label reported by getifaddrs(), IPv4 address) -> links that hold it, in dump order.
using IPv4AddressLinks = std::map<std::pair<std::string, std::string>, std::vector<std::string>>;

// getifaddrs() names IPv4 addresses after their label, which can be any string, and does not
// expose the owning link. These helpers recover it from the kernel's RTM_GETADDR dump.
class NetworkLinuxAddressResolver final
{
        static constexpr unsigned int DUMP_SEQUENCE { 1 };
        static constexpr int DUMP_ATTEMPTS { 3 };

        class NetlinkSocket final
        {
                int m_fd;

            public:
                NetlinkSocket()
                    : m_fd{ socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE) }
                {
                    if (m_fd < 0)
                    {
                        throw std::runtime_error { "Cannot open netlink socket" };
                    }
                }

                ~NetlinkSocket()
                {
                    close(m_fd);
                }

                NetlinkSocket(const NetlinkSocket&) = delete;
                NetlinkSocket& operator=(const NetlinkSocket&) = delete;

                int fd() const
                {
                    return m_fd;
                }
        };

        static std::vector<IPv4AddressRecord> requestDump()
        {
            NetlinkSocket netlink;

            struct
            {
                nlmsghdr header;
                ifaddrmsg message;
            } request {};

            request.header.nlmsg_len = NLMSG_LENGTH(sizeof(ifaddrmsg));
            request.header.nlmsg_type = RTM_GETADDR;
            request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
            request.header.nlmsg_seq = DUMP_SEQUENCE;
            request.message.ifa_family = AF_INET;

            sockaddr_nl kernel {};
            kernel.nl_family = AF_NETLINK;

            if (sendto(netlink.fd(), &request, request.header.nlmsg_len, 0, reinterpret_cast<sockaddr*>(&kernel), sizeof(kernel)) < 0)
            {
                throw std::runtime_error { "Cannot request the netlink address dump" };
            }

            std::vector<IPv4AddressRecord> records;
            std::vector<char> buffer(32768);
            auto pending { true };

            while (pending)
            {
                sockaddr_nl sender {};
                socklen_t senderLength { sizeof(sender) };
                const auto received { recvfrom(netlink.fd(), buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&sender), &senderLength) };

                if (received < 0 && EINTR == errno)
                {
                    continue;
                }

                if (received <= 0)
                {
                    throw std::runtime_error { "Cannot read the netlink address dump" };
                }

                // Only the kernel answers the dump.
                if (0 != sender.nl_pid)
                {
                    continue;
                }

                pending = parseAddressMessages(buffer.data(), static_cast<size_t>(received), DUMP_SEQUENCE, records);
            }

            return records;
        }

    public:
        // Parses one buffer of an RTM_GETADDR reply. Returns false once the dump is complete.
        static bool parseAddressMessages(const void* buffer, const size_t length, const unsigned int sequence, std::vector<IPv4AddressRecord>& records)
        {
            auto remaining { static_cast<int>(length) };

            for (auto header { static_cast<const nlmsghdr*>(buffer) }; NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining))
            {
                if (sequence != header->nlmsg_seq)
                {
                    continue;
                }

                // The kernel can set the flag on any message of the dump, NLMSG_DONE included.
                if (header->nlmsg_flags & NLM_F_DUMP_INTR)
                {
                    throw NetlinkDumpInterrupted { "Netlink address dump interrupted" };
                }

                if (NLMSG_DONE == header->nlmsg_type)
                {
                    // NLMSG_DONE carries the dump's own result.
                    int result { 0 };

                    if (header->nlmsg_len >= NLMSG_LENGTH(sizeof(result)))
                    {
                        std::memcpy(&result, NLMSG_DATA(header), sizeof(result));
                    }

                    if (result < 0)
                    {
                        throw std::runtime_error { "Netlink address dump failed" };
                    }

                    return false;
                }

                if (NLMSG_ERROR == header->nlmsg_type)
                {
                    throw std::runtime_error { "Netlink address dump failed" };
                }

                if (RTM_NEWADDR != header->nlmsg_type || header->nlmsg_len < NLMSG_LENGTH(sizeof(ifaddrmsg)))
                {
                    continue;
                }

                const auto message { static_cast<const ifaddrmsg*>(NLMSG_DATA(header)) };

                if (AF_INET != message->ifa_family)
                {
                    continue;
                }

                IPv4AddressRecord record { message->ifa_index, "", "" };
                std::string localAddress;
                std::string peerAddress;
                auto attributesLength { static_cast<int>(IFA_PAYLOAD(header)) };

                for (auto attribute { IFA_RTA(message) }; RTA_OK(attribute, attributesLength); attribute = RTA_NEXT(attribute, attributesLength))
                {
                    const auto payloadLength { RTA_PAYLOAD(attribute) };

                    if (IFA_LOCAL == attribute->rta_type && payloadLength >= sizeof(in_addr))
                    {
                        localAddress = Utils::NetworkHelper::IAddressToBinary(AF_INET, RTA_DATA(attribute));
                    }
                    else if (IFA_ADDRESS == attribute->rta_type && payloadLength >= sizeof(in_addr))
                    {
                        peerAddress = Utils::NetworkHelper::IAddressToBinary(AF_INET, RTA_DATA(attribute));
                    }
                    else if (IFA_LABEL == attribute->rta_type && payloadLength > 0)
                    {
                        record.label = std::string { static_cast<const char*>(RTA_DATA(attribute)), strnlen(static_cast<const char*>(RTA_DATA(attribute)), payloadLength) };
                    }
                }

                // Same rule glibc uses to fill ifa_addr.
                record.address = localAddress.empty() ? peerAddress : localAddress;

                if (!record.address.empty())
                {
                    records.push_back(std::move(record));
                }
            }

            return true;
        }

        // Only an interrupted dump is retried; any other failure would fail again.
        static std::vector<IPv4AddressRecord> dumpIPv4Addresses()
        {
            for (auto attempt { 1 }; ; ++attempt)
            {
                try
                {
                    return requestDump();
                }
                catch (const NetlinkDumpInterrupted&)
                {
                    if (attempt >= DUMP_ATTEMPTS)
                    {
                        throw;
                    }
                }
            }
        }

        // Link names come from the AF_PACKET entries of the same getifaddrs() snapshot, so they
        // match the interfaces being reported. if_indextoname() covers a link without one. An address
        // whose link cannot be named keeps its slot with an empty name, so the entries after it that
        // share its label and address still get their own links.
        static IPv4AddressLinks resolveLinks(const std::vector<IPv4AddressRecord>& records, ifaddrs* addresses)
        {
            std::map<unsigned int, std::string> linkNames;

            for (auto ifa { addresses }; ifa; ifa = ifa->ifa_next)
            {
                if (ifa->ifa_name && ifa->ifa_addr && AF_PACKET == ifa->ifa_addr->sa_family)
                {
                    linkNames.emplace(reinterpret_cast<const sockaddr_ll*>(ifa->ifa_addr)->sll_ifindex, ifa->ifa_name);
                }
            }

            IPv4AddressLinks links;

            for (const auto& record : records)
            {
                auto it { linkNames.find(record.index) };

                if (linkNames.end() == it)
                {
                    char linkName[IF_NAMESIZE] {};

                    if (if_indextoname(record.index, linkName))
                    {
                        it = linkNames.emplace(record.index, linkName).first;
                    }
                }

                const auto linkName { linkNames.end() == it ? std::string {} : it->second };
                // Without IFA_LABEL, getifaddrs() names the address after its link.
                const auto label { record.label.empty() ? linkName : record.label };

                if (!label.empty())
                {
                    links[std::make_pair(label, record.address)].push_back(linkName);
                }
            }

            return links;
        }

        // Regroups the entries kept by NetworkUnixHelper::getNetworks() by the link that holds them,
        // in getifaddrs() order. Entries not found in links, or whose link is unnamed, keep the name
        // cut at the first ':'.
        // getifaddrs() and the dump list the addresses in the same kernel order, so entries that share
        // a label and an address take their links in turn.
        static std::map<std::string, std::vector<ifaddrs*>> groupByLink(ifaddrs* addresses,
                                                                        const std::map<std::string, std::vector<ifaddrs*>>& networkInterfaces,
                                                                        const IPv4AddressLinks& links)
        {
            std::set<const ifaddrs*> selected;

            for (const auto& interface : networkInterfaces)
            {
                selected.insert(interface.second.begin(), interface.second.end());
            }

            std::map<std::pair<std::string, std::string>, size_t> consumed;
            std::map<std::string, std::vector<ifaddrs*>> groups;

            for (auto ifa { addresses }; ifa; ifa = ifa->ifa_next)
            {
                const auto isSelected { selected.find(ifa) != selected.end() };
                std::string linkName { isSelected ? Utils::substrOnFirstOccurrence(ifa->ifa_name, ":") : "" };

                if (ifa->ifa_name && ifa->ifa_addr && AF_INET == ifa->ifa_addr->sa_family)
                {
                    const auto key { std::make_pair(std::string { ifa->ifa_name },
                                                    Utils::NetworkHelper::IAddressToBinary(AF_INET, &reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr)->sin_addr)) };
                    const auto it { links.find(key) };
                    // Counted for unselected entries too, so the positions stay aligned with the dump.
                    const auto position { consumed[key]++ };

                    if (links.end() != it && position < it->second.size() && !it->second[position].empty())
                    {
                        linkName = it->second[position];
                    }
                }

                if (isSelected)
                {
                    groups[linkName].push_back(ifa);
                }
            }

            return groups;
        }
};

#endif // _NETWORK_LINUX_ADDRESS_RESOLVER_H
