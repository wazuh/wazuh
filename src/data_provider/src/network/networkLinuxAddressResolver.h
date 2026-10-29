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

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
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

struct IPv4AddressRecord
{
    unsigned int index;
    std::string label;
    std::string address;
};

// (label reported by getifaddrs(), IPv4 address) -> name of the link that holds the address.
using IPv4AddressLinks = std::map<std::pair<std::string, std::string>, std::string>;

// getifaddrs() names IPv4 addresses after their label, which can be any string, and does not
// expose the owning link. These helpers recover it from the kernel's RTM_GETADDR dump.
class NetworkLinuxAddressResolver final
{
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

        static std::string ipv4ToString(const void* address)
        {
            char buffer[INET_ADDRSTRLEN] {};
            return inet_ntop(AF_INET, address, buffer, sizeof(buffer)) ? buffer : "";
        }

    public:
        // Parses one buffer of an RTM_GETADDR reply. Returns false once the dump is complete.
        static bool parseAddressMessages(const void* buffer, const size_t length, std::vector<IPv4AddressRecord>& records)
        {
            auto remaining { static_cast<int>(length) };

            for (auto header { static_cast<const nlmsghdr*>(buffer) }; NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining))
            {
                if (NLMSG_DONE == header->nlmsg_type)
                {
                    return false;
                }

                if (NLMSG_ERROR == header->nlmsg_type)
                {
                    throw std::runtime_error { "Netlink address dump failed" };
                }

                if (header->nlmsg_flags & NLM_F_DUMP_INTR)
                {
                    throw std::runtime_error { "Netlink address dump interrupted" };
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
                        localAddress = ipv4ToString(RTA_DATA(attribute));
                    }
                    else if (IFA_ADDRESS == attribute->rta_type && payloadLength >= sizeof(in_addr))
                    {
                        peerAddress = ipv4ToString(RTA_DATA(attribute));
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

        static IPv4AddressLinks getIPv4AddressLinks()
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
            request.header.nlmsg_seq = 1;
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
                const auto received { recv(netlink.fd(), buffer.data(), buffer.size(), 0) };

                if (received <= 0)
                {
                    throw std::runtime_error { "Cannot read the netlink address dump" };
                }

                pending = parseAddressMessages(buffer.data(), static_cast<size_t>(received), records);
            }

            IPv4AddressLinks links;

            for (const auto& record : records)
            {
                char linkName[IF_NAMESIZE] {};

                if (if_indextoname(record.index, linkName))
                {
                    // Without IFA_LABEL, getifaddrs() names the address after its link.
                    const auto label { record.label.empty() ? std::string { linkName } : record.label };
                    links.emplace(std::make_pair(label, record.address), linkName);
                }
            }

            return links;
        }

        // Regroups the entries kept by NetworkUnixHelper::getNetworks() by the link that holds them,
        // in getifaddrs() order. Entries not found in links keep the name cut at the first ':'.
        static std::map<std::string, std::vector<ifaddrs*>> groupByLink(ifaddrs* addresses,
                                                                        const std::map<std::string, std::vector<ifaddrs*>>& networkInterfaces,
                                                                        const IPv4AddressLinks& links)
        {
            std::set<const ifaddrs*> selected;

            for (const auto& interface : networkInterfaces)
            {
                selected.insert(interface.second.begin(), interface.second.end());
            }

            std::map<std::string, std::vector<ifaddrs*>> groups;

            for (auto ifa { addresses }; ifa; ifa = ifa->ifa_next)
            {
                if (selected.find(ifa) == selected.end())
                {
                    continue;
                }

                auto linkName { Utils::substrOnFirstOccurrence(ifa->ifa_name, ":") };

                if (ifa->ifa_addr && AF_INET == ifa->ifa_addr->sa_family)
                {
                    const auto address { ipv4ToString(&reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr)->sin_addr) };
                    const auto it { links.find(std::make_pair(std::string { ifa->ifa_name }, address)) };

                    if (links.end() != it)
                    {
                        linkName = it->second;
                    }
                }

                groups[linkName].push_back(ifa);
            }

            return groups;
        }
};

#endif // _NETWORK_LINUX_ADDRESS_RESOLVER_H
