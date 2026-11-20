/*
 * Wazuh SYSINFO
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _NETWORK_LINUX_ADDRESS_RESOLVER_H
#define _NETWORK_LINUX_ADDRESS_RESOLVER_H

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <filesystem>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>
#include "stringHelper.h"
#include "networkHelper.h"

// Missing from older kernel headers; kernels that predate it never set it.
#ifndef NLM_F_DUMP_INTR
#define NLM_F_DUMP_INTR 0x10
#endif

// Absent from kernel headers older than 2.6.
#ifndef RTA_MULTIPATH
#define RTA_MULTIPATH 9
#endif

// RTM_F_CLONED marks the cached routes; absent from headers that predate the route cache split.
#ifndef RTM_F_CLONED
#define RTM_F_CLONED 0x200
#endif

// IFA_FLAGS is an enum value, absent from kernel headers older than 3.14
#ifndef IFA_FLAGS
#define IFA_FLAGS 8
#endif

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
    // IFA_FLAGS when the kernel sends it, else the 8-bit ifa_flags.
    uint32_t flags { 0 };
    unsigned int prefixLength { 0 };
};

// (label reported by getifaddrs(), IPv4 address) -> links that hold it, in dump order.
using IPv4AddressLinks = std::map<std::pair<std::string, std::string>, std::vector<std::string>>;

// (link name, IPv4 address, prefix length) -> IFA_F_* flags of that address. One link can hold the
// same address twice with different prefixes, each with its own flags.
using IPv4AddressKey = std::tuple<std::string, std::string, unsigned int>;
using IPv4AddressFlags = std::map<IPv4AddressKey, uint32_t>;

// Interface name -> IPv6 default gateway, read once per listing.
using IPv6Gateways = std::map<std::string, std::string>;

// One ::/0 route of the dump, in dump order. nexthopId is set when the route names a nexthop object
// (RTA_NH_ID); a route that only names it has no interface or gateway until the nexthop dump resolves it.
struct IPv6Route
{
    std::string link;
    std::string gateway;
    uint32_t nexthopId { 0 };
};

// Nexthop object of the RTM_GETNEXTHOP dump: either one IPv6 gateway on one interface, or a group of
// other nexthop ids.
struct IPv6Nexthop
{
    std::string link;
    std::string gateway;
    std::vector<uint32_t> members;
    bool isGroup { false };
};

using IPv6Nexthops = std::map<uint32_t, IPv6Nexthop>;

// getifaddrs() names IPv4 addresses after their label, which can be any string, and does not
// expose the owning link. These helpers recover it from the kernel's RTM_GETADDR dump.
class NetworkLinuxAddressResolver final
{
        static constexpr unsigned int DUMP_SEQUENCE { 1 };
        static constexpr int DUMP_ATTEMPTS { 3 };
        static constexpr const char* IF_INET6_PATH { "/proc/net/if_inet6" };

        // Kernel headers older than 5.3 lack the nexthop objects: these are the values and the exact layouts of
        // RTA_NH_ID, RTM_NEWNEXTHOP, RTM_GETNEXTHOP, struct nhmsg, the NHA_* attributes and struct nexthop_grp.
        static constexpr unsigned short ROUTE_ATTRIBUTE_NH_ID { 30 };
        static constexpr unsigned short MESSAGE_NEW_NEXTHOP { 104 };
        static constexpr unsigned short MESSAGE_GET_NEXTHOP { 106 };
        static constexpr unsigned short NEXTHOP_ATTRIBUTE_ID { 1 };
        static constexpr unsigned short NEXTHOP_ATTRIBUTE_GROUP { 2 };
        static constexpr unsigned short NEXTHOP_ATTRIBUTE_BLACKHOLE { 4 };
        static constexpr unsigned short NEXTHOP_ATTRIBUTE_OIF { 5 };
        static constexpr unsigned short NEXTHOP_ATTRIBUTE_GATEWAY { 6 };

        struct NexthopMessage
        {
            unsigned char family;
            unsigned char scope;
            unsigned char protocol;
            unsigned char reserved;
            uint32_t flags;
        };

        struct NexthopGroupEntry
        {
            uint32_t id;
            unsigned char weight;
            unsigned char reserved1;
            unsigned short reserved2;
        };

        static_assert(8 == sizeof(NexthopMessage), "NexthopMessage must match struct nhmsg");
        static_assert(8 == sizeof(NexthopGroupEntry), "NexthopGroupEntry must match struct nexthop_grp");

        class NetlinkSocket final
        {
                int m_fd;

#ifdef SOCK_CLOEXEC
                static constexpr int CLOEXEC_FLAG { SOCK_CLOEXEC };
#else
                static constexpr int CLOEXEC_FLAG { 0 };
#endif

            public:
                NetlinkSocket()
                    : m_fd{ socket(AF_NETLINK, SOCK_RAW | CLOEXEC_FLAG, NETLINK_ROUTE) }
                {
                    if (m_fd < 0)
                    {
                        throw std::runtime_error { "Cannot open netlink socket" };
                    }

#ifndef SOCK_CLOEXEC
                    fcntl(m_fd, F_SETFD, FD_CLOEXEC);
#endif
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

        template<typename Dump>
        static auto retryInterrupted(Dump dump) -> decltype(dump())
        {
            for (auto attempt { 1 }; ; ++attempt)
            {
                try
                {
                    return dump();
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

        template<typename Parser>
        static void readDump(const NetlinkSocket& netlink, const char* failure, Parser parse)
        {
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
                    throw std::runtime_error { failure };
                }

                // Only the kernel answers the dump.
                if (0 != sender.nl_pid)
                {
                    continue;
                }

                pending = parse(buffer.data(), static_cast<size_t>(received));
            }
        }

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
            readDump(netlink, "Cannot read the netlink address dump", [&records](const void* data, const size_t length)
            {
                return parseAddressMessages(data, length, DUMP_SEQUENCE, records);
            });

            return records;
        }

        static std::vector<IPv6Route> requestRoutes()
        {
            NetlinkSocket netlink;

            struct
            {
                nlmsghdr header;
                rtmsg message;
            } request {};

            request.header.nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
            request.header.nlmsg_type = RTM_GETROUTE;
            request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
            request.header.nlmsg_seq = DUMP_SEQUENCE;
            request.message.rtm_family = AF_INET6;

            sockaddr_nl kernel {};
            kernel.nl_family = AF_NETLINK;

            if (sendto(netlink.fd(), &request, request.header.nlmsg_len, 0, reinterpret_cast<sockaddr*>(&kernel), sizeof(kernel)) < 0)
            {
                throw std::runtime_error { "Cannot request the netlink route dump" };
            }

            std::vector<IPv6Route> routes;
            readDump(netlink, "Cannot read the netlink route dump", [&routes](const void* data, const size_t length)
            {
                return parseRouteMessages(data, length, DUMP_SEQUENCE, routes);
            });

            return routes;
        }

        static IPv6Gateways requestRouteDump()
        {
            const auto routes { requestRoutes() };

            const auto nexthops { hasPendingRoute(routes) ? requestNexthopDump() : IPv6Nexthops {} };

            return selectGateways(routes, nexthops);
        }

        static IPv6Nexthops requestNexthopDump()
        {
            NetlinkSocket netlink;

            struct
            {
                nlmsghdr header;
                NexthopMessage message;
            } request {};

            request.header.nlmsg_len = NLMSG_LENGTH(sizeof(NexthopMessage));
            request.header.nlmsg_type = MESSAGE_GET_NEXTHOP;
            request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
            request.header.nlmsg_seq = DUMP_SEQUENCE;
            request.message.family = AF_UNSPEC;

            sockaddr_nl kernel {};
            kernel.nl_family = AF_NETLINK;

            if (sendto(netlink.fd(), &request, request.header.nlmsg_len, 0, reinterpret_cast<sockaddr*>(&kernel), sizeof(kernel)) < 0)
            {
                throw std::runtime_error { "Cannot request the netlink nexthop dump" };
            }

            IPv6Nexthops nexthops;
            readDump(netlink, "Cannot read the netlink nexthop dump", [&nexthops](const void* data, const size_t length)
            {
                return parseNexthopMessages(data, length, DUMP_SEQUENCE, nexthops);
            });

            return nexthops;
        }

        static bool isDumpDone(const nlmsghdr* header, const char* failure)
        {
            // The kernel can set the flag on any message of the dump, NLMSG_DONE included.
            if (header->nlmsg_flags & NLM_F_DUMP_INTR)
            {
                throw NetlinkDumpInterrupted { failure };
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
                    throw std::runtime_error { failure };
                }

                return true;
            }

            if (NLMSG_ERROR == header->nlmsg_type)
            {
                throw std::runtime_error { failure };
            }

            return false;
        }

        // Names the gateway's link. Returns false for the same all-zero gateway the /proc table lists for the
        // routes that are not via a router, and for a link without a name.
        static bool nameGateway(const unsigned int index, const void* gateway, std::string& link, std::string& address)
        {
            const in6_addr any {};
            char linkName[IF_NAMESIZE] {};

            if (0 == std::memcmp(gateway, &any, sizeof(any)) || !if_indextoname(index, linkName))
            {
                return false;
            }

            link = linkName;
            address = Utils::NetworkHelper::IAddressToBinary(AF_INET6, gateway);
            return true;
        }

        static void addRoute(std::vector<IPv6Route>& routes, const unsigned int index, const void* gateway, const uint32_t nexthopId)
        {
            IPv6Route route;
            route.nexthopId = nexthopId;

            if (nameGateway(index, gateway, route.link, route.gateway))
            {
                routes.push_back(std::move(route));
            }
        }

        // A group adds nothing itself; the caller expands its members. Returns nullptr for an unknown id.
        static const IPv6Nexthop* addNexthopGateway(IPv6Gateways& gateways, const IPv6Nexthops& nexthops, const uint32_t id)
        {
            const auto it { nexthops.find(id) };

            if (nexthops.end() == it)
            {
                return nullptr;
            }

            if (!it->second.isGroup)
            {
                gateways.emplace(it->second.link, it->second.gateway);
            }

            return &it->second;
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

                if (isDumpDone(header, "Netlink address dump failed"))
                {
                    return false;
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

                IPv4AddressRecord record { message->ifa_index, "", "", message->ifa_flags, message->ifa_prefixlen };
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
                    else if (IFA_FLAGS == attribute->rta_type && payloadLength >= sizeof(record.flags))
                    {
                        std::memcpy(&record.flags, RTA_DATA(attribute), sizeof(record.flags));
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

        // Appends, in dump order, the routes /proc/net/ipv6_route lists with RTF_UP|RTF_GATEWAY and ::/0 (any table, unicast,
        // not cached, one route per ECMP nexthop). With net.ipv4.nexthop_compat_mode=0 a route through a nexthop object carries
        // only RTA_NH_ID, so it is appended with that id and no gateway. Returns false on NLMSG_DONE.
        static bool parseRouteMessages(const void* buffer, const size_t length, const unsigned int sequence, std::vector<IPv6Route>& routes)
        {
            auto remaining { static_cast<int>(length) };

            for (auto header { static_cast<const nlmsghdr*>(buffer) }; NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining))
            {
                if (sequence != header->nlmsg_seq)
                {
                    continue;
                }

                if (isDumpDone(header, "Netlink route dump failed"))
                {
                    return false;
                }

                if (RTM_NEWROUTE != header->nlmsg_type || header->nlmsg_len < NLMSG_LENGTH(sizeof(rtmsg)))
                {
                    continue;
                }

                const auto message { static_cast<const rtmsg*>(NLMSG_DATA(header)) };

                if (AF_INET6 != message->rtm_family || 0 != message->rtm_dst_len || 0 != message->rtm_src_len ||
                        RTN_UNICAST != message->rtm_type || (message->rtm_flags & RTM_F_CLONED))
                {
                    continue;
                }

                unsigned int index { 0 };
                const void* gateway { nullptr };
                const rtattr* multipath { nullptr };
                uint32_t nexthopId { 0 };
                auto attributesLength { static_cast<int>(RTM_PAYLOAD(header)) };

                for (auto attribute { RTM_RTA(message) }; RTA_OK(attribute, attributesLength); attribute = RTA_NEXT(attribute, attributesLength))
                {
                    const auto payloadLength { RTA_PAYLOAD(attribute) };

                    if (RTA_OIF == attribute->rta_type && payloadLength >= sizeof(index))
                    {
                        std::memcpy(&index, RTA_DATA(attribute), sizeof(index));
                    }
                    else if (RTA_GATEWAY == attribute->rta_type && payloadLength >= sizeof(in6_addr))
                    {
                        gateway = RTA_DATA(attribute);
                    }
                    else if (RTA_MULTIPATH == attribute->rta_type)
                    {
                        multipath = attribute;
                    }
                    else if (ROUTE_ATTRIBUTE_NH_ID == attribute->rta_type && payloadLength >= sizeof(nexthopId))
                    {
                        std::memcpy(&nexthopId, RTA_DATA(attribute), sizeof(nexthopId));
                    }
                }

                if (!multipath)
                {
                    if (gateway)
                    {
                        addRoute(routes, index, gateway, nexthopId);
                    }
                    else if (0 != nexthopId)
                    {
                        routes.push_back({ "", "", nexthopId });
                    }

                    continue;
                }

                auto nexthopsLength { static_cast<int>(RTA_PAYLOAD(multipath)) };

                auto nexthop { static_cast<const rtnexthop*>(RTA_DATA(multipath)) };

                while (nexthopsLength >= static_cast<int>(sizeof(rtnexthop)) && RTNH_OK(nexthop, nexthopsLength))
                {
                    auto nexthopAttributesLength { static_cast<int>(nexthop->rtnh_len) - static_cast<int>(RTNH_LENGTH(0)) };

                    for (auto attribute { RTNH_DATA(nexthop) }; RTA_OK(attribute, nexthopAttributesLength);
                            attribute = RTA_NEXT(attribute, nexthopAttributesLength))
                    {
                        if (RTA_GATEWAY == attribute->rta_type && RTA_PAYLOAD(attribute) >= sizeof(in6_addr))
                        {
                            addRoute(routes, static_cast<unsigned int>(nexthop->rtnh_ifindex), RTA_DATA(attribute), nexthopId);
                        }
                    }

                    nexthopsLength -= static_cast<int>(RTNH_ALIGN(nexthop->rtnh_len));
                    nexthop = RTNH_NEXT(nexthop);
                }
            }

            return true;
        }

        // Blackhole, IPv4 and gateway-less nexthops cannot be a default gateway, so they are dropped. Returns false on NLMSG_DONE.
        static bool parseNexthopMessages(const void* buffer, const size_t length, const unsigned int sequence, IPv6Nexthops& nexthops)
        {
            auto remaining { static_cast<int>(length) };

            for (auto header { static_cast<const nlmsghdr*>(buffer) }; NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining))
            {
                if (sequence != header->nlmsg_seq)
                {
                    continue;
                }

                if (isDumpDone(header, "Netlink nexthop dump failed"))
                {
                    return false;
                }

                if (MESSAGE_NEW_NEXTHOP != header->nlmsg_type || header->nlmsg_len < NLMSG_LENGTH(sizeof(NexthopMessage)))
                {
                    continue;
                }

                const auto message { static_cast<const NexthopMessage*>(NLMSG_DATA(header)) };
                auto attribute { reinterpret_cast<const rtattr*>(reinterpret_cast<const char*>(message) + NLMSG_ALIGN(sizeof(NexthopMessage))) };
                auto attributesLength { static_cast<int>(NLMSG_PAYLOAD(header, sizeof(NexthopMessage))) };

                uint32_t id { 0 };
                uint32_t index { 0 };
                const void* gateway { nullptr };
                const rtattr* group { nullptr };
                auto blackhole { false };

                while (RTA_OK(attribute, attributesLength))
                {
                    const auto payloadLength { RTA_PAYLOAD(attribute) };

                    if (NEXTHOP_ATTRIBUTE_ID == attribute->rta_type && payloadLength >= sizeof(id))
                    {
                        std::memcpy(&id, RTA_DATA(attribute), sizeof(id));
                    }
                    else if (NEXTHOP_ATTRIBUTE_OIF == attribute->rta_type && payloadLength >= sizeof(index))
                    {
                        std::memcpy(&index, RTA_DATA(attribute), sizeof(index));
                    }
                    else if (NEXTHOP_ATTRIBUTE_GATEWAY == attribute->rta_type && AF_INET6 == message->family && payloadLength >= sizeof(in6_addr))
                    {
                        gateway = RTA_DATA(attribute);
                    }
                    else if (NEXTHOP_ATTRIBUTE_GROUP == attribute->rta_type)
                    {
                        group = attribute;
                    }
                    else if (NEXTHOP_ATTRIBUTE_BLACKHOLE == attribute->rta_type)
                    {
                        blackhole = true;
                    }

                    attribute = RTA_NEXT(attribute, attributesLength);
                }

                if (0 == id || blackhole)
                {
                    continue;
                }

                IPv6Nexthop nexthop;

                if (group)
                {
                    nexthop.isGroup = true;
                    const auto count { RTA_PAYLOAD(group) / sizeof(NexthopGroupEntry) };

                    for (size_t position { 0 }; position < count; ++position)
                    {
                        NexthopGroupEntry entry {};
                        std::memcpy(&entry, static_cast<const char*>(RTA_DATA(group)) + position * sizeof(entry), sizeof(entry));
                        nexthop.members.push_back(entry.id);
                    }
                }
                else if (!gateway || !nameGateway(index, gateway, nexthop.link, nexthop.gateway))
                {
                    continue;
                }

                nexthops.emplace(id, std::move(nexthop));
            }

            return true;
        }

        // Keeps the first gateway of each interface, in route order. A route through a nexthop object takes the gateway
        // of that nexthop, or of every member of its group (one level: a member that is a group adds nothing). An id
        // the dump does not list adds nothing.
        static IPv6Gateways selectGateways(const std::vector<IPv6Route>& routes, const IPv6Nexthops& nexthops)
        {
            IPv6Gateways gateways;

            for (const auto& route : routes)
            {
                if (!route.gateway.empty())
                {
                    gateways.emplace(route.link, route.gateway);
                    continue;
                }

                const auto nexthop { addNexthopGateway(gateways, nexthops, route.nexthopId) };

                for (size_t position { 0 }; nexthop && position < nexthop->members.size(); ++position)
                {
                    addNexthopGateway(gateways, nexthops, nexthop->members[position]);
                }
            }

            return gateways;
        }

        // Only an interrupted dump is retried; any other failure would fail again.
        static std::vector<IPv4AddressRecord> dumpIPv4Addresses()
        {
            return retryInterrupted(requestDump);
        }

        // The kernel walks the tables in /proc/net/ipv6_route order, so the first route of an interface is the same one.
        // Differs from /proc only for a default route through a nexthop group: every member is reported, /proc lists the first.
        static IPv6Gateways dumpIPv6DefaultGateways()
        {
            return dumpIPv6DefaultGatewaysIfEnabled(IF_INET6_PATH);
        }

        static bool hasPendingRoute(const std::vector<IPv6Route>& routes)
        {
            return std::any_of(routes.begin(), routes.end(), [](const IPv6Route & route)
            {
                return route.gateway.empty() && 0 != route.nexthopId;
            });
        }

        // True when a route goes through a nexthop object, whether or not the kernel also lists its gateways inline.
        static bool usesNexthopObjects(const std::vector<IPv6Route>& routes)
        {
            return std::any_of(routes.begin(), routes.end(), [](const IPv6Route & route)
            {
                return 0 != route.nexthopId;
            });
        }

        // Unresolved ::/0 routes; used by the tests to detect a host that routes through nexthop objects.
        static std::vector<IPv6Route> dumpIPv6Routes()
        {
            return retryInterrupted(requestRoutes);
        }

        // With ipv6.disable=1 the kernel has no AF_INET6 handler and answers an AF_INET6 route dump with every family, so
        // without /proc/net/if_inet6 there is nothing to ask.
        static IPv6Gateways dumpIPv6DefaultGatewaysIfEnabled(const std::string& interfacesPath)
        {
            std::error_code ec;

            if (!std::filesystem::is_regular_file(interfacesPath, ec))
            {
                return {};
            }

            return retryInterrupted(requestRouteDump);
        }

        // Link names come from the AF_PACKET entries of the same getifaddrs() snapshot, so they
        // match the interfaces being reported. if_indextoname() covers a link without one. An address
        // whose link cannot be named keeps its slot with an empty name, so the entries after it that
        // share its label and address still get their own links.
        // When flags is given, it receives the flags of every address whose link has a name.
        static IPv4AddressLinks resolveLinks(const std::vector<IPv4AddressRecord>& records, ifaddrs* addresses, IPv4AddressFlags* flags = nullptr)
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

                static const std::string NO_LINK_NAME;
                const auto& linkName { linkNames.end() == it ? NO_LINK_NAME : it->second };
                // Without IFA_LABEL, getifaddrs() names the address after its link.
                const auto& label { record.label.empty() ? linkName : record.label };

                if (!label.empty())
                {
                    links[std::make_pair(label, record.address)].push_back(linkName);
                }

                if (flags && !linkName.empty())
                {
                    flags->emplace(IPv4AddressKey { linkName, record.address, record.prefixLength }, record.flags);
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
