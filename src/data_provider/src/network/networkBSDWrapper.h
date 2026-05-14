/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * October 26, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _NETWORK_BSD_WRAPPER_H
#define _NETWORK_BSD_WRAPPER_H

#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <sstream>
#include <iomanip>
#include <net/route.h>
#include <sys/sysctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "inetworkWrapper.h"
#include "networkHelper.h"
#include "makeUnique.h"
#include "sharedDefs.h"
#include "stringHelper.h"

static const std::map<std::pair<int, int>, std::string> NETWORK_INTERFACE_TYPE =
{
    { std::make_pair(IFT_ETHER, IFT_ETHER),                     "ethernet"       },
    { std::make_pair(IFT_ISO88023, IFT_ISO88023),               "CSMA/CD"        },
    { std::make_pair(IFT_ISO88024, IFT_ISO88025),               "token ring"     },
    { std::make_pair(IFT_FDDI, IFT_FDDI),                       "FDDI"           },
    { std::make_pair(IFT_PPP, IFT_PPP),                         "point-to-point" },
    { std::make_pair(IFT_ATM, IFT_ATM),                         "ATM"            },
};

class NetworkBSDInterface final : public INetworkInterfaceWrapper
{
        ifaddrs* m_interfaceAddress;
        const std::string m_scanTime;

    public:
        explicit NetworkBSDInterface(ifaddrs* addrs)
            : m_interfaceAddress{addrs}
        {
            if (!addrs)
            {
                throw std::runtime_error { "Nullptr instances of network interface" };
            }
        }

        std::string name() const override
        {
            return m_interfaceAddress->ifa_name ? Utils::substrOnFirstOccurrence(m_interfaceAddress->ifa_name, ":") : "";
        }

        std::string adapter() const override
        {
            return "";
        }

        int family() const override
        {
            return m_interfaceAddress->ifa_addr ? m_interfaceAddress->ifa_addr->sa_family : AF_UNSPEC;
        }

        std::string address() const override
        {
            return m_interfaceAddress->ifa_addr ?
                   Utils::NetworkHelper::IAddressToBinary(
                       this->family(),
                       &(reinterpret_cast<sockaddr_in*>(m_interfaceAddress->ifa_addr))->sin_addr) : "";
        }

        std::string netmask() const override
        {
            return m_interfaceAddress->ifa_netmask ?
                   Utils::NetworkHelper::IAddressToBinary(
                       m_interfaceAddress->ifa_netmask->sa_family,
                       &(reinterpret_cast<sockaddr_in*>(m_interfaceAddress->ifa_netmask))->sin_addr) : "";
        }

        std::string broadcast() const override
        {
            return m_interfaceAddress->ifa_dstaddr ?
                   Utils::NetworkHelper::IAddressToBinary(
                       m_interfaceAddress->ifa_dstaddr->sa_family,
                       &(reinterpret_cast<sockaddr_in*>(m_interfaceAddress->ifa_dstaddr))->sin_addr) : "";
        }

        std::string addressV6() const override
        {
            return m_interfaceAddress->ifa_addr ?
                   Utils::NetworkHelper::IAddressToBinary(
                       m_interfaceAddress->ifa_addr->sa_family,
                       &(reinterpret_cast<sockaddr_in6*>(m_interfaceAddress->ifa_addr))->sin6_addr) : "";
        }

        std::string netmaskV6() const override
        {
            return m_interfaceAddress->ifa_netmask ?
                   Utils::NetworkHelper::IAddressToBinary(
                       m_interfaceAddress->ifa_netmask->sa_family,
                       &(reinterpret_cast<sockaddr_in6*>(m_interfaceAddress->ifa_netmask))->sin6_addr) : "";
        }

        std::string broadcastV6() const override
        {
            return m_interfaceAddress->ifa_dstaddr ?
                   Utils::NetworkHelper::IAddressToBinary(
                       m_interfaceAddress->ifa_dstaddr->sa_family,
                       &(reinterpret_cast<sockaddr_in6*>(m_interfaceAddress->ifa_dstaddr))->sin6_addr) : "";
        }

        std::string gateway() const override
        {
            std::string retVal;
            size_t tableSize { 0 };
            int mib[] = { CTL_NET, AF_ROUTE, 0, AF_UNSPEC, NET_RT_FLAGS, RTF_UP | RTF_GATEWAY };

            if (sysctl(mib, sizeof(mib) / sizeof(int), nullptr, &tableSize, nullptr, 0) == 0)
            {
                std::unique_ptr<char[]> table { std::make_unique<char[]>(tableSize) };

                if (sysctl(mib, sizeof(mib) / sizeof(int), table.get(), &tableSize, nullptr, 0) == 0)
                {
                    size_t messageLength { 0 };

                    for (char* p = table.get(); p < table.get() + tableSize; p += messageLength)
                    {
                        auto msg { reinterpret_cast<rt_msghdr*>(p) };
                        auto sa { reinterpret_cast<sockaddr*>(msg + 1) };
                        auto sdl { reinterpret_cast<sockaddr_dl*>(m_interfaceAddress->ifa_addr) };

                        if (sdl &&
                                (msg->rtm_addrs & RTA_GATEWAY) == RTA_GATEWAY &&
                                msg->rtm_index == sdl->sdl_index)
                        {
                            auto sock { reinterpret_cast<sockaddr*>(reinterpret_cast<char*>(sa) + ROUNDUP(sa->sa_len)) };

                            if (sock && AF_INET == sock->sa_family)
                            {
                                retVal = Utils::NetworkHelper::IAddressToBinary(AF_INET, &reinterpret_cast<sockaddr_in*>(sock)->sin_addr);
                            }

                            break;
                        }

                        messageLength = msg->rtm_msglen;
                    }
                }
            }

            return retVal;
        }

        std::string metrics() const override
        {
            return "";
        }

        std::string metricsV6() const override
        {
            return "";
        }

        std::string dhcp() const override
        {
            return "unknown";
        }

        uint32_t mtu() const override
        {
            return m_interfaceAddress->ifa_data ? reinterpret_cast<if_data*>(m_interfaceAddress->ifa_data)->ifi_mtu : 0;
        }

        LinkStats stats() const override
        {
            const auto stats { reinterpret_cast<if_data*>(m_interfaceAddress->ifa_data) };
            LinkStats retVal {};

            if (stats)
            {
                retVal.txPackets    = stats->ifi_opackets;
                retVal.rxPackets    = stats->ifi_ipackets;
                retVal.txBytes      = stats->ifi_obytes;
                retVal.rxBytes      = stats->ifi_ibytes;
                retVal.txErrors     = stats->ifi_oerrors;
                retVal.rxErrors     = stats->ifi_ierrors;
                retVal.rxDropped    = stats->ifi_iqdrops;
            }

            return retVal;
        }

        std::string type() const override
        {
            std::string retVal { UNKNOWN_VALUE };

            if (m_interfaceAddress->ifa_addr)
            {
                auto sdl { reinterpret_cast<struct sockaddr_dl*>(m_interfaceAddress->ifa_addr) };
                const auto type { Utils::NetworkHelper::getNetworkTypeStringCode(sdl->sdl_type, NETWORK_INTERFACE_TYPE) };
                retVal = type.empty() ? UNKNOWN_VALUE : type;
            }

            return retVal;
        }

        std::string state() const override
        {
            return m_interfaceAddress->ifa_flags & IFF_UP ? "up" : "down";
        }

        std::string MAC() const override
        {
            std::string retVal { "00:00:00:00:00:00" };
            auto sdl { reinterpret_cast<struct sockaddr_dl*>(m_interfaceAddress->ifa_addr) };
            std::stringstream ss;

            if (sdl && MAC_ADDRESS_COUNT_SEGMENTS == sdl->sdl_alen)
            {
                auto macAddress { &sdl->sdl_data[sdl->sdl_nlen] };

                if (macAddress)
                {
                    for (auto i = 0ull; i < MAC_ADDRESS_COUNT_SEGMENTS; ++i)
                    {
                        ss << std::hex << std::setfill('0') << std::setw(2);
                        ss << static_cast<int>(static_cast<uint8_t>(macAddress[i]));

                        if (i != MAC_ADDRESS_COUNT_SEGMENTS - 1)
                        {
                            ss << ":";
                        }
                    }

                    retVal = ss.str();
                }
            }

            return retVal;
        }
};

#endif //_NETWORK_BSD_WRAPPER_H
