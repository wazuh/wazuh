/*
 * Wazuh RSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 24, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <net/if.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <sstream>
#include <iomanip>
#include <net/route.h>
#include <sys/sysctl.h>
#include <sys/param.h>
#include <netinet/in.h>

#include "networkInterfaceBSD.h"
#include "networkHelper.h"
#include "makeUnique.h"
#include "sharedDefs.h"

static const std::map<std::pair<int, int>, std::string> NETWORK_INTERFACE_TYPE =
{
    { std::make_pair(IFT_ETHER, IFT_ETHER),                     "ethernet"       },
    { std::make_pair(IFT_ISO88023, IFT_ISO88023),               "CSMA/CD"        },
    { std::make_pair(IFT_ISO88024, IFT_ISO88025),               "token ring"     },
    { std::make_pair(IFT_FDDI, IFT_FDDI),                       "FDDI"           },
    { std::make_pair(IFT_PPP, IFT_PPP),                         "point-to-point" },
    { std::make_pair(IFT_ATM, IFT_ATM),                         "ATM"            },
};

static std::string getGateway(const ifaddrs* interfaceAddress)
{
    std::string retVal = "unknown";
    size_t tableSize { 0 };
    int mib[] = { CTL_NET, PF_ROUTE, 0, PF_UNSPEC, NET_RT_FLAGS, RTF_UP | RTF_GATEWAY };

    if (sysctl(mib, sizeof(mib) / sizeof(int), nullptr, &tableSize, nullptr, 0) == 0)
    {
        std::unique_ptr<char[]> table { std::make_unique<char[]>(tableSize) };
        if (sysctl(mib, sizeof(mib)/ sizeof(int), table.get(), &tableSize, nullptr, 0) == 0)
        {
            size_t messageLength { 0 };
            for (char* p = table.get(); p < table.get()+tableSize; p+=messageLength)
            {
                auto msg { reinterpret_cast<rt_msghdr *>(p) };
                auto sa { reinterpret_cast<sockaddr *>(msg + 1) };
                auto sdl { reinterpret_cast<sockaddr_dl *>(interfaceAddress->ifa_addr) };

                if (msg &&
                    (msg->rtm_addrs & RTA_GATEWAY) == RTA_GATEWAY &&
                    msg->rtm_index == sdl->sdl_index)
                {
                    auto sock { reinterpret_cast<sockaddr *>(reinterpret_cast<char *>(sa)+ROUNDUP(sa->sa_len)) };
                    if (sock && AF_INET == sock->sa_family)
                    {
                        char gateway[MAXHOSTNAMELEN] = { 0 };
                        retVal = inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in *>(sock)->sin_addr.s_addr, gateway, sizeof(gateway)-1);
                    }
                    break;
                }
                messageLength = msg->rtm_msglen;
            }
        }
    }
    return retVal;
}


std::shared_ptr<IOSNetwork> FactoryBSDNetwork::create(const sa_family_t osNetworkType)
{
    std::shared_ptr<IOSNetwork> ret;
    
    if(AF_INET == osNetworkType)
    {
        ret = std::make_shared<BSDNetworkImpl<AF_INET>>();
    }
    else if (AF_INET6 == osNetworkType)
    {
        ret = std::make_shared<BSDNetworkImpl<AF_INET6>>();
    }
    else if (AF_LINK == osNetworkType)
    {
        ret = std::make_shared<BSDNetworkImpl<AF_LINK>>();
    }
    else
    {
        throw std::runtime_error("Error creating linux network data retriever.");
    }
    return ret;
}

static std::string getMACaddress(const sockaddr_dl * sdl)
{
    std::stringstream ss;
    std::string retVal { "00:00:00:00:00:00" };
    if (sdl && 6 == sdl->sdl_alen)
    {
        auto macAddress { &sdl->sdl_data[sdl->sdl_nlen] };
        if (macAddress)
        {
            for(auto i = 0ull;i < MAC_ADDRESS_COUNT_SEGMENTS;++i)
            {
                ss << std::hex << std::setfill('0') << std::setw(2);
                ss << static_cast<int>(static_cast<uint8_t>(macAddress[i]));
                if (i != MAC_ADDRESS_COUNT_SEGMENTS-1)
                {
                    ss << ":";
                }
            }
            retVal = ss.str();
        }
    }
    return retVal;
}

template <>
void BSDNetworkImpl<AF_INET>::buildNetworkData(const ifaddrs* interfaceAddress, nlohmann::json& network)
{
    // Get IPv4 address
    if (interfaceAddress->ifa_addr)
    {
        const auto address 
        { 
            Utils::NetworkHelper::IAddressToBinary(
                interfaceAddress->ifa_addr->sa_family, 
                &(reinterpret_cast<sockaddr_in *>(interfaceAddress->ifa_addr))->sin_addr) 
        };
        network["IPv4"]["address"] = address;

        if (interfaceAddress->ifa_netmask)
        {
            const auto netmask 
            { 
                Utils::NetworkHelper::IAddressToBinary(
                    interfaceAddress->ifa_netmask->sa_family, 
                    &(reinterpret_cast<sockaddr_in *>(interfaceAddress->ifa_netmask))->sin_addr) 
            };
            network["IPv4"]["netmask"] = netmask;
        }

        if (interfaceAddress->ifa_dstaddr)
        {
            const auto broadcast 
            { 
                Utils::NetworkHelper::IAddressToBinary(
                    interfaceAddress->ifa_dstaddr->sa_family, 
                    &(reinterpret_cast<sockaddr_in *>(interfaceAddress->ifa_dstaddr))->sin_addr) 
            };
            network["IPv4"]["broadcast"] = broadcast;
        }
        network["IPv4"]["DHCP"] = "unknown";
    }
    else
    {
        throw std::runtime_error("Invalid IpV4 address.");
    }
}
template <>
void BSDNetworkImpl<AF_INET6>::buildNetworkData(const ifaddrs* interfaceAddress, nlohmann::json& network)
{
    if (interfaceAddress->ifa_addr)
    {
        const auto address 
        { 
            Utils::NetworkHelper::IAddressToBinary(
                interfaceAddress->ifa_addr->sa_family, 
                &(reinterpret_cast<sockaddr_in6 *>(interfaceAddress->ifa_addr))->sin6_addr) 
        };
        network["IPv6"]["address"] = address;

        if (interfaceAddress->ifa_netmask)
        {
            const auto netmask 
            { 
                Utils::NetworkHelper::IAddressToBinary(
                    interfaceAddress->ifa_netmask->sa_family, 
                    &(reinterpret_cast<sockaddr_in6 *>(interfaceAddress->ifa_netmask))->sin6_addr) 
            };
            network["IPv6"]["netmask"] = netmask;
        }

        if (interfaceAddress->ifa_dstaddr)
        {
            const auto broadcast 
            { 
                Utils::NetworkHelper::IAddressToBinary(
                    interfaceAddress->ifa_dstaddr->sa_family, 
                    &(reinterpret_cast<sockaddr_in6 *>(interfaceAddress->ifa_dstaddr))->sin6_addr) 
            };
            network["IPv6"]["broadcast"] = broadcast;
        }
        network["IPv6"]["DHCP"] = "unknown";
    }
    else
    {
        throw std::runtime_error("Invalid IpV4 address.");
    }
}
template <>
void BSDNetworkImpl<AF_LINK>::buildNetworkData(const ifaddrs* interfaceAddress, nlohmann::json& network)
{
    /* Get stats of interface */
    if (interfaceAddress && interfaceAddress->ifa_data)
    {
        network["name"] = interfaceAddress->ifa_name ? interfaceAddress->ifa_name : "unknown";
        network["state"] = interfaceAddress->ifa_flags & IFF_UP ? "up" : "down";
        if (interfaceAddress->ifa_addr)
        {
            auto sdl { reinterpret_cast<struct sockaddr_dl *>(interfaceAddress->ifa_addr) };
            network["type"] = Utils::NetworkHelper::getNetworkTypeStringCode(sdl->sdl_type, NETWORK_INTERFACE_TYPE);
            network["MAC"] = getMACaddress(sdl);
        }
        
        const auto stats { reinterpret_cast<if_data *>(interfaceAddress->ifa_data) };

        network["tx_packets"] = stats->ifi_opackets;
        network["rx_packets"] = stats->ifi_ipackets;
        network["tx_bytes"] = stats->ifi_obytes;
        network["rx_bytes"] = stats->ifi_ibytes;
        network["tx_errors"] = stats->ifi_oerrors;
        network["rx_errors"] = stats->ifi_ierrors;
        network["rx_dropped"] = stats->ifi_iqdrops;

        network["MTU"] = stats->ifi_mtu;
        network["gateway"] = getGateway(interfaceAddress);
    }
    else
    {
        throw std::runtime_error("Invalid interface data.");
    }
}
