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
#include "networkInterfaceBSD.h"
#include "networkHelper.h"

static const std::map<std::pair<int, int>, std::string> NETWORK_INTERFACE_TYPE =
{
    { std::make_pair(IFT_ETHER, IFT_ETHER),                     "ethernet"       },
    { std::make_pair(IFT_ISO88023, IFT_ISO88023),               "CSMA/CD"        },
    { std::make_pair(IFT_ISO88024, IFT_ISO88025),               "token ring"     },
    { std::make_pair(IFT_FDDI, IFT_FDDI),                       "FDDI"           },
    { std::make_pair(IFT_PPP, IFT_PPP),                         "point-to-point" },
    { std::make_pair(IFT_ATM, IFT_ATM),                         "ATM"            },
};

constexpr auto MacAddressCountSegments = 6ull;

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
    auto macAddress { reinterpret_cast<unsigned char *>(static_cast<LLADDR>(sdl)) };
    
    auto oldFill { ss.fill('0') };
    for(auto i = 0;i < MacAddressCountSegments-1;++i)
    {
        ss << std::setw(2) << std::hex << macAddress[i] << ":";
    }
    ss << std::setw(2) << std::hex << macAddress[MacAddressCountSegments];
    ss.fill(oldFill);
    
    return ss.str();
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
                &(reinterpret_cast <sockaddr_in *> (interfaceAddress->ifa_addr))->sin_addr) 
        };
        network["IPv4"]["address"] = address;

        if (interfaceAddress->ifa_netmask)
        {
            const auto netmask 
            { 
                Utils::NetworkHelper::IAddressToBinary(
                    interfaceAddress->ifa_netmask->sa_family, 
                    &(reinterpret_cast <sockaddr_in *> (interfaceAddress->ifa_netmask))->sin_addr) 
            };
            network["IPv4"]["netmask"] = netmask;
        }

        if (interfaceAddress->ifa_netmask)
        {
            const auto netmask 
            { 
                Utils::NetworkHelper::IAddressToBinary(
                    interfaceAddress->ifa_dstaddr->sa_family, 
                    &(reinterpret_cast <sockaddr_in *> (interfaceAddress->ifa_dstaddr))->sin_addr) 
            };
            network["IPv4"]["netmask"] = netmask;
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
                &((struct sockaddr_in6 *) interfaceAddress->ifa_addr)->sin6_addr) 
        };
        network["IPv6"]["address"] = address;

        if (interfaceAddress->ifa_netmask)
        {
            const auto netmask 
            { 
                Utils::NetworkHelper::IAddressToBinary(
                    interfaceAddress->ifa_netmask->sa_family, 
                    &((struct sockaddr_in6 *) interfaceAddress->ifa_netmask)->sin6_addr) 
            };
            network["IPv6"]["netmask"] = netmask;
        }

        if (interfaceAddress->ifa_netmask)
        {
            const auto netmask 
            { 
                Utils::NetworkHelper::IAddressToBinary(
                    interfaceAddress->ifa_dstaddr->sa_family, 
                    &((struct sockaddr_in6 *) interfaceAddress->ifa_dstaddr)->sin6_addr) 
            };
            network["IPv6"]["netmask"] = netmask;
        }
        network["IPv4"]["DHCP"] = "unknown";
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
    if (interfaceAddress->ifa_data)
    {
        auto sdl { reinterpret_cast<sockaddr_dl *>(interfaceAddress->ifa_addr) };

        network["name"] = interfaceAddress->ifa_name;
        network["type"] = Utils::NetworkHelper::getNetworkTypeStringCode(sdl->sdl_type, NETWORK_INTERFACE_TYPE);
        network["state"] = interfaceAddress->ifa_flags & IFF_UP ? "up" : "down";
        network["MAC"] = getMACaddress(sdl);
        
        const auto stats { reinterpret_cast<if_data *>(interfaceAddress->ifa_data) };

        network["tx_packets"] = stats->ifi_opackets;
        network["rx_packets"] = stats->ifi_ipackets;
        network["tx_bytes"] = stats->ifi_obytes;
        network["rx_bytes"] = stats->ifi_ibytes;
        network["tx_errors"] = stats->ifi_oerrors;
        network["rx_errors"] = stats->ifi_ierrors;
        network["rx_dropped"] = stats->ifi_iqdrops;

        network["MTU"] = stats->ifi_mtu;
    }
    else
    {
        throw std::runtime_error("Invalid interface data.");
    }
}
