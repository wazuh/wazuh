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

#include <netdb.h>
#include "networkInterfaceLinux.h"
#include "networkHelper.h"
#include "filesystemHelper.h"
#include "stringHelper.h"
#include "sharedDefs.h"


namespace GatewayFileFields
{
    enum 
    {
        Iface,
        Destination,
        Gateway,
        Flags,
        RefCnt,
        Use,
        Metric,
        Mask,
        MTU,
        Window,
        IRTT,
        Size
    };
}

namespace DebianInterfaceConfig
{
    enum Config
    {
        Type,
        Name,
        Family,
        Method,
        Size
    };
}

namespace RHInterfaceConfig
{
    enum Config
    {
        Key,
        Value,
        Size
    };
}


std::shared_ptr<IOSNetwork> FactoryLinuxNetwork::create(const sa_family_t osNetworkType)
{
    std::shared_ptr<IOSNetwork> ret;

    if(AF_INET == osNetworkType)
    {
        ret = std::make_shared<LinuxNetworkImpl<AF_INET>>();
    }
    else if (AF_INET6 == osNetworkType)
    {
        ret = std::make_shared<LinuxNetworkImpl<AF_INET6>>();
    }
    else if (AF_PACKET == osNetworkType)
    {
        ret = std::make_shared<LinuxNetworkImpl<AF_PACKET>>();
    }
    else
    {
        throw std::runtime_error("Error creating linux network data retriever.");
    }
    return ret;
}

static std::string getNameInfo(const sockaddr* inputData, const socklen_t socketLen)
{
    auto retVal { std::make_unique<char[]>(NI_MAXHOST) };
    if (inputData)
    {
        const auto result = getnameinfo(inputData,
            socketLen,
            retVal.get(), NI_MAXHOST,
            NULL, 0, NI_NUMERICHOST);
        
        if (result != 0)
        {
            throw std::runtime_error
            {
                "Cannot get socket address information, Code: " + result
            };
        }
    }
    return retVal.get();
}

static std::string getRedHatDHCPStatus(const std::vector<std::string>& fields)
{
    std::string retVal { "unknown" };
    const auto value { fields.at(RHInterfaceConfig::Value) };
    
    if (value.compare("static") == 0 || value.compare("none") == 0 || value.compare("no") == 0)
    {
        retVal = "disabled";
    }
    else if (value.compare("dhcp") == 0 || value.compare("yes") == 0)
    {
        retVal = "enabled";
    }
    else if (value.compare("bootp") == 0)
    {
        retVal = "BOOTP";
    }

    return retVal;
}

static std::string getDebianDHCPStatus(const std::string& family, const std::vector<std::string>& fields)
{
    std::string retVal { "enabled" };
    if (fields.at(DebianInterfaceConfig::Family).compare(family) == 0)
    {
        const auto method { fields.at(DebianInterfaceConfig::Method) };
        if (method.compare("static") == 0 || method.compare("manual") == 0)
        {
            retVal = "disabled";
        }
        else if (method.compare("dhcp") == 0)
        {
            retVal = "enabled";
        }
    }
    return retVal;
}

static std::string getDHCP(const int family, const std::string& ifName)
{
    auto fileData { Utils::getFileContent(WM_SYS_IF_FILE) };
    std::string retVal { "unknown" };
    if (!fileData.empty())
    {
        const auto lines { Utils::split(fileData, '\n') };
        for (const auto& line : lines)
        {
            const auto fields { Utils::split(line, ' ') };
            if (DebianInterfaceConfig::Size == fields.size())
            {
                if (fields.at(DebianInterfaceConfig::Type).compare("iface") == 0 &&
                    fields.at(DebianInterfaceConfig::Name).compare(ifName) == 0)
                {
                    if (AF_INET == family)
                    {
                        retVal = getDebianDHCPStatus("inet", fields);
                    }
                    else if (AF_INET6 == family)
                    {
                        retVal = getDebianDHCPStatus("inet6", fields);
                    }
                }
            }
        }
    }
    else
    {
        const auto fileName { "ifcfg-" + ifName };
        fileData = Utils::getFileContent(WM_SYS_IF_DIR_RH + fileName);
        fileData = fileData.empty() ? Utils::getFileContent(WM_SYS_IF_DIR_SUSE + fileName) : fileData;

        if (!fileData.empty())
        {
            const auto lines { Utils::split(fileData, '\n') };
            for (const auto& line : lines)
            {
                const auto fields { Utils::split(line, '=') };
                if (fields.size() == RHInterfaceConfig::Size)
                {
                    if (AF_INET == family)
                    {
                        if (fields.at(RHInterfaceConfig::Key).compare("BOOTPROTO") == 0)
                        {
                            retVal = getRedHatDHCPStatus(fields);
                        }
                    }
                    else if (AF_INET6 == family)
                    {
                        if (fields.at(RHInterfaceConfig::Key).compare("DHCPV6C") == 0)
                        {
                            retVal = getRedHatDHCPStatus(fields);
                        }
                    }
                }
            }
        }
    }
    return retVal;
}

static std::string getGateway(const std::string& ifName)
{
    std::string retVal { "unknown" };
    auto fileData { Utils::getFileContent(std::string(WM_SYS_NET_DIR) + "route") };
    
    if (!fileData.empty())
    {
        auto lines { Utils::split(fileData, '\n') };
        for (auto& line : lines)
        {
            line = Utils::rightTrim(line);
            Utils::replaceAll(line, "\t", " ");
            Utils::replaceAll(line, "  ", " ");
            const auto fields { Utils::split(line, ' ') };

            if (GatewayFileFields::Size == fields.size())
            {
                if (fields.at(GatewayFileFields::Iface).compare(ifName) == 0)
                {
                    const auto address { static_cast<uint32_t>(std::stoi(fields.at(GatewayFileFields::Gateway), 0, 16)) };
                    if (address)
                    {
                        retVal = std::string(inet_ntoa({ address })) + "|" + fields.at(GatewayFileFields::Metric);
                    }
                }
            }
        }
    }
    return retVal;
}

template <>
void LinuxNetworkImpl<AF_INET>::buildNetworkData(const ifaddrs* interfaceAddress, nlohmann::json& network)
{
    // Get IPv4 address
    if (interfaceAddress && interfaceAddress->ifa_addr)
    {
        const auto address { getNameInfo(interfaceAddress->ifa_addr, sizeof(struct sockaddr_in)) };
        network["IPv4"]["address"] = address;
        if (interfaceAddress->ifa_netmask)
        {
            const auto netmask { getNameInfo(interfaceAddress->ifa_netmask, sizeof(struct sockaddr_in)) };
            network["IPv4"]["netmask"] = netmask;

            if (interfaceAddress->ifa_ifu.ifu_broadaddr)
            {
                const auto broadcast { getNameInfo(interfaceAddress->ifa_ifu.ifu_broadaddr, sizeof(struct sockaddr_in)) };
                network["IPv4"]["broadcast"] = broadcast;
            }
            else if (netmask.size() && address.size())
            {
                const auto broadcast { Utils::NetworkHelper::getBroadcast(address, netmask) };
                network["IPv4"]["broadcast"] = broadcast;
            }
        }
        network["IPv4"]["dhcp"] = getDHCP(AF_INET, interfaceAddress->ifa_name);
        network["IPv4"]["gateway"] = getGateway(interfaceAddress->ifa_name);
    }
    else
    {
        throw std::runtime_error("Invalid IpV4 address.");
    }
}
template <>
void LinuxNetworkImpl<AF_INET6>::buildNetworkData(const ifaddrs* interfaceAddress, nlohmann::json& network)
{
    if (interfaceAddress && interfaceAddress->ifa_addr)
    {
        const auto address { Utils::splitIndex(getNameInfo(interfaceAddress->ifa_addr, sizeof(struct sockaddr_in6)), '%', 0) };
        network["IPv6"]["address"] = address; 

        if (interfaceAddress->ifa_netmask)
        {
            network["IPv6"]["netmask"] = getNameInfo(interfaceAddress->ifa_netmask, sizeof(struct sockaddr_in6));

            if (interfaceAddress->ifa_ifu.ifu_broadaddr)
            {
                network["IPv6"]["broadcast"] = getNameInfo(interfaceAddress->ifa_ifu.ifu_broadaddr, sizeof(struct sockaddr_in6));
            }
        }
        network["IPv6"]["dhcp"] = getDHCP(AF_INET6, interfaceAddress->ifa_name);
    }
    else
    {
        throw std::runtime_error("Invalid IpV6 address.");
    }
}
template <>
void LinuxNetworkImpl<AF_PACKET>::buildNetworkData(const ifaddrs* interfaceAddress, nlohmann::json& network)
{
    /* Get stats of interface */
    if (interfaceAddress && interfaceAddress->ifa_data)
    {
        const auto stats { reinterpret_cast<LinkStats *>(interfaceAddress->ifa_data) };

        network["tx_packets"] = stats->txPackets;
        network["rx_packets"] = stats->rxPackets;
        network["tx_bytes"] = stats->txBytes;
        network["rx_bytes"] = stats->rxBytes;
        network["tx_errors"] = stats->txErrors;
        network["rx_errors"] = stats->rxErrors;
        network["tx_dropped"] = stats->txDropped;
        network["rx_dropped"] = stats->rxDropped;

        const auto mtuFileContent { Utils::getFileContent(std::string(WM_SYS_IFDATA_DIR) + interfaceAddress->ifa_name + "/mtu") };
        network["MTU"] = Utils::splitIndex(mtuFileContent, '\n', 0);
    }
    else
    {
        throw std::runtime_error("Invalid interface data.");
    } 
}
