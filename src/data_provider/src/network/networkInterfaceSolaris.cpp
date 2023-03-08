/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * December 21, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "networkInterfaceSolaris.h"
#include "sys/socket.h"


std::shared_ptr<IOSNetwork> FactorySolarisNetwork::create(const std::shared_ptr<INetworkInterfaceWrapper>& interfaceWrapper)
{
    std::shared_ptr<IOSNetwork> ret;

    if (interfaceWrapper)
    {
        const auto family { interfaceWrapper->family() };

        if (AF_INET == family)
        {
            ret = std::make_shared<SolarisNetworkImpl<AF_INET>>(interfaceWrapper);
        }
        else if (AF_INET6 == family)
        {
            ret = std::make_shared<SolarisNetworkImpl<AF_INET6>>(interfaceWrapper);
        }
        else if (AF_UNSPEC == family)
        {
            ret = std::make_shared<SolarisNetworkImpl<AF_UNSPEC>>(interfaceWrapper);
        }

        // else: unknown family
    }
    else
    {
        throw std::runtime_error { "Error nullptr interfaceWrapper instance." };
    }

    return ret;
}

template <>
void SolarisNetworkImpl<AF_INET>::buildNetworkData(nlohmann::json& network)
{
    const auto address { m_interfaceAddress->address() };

    if (!address.empty())
    {
        nlohmann::json ipv4JS { };
        ipv4JS["address"] = address;
        ipv4JS["netmask"] = m_interfaceAddress->netmask();
        ipv4JS["broadcast"] = m_interfaceAddress->broadcast();
        ipv4JS["metric"] = m_interfaceAddress->metrics();
        ipv4JS["dhcp"]   = m_interfaceAddress->dhcp();

        network["IPv4"].push_back(ipv4JS);
    }
    else
    {
        throw std::runtime_error { "Invalid IpV4 address." };
    }
}
template <>
void SolarisNetworkImpl<AF_INET6>::buildNetworkData(nlohmann::json& network)
{
    const auto address { m_interfaceAddress->addressV6() };

    if (!address.empty())
    {
        nlohmann::json ipv6JS {};
        ipv6JS["address"] = address;
        ipv6JS["netmask"] = m_interfaceAddress->netmaskV6();
        ipv6JS["broadcast"] = m_interfaceAddress->broadcastV6();
        ipv6JS["metric"] = m_interfaceAddress->metricsV6();
        ipv6JS["dhcp"]   = m_interfaceAddress->dhcp();

        network["IPv6"].push_back(ipv6JS);
    }
    else
    {
        throw std::runtime_error { "Invalid IpV6 address." };
    }
}

template <>
void SolarisNetworkImpl<AF_UNSPEC>::buildNetworkData(nlohmann::json& network)
{
    // Extraction of common adapter data
    network["name"]       = m_interfaceAddress->name();
    network["adapter"]    = m_interfaceAddress->adapter();
    network["state"]      = m_interfaceAddress->state();
    network["type"]       = m_interfaceAddress->type();
    network["mac"]        = m_interfaceAddress->MAC();

    const auto stats { m_interfaceAddress->stats() };
    network["tx_packets"] = stats.txPackets;
    network["rx_packets"] = stats.rxPackets;
    network["tx_bytes"]   = stats.txBytes;
    network["rx_bytes"]   = stats.rxBytes;
    network["tx_errors"]  = stats.txErrors;
    network["rx_errors"]  = stats.rxErrors;
    network["tx_dropped"] = stats.txDropped;
    network["rx_dropped"] = stats.rxDropped;

    network["mtu"]        = m_interfaceAddress->mtu();
    network["gateway"]    = m_interfaceAddress->gateway();
}
