/*
 * Wazuh SYSCOLLECTOR
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 24, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "networkInterfaceBSD.h"
#include "networkLinuxWrapper.h"

std::shared_ptr<IOSNetwork> FactoryBSDNetwork::create(const std::shared_ptr<INetworkInterfaceWrappers>& interface)
{
    std::shared_ptr<IOSNetwork> ret;

    if(AF_INET == interface->family())
    {
        ret = std::make_shared<BSDNetworkImpl<AF_INET>>();
    }
    else if (AF_INET6 == interface->family())
    {
        ret = std::make_shared<BSDNetworkImpl<AF_INET6>>();
    }
    else if (AF_LINK == interface->family())
    {
        ret = std::make_shared<BSDNetworkImpl<AF_LINK>>();
    }
    else
    {
        throw std::runtime_error("Error creating BSD network data retriever.");
    }
    return ret;
}

template <>
void BSDNetworkImpl<AF_INET>::buildNetworkData(nlohmann::json& network)
{
    // Get IPv4 address
    const auto address { m_interfaceAddress->address() };
    if (!address.empty())
    {
        network["IPv4"]["address"] = address;

        const auto netmask { m_interfaceAddress->netmask() };
        if (!netmask.empty())
        {
            network["IPv4"]["netmask"] = netmask;
        }

        const auto broadcast { m_interfaceAddress->broadcast() };
        if (!broadcast.empty())
        {
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
void BSDNetworkImpl<AF_INET6>::buildNetworkData(nlohmann::json& network)
{
    const auto address { m_interfaceAddress->addressV6() };
    if (!address.empty())
    {
        network["IPv6"]["address"] = address;

        const auto netmask { m_interfaceAddress->netmaskV6() };
        if (!netmask.empty())
        {
            network["IPv6"]["netmask"] = netmask;
        }

        const auto broadcast { m_interfaceAddress->broadcastV6() };
        if (!broadcast.empty())
        {
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
void BSDNetworkImpl<AF_LINK>::buildNetworkData(nlohmann::json& network)
{
    /* Get stats of interface */

    network["name"] = m_interfaceAddress->name();
    network["state"] = m_interfaceAddress->state();
    network["type"] = m_interfaceAddress->type();
    network["MAC"] = m_interfaceAddress->MAC();

    const auto stats { m_interfaceAddress->stats() };

    network["tx_packets"] = stats.txPackets;
    network["rx_packets"] = stats.rxPackets;
    network["tx_bytes"] = stats.txBytes;
    network["rx_bytes"] = stats.rxBytes;
    network["tx_errors"] = stats.txErrors;
    network["rx_errors"] = stats.rxErrors;
    network["rx_dropped"] = stats.rxDropped;

    network["MTU"] = m_interfaceAddress->mtu();
    network["gateway"] = m_interfaceAddress->gateway();
}
