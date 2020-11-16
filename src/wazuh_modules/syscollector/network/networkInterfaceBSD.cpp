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

#include <ifaddrs.h>
#include "networkInterfaceBSD.h"
#include "networkBSDWrapper.h"

std::shared_ptr<IOSNetwork> FactoryBSDNetwork::create(const std::shared_ptr<INetworkInterfaceWrapper>& interfaceWrapper)
{
    std::shared_ptr<IOSNetwork> ret;

    if (interfaceWrapper)
    {
        const auto family { interfaceWrapper->family() };
        if(AF_INET == family)
        {
            ret = std::make_shared<BSDNetworkImpl<AF_INET>>(interfaceWrapper);
        }
        else if (AF_INET6 == family)
        {
            ret = std::make_shared<BSDNetworkImpl<AF_INET6>>(interfaceWrapper);
        }
        else if (AF_LINK == family)
        {
            ret = std::make_shared<BSDNetworkImpl<AF_LINK>>(interfaceWrapper);
        }
        else
        {
            throw std::runtime_error { "Error creating BSD network data retriever." };
        }
    }
    else
    {
        throw std::runtime_error { "Error nullptr interfaceWrapper instance." };
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

        const auto metrics { m_interfaceAddress->metrics() };
        if (!metrics.empty())
        {
            network["IPv4"]["metric"] = metrics;
        }

        network["IPv4"]["dhcp"] = "unknown";
    }
    else
    {
        throw std::runtime_error { "Invalid IpV4 address." };
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

        const auto metrics { m_interfaceAddress->metrics() };
        if (!metrics.empty())
        {
            network["IPv6"]["metric"] = metrics;
        }

        network["IPv6"]["dhcp"] = "unknown";
    }
    else
    {
        throw std::runtime_error { "Invalid IpV4 address." };
    }
}
template <>
void BSDNetworkImpl<AF_LINK>::buildNetworkData(nlohmann::json& network)
{
    /* Get stats of interface */

    network["name"] = m_interfaceAddress->name();
    network["state"] = m_interfaceAddress->state();
    network["type"] = m_interfaceAddress->type();
    network["mac"] = m_interfaceAddress->MAC();

    const auto stats { m_interfaceAddress->stats() };

    network["tx_packets"] = stats.txPackets;
    network["rx_packets"] = stats.rxPackets;
    network["tx_bytes"] = stats.txBytes;
    network["rx_bytes"] = stats.rxBytes;
    network["tx_errors"] = stats.txErrors;
    network["rx_errors"] = stats.rxErrors;
    network["rx_dropped"] = stats.rxDropped;

    network["mtu"] = m_interfaceAddress->mtu();
    network["gateway"] = m_interfaceAddress->gateway();
}
