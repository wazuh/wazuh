/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * October 24, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <netdb.h>
#include <ifaddrs.h>
#include "networkInterfaceLinux.h"
#include "networkLinuxWrapper.h"

std::shared_ptr<IOSNetwork> FactoryLinuxNetwork::create(const std::shared_ptr<INetworkInterfaceWrapper>& interfaceWrapper)
{
    std::shared_ptr<IOSNetwork> ret;

    if (interfaceWrapper)
    {
        const auto family { interfaceWrapper->family() };

        if (AF_INET == family)
        {
            ret = std::make_shared<LinuxNetworkImpl<AF_INET>>(interfaceWrapper);
        }
        else if (AF_INET6 == family)
        {
            ret = std::make_shared<LinuxNetworkImpl<AF_INET6>>(interfaceWrapper);
        }
        else if (AF_PACKET == family)
        {
            ret = std::make_shared<LinuxNetworkImpl<AF_PACKET>>(interfaceWrapper);
        }

        // else: The current interface family is not supported
    }
    else
    {
        throw std::runtime_error { "Error nullptr interfaceWrapper instance." };
    }

    return ret;
}

template <>
void LinuxNetworkImpl<AF_INET>::buildNetworkData(nlohmann::json& network)
{
    // Get IPv4 address
    const auto address { m_interfaceAddress->address() };

    if (!address.empty())
    {
        nlohmann::json ipv4JS { };
        ipv4JS["network_ip"] = address;
        ipv4JS["network_netmask"] = m_interfaceAddress->netmask();
        ipv4JS["network_broadcast"] = m_interfaceAddress->broadcast();
        ipv4JS["network_metric"] = m_interfaceAddress->metrics();
        ipv4JS["network_dhcp"] = m_interfaceAddress->dhcp();

        network["IPv4"].push_back(ipv4JS);
    }
    else
    {
        throw std::runtime_error { "Invalid IpV4 address." };
    }
}
template <>
void LinuxNetworkImpl<AF_INET6>::buildNetworkData(nlohmann::json& network)
{
    const auto address { m_interfaceAddress->addressV6() };

    if (!address.empty())
    {
        nlohmann::json ipv6JS {};
        ipv6JS["network_ip"] = address;
        ipv6JS["network_netmask"] = m_interfaceAddress->netmaskV6();
        ipv6JS["network_broadcast"] = m_interfaceAddress->broadcastV6();
        ipv6JS["network_metric"] = m_interfaceAddress->metricsV6();
        ipv6JS["network_dhcp"] = m_interfaceAddress->dhcp();

        network["IPv6"].push_back(ipv6JS);
    }
    else
    {
        throw std::runtime_error { "Invalid IpV6 address." };
    }
}
template <>
void LinuxNetworkImpl<AF_PACKET>::buildNetworkData(nlohmann::json& network)
{
    /* Get stats of interface */
    network["interface_name"]  = m_interfaceAddress->name();
    network["interface_alias"] = m_interfaceAddress->adapter();
    network["interface_type"]  = m_interfaceAddress->type();
    network["interface_state"] = m_interfaceAddress->state();
    network["host_mac"]        = m_interfaceAddress->MAC();

    const auto stats { m_interfaceAddress->stats() };

    network["host_network_egress_packages"]  = stats.txPackets;
    network["host_network_ingress_packages"] = stats.rxPackets;
    network["host_network_egress_bytes"]     = stats.txBytes;
    network["host_network_ingress_bytes"]    = stats.rxBytes;
    network["host_network_egress_errors"]    = stats.txErrors;
    network["host_network_ingress_errors"]   = stats.rxErrors;
    network["host_network_egress_drops"]     = stats.txDropped;
    network["host_network_ingress_drops"]    = stats.rxDropped;

    network["interface_mtu"]   = m_interfaceAddress->mtu();
    network["network_gateway"] = m_interfaceAddress->gateway();
}
