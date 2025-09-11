/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * November 4, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <ws2tcpip.h>
#include "windowsHelper.h"
#include "networkInterfaceWindows.h"
#include "networkWindowsWrapper.h"

std::shared_ptr<IOSNetwork> FactoryWindowsNetwork::create(const std::shared_ptr<INetworkInterfaceWrapper>& interfaceWrapper)
{
    std::shared_ptr<IOSNetwork> ret;

    if (interfaceWrapper)
    {
        const auto family { interfaceWrapper->family() };

        if (Utils::NetworkWindowsHelper::IPV4 == family)
        {
            ret = std::make_shared<WindowsNetworkImpl<Utils::NetworkWindowsHelper::IPV4>>(interfaceWrapper);
        }
        else if (Utils::NetworkWindowsHelper::IPV6 == family)
        {
            ret = std::make_shared<WindowsNetworkImpl<Utils::NetworkWindowsHelper::IPV6>>(interfaceWrapper);
        }
        else if (Utils::NetworkWindowsHelper::COMMON_DATA == family)
        {
            ret = std::make_shared<WindowsNetworkImpl<Utils::NetworkWindowsHelper::COMMON_DATA>>(interfaceWrapper);
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
void WindowsNetworkImpl<Utils::NetworkWindowsHelper::UNDEF>::buildNetworkData(nlohmann::json& /*network*/)
{
    throw std::runtime_error { "Invalid network adapter family." };
}

template <>
void WindowsNetworkImpl<Utils::NetworkWindowsHelper::IPV4>::buildNetworkData(nlohmann::json& networkV4)
{
    // Get IPv4 address
    const auto address { m_interfaceAddress->address() };

    if (!address.empty())
    {
        nlohmann::json ipv4JS;
        ipv4JS["network_ip"] = address;
        ipv4JS["network_netmask"] =  m_interfaceAddress->netmask();
        ipv4JS["network_broadcast"] = m_interfaceAddress->broadcast();
        ipv4JS["network_metric"] = m_interfaceAddress->metrics();
        ipv4JS["network_dhcp"] = m_interfaceAddress->dhcp();

        networkV4["IPv4"].push_back(ipv4JS);
    }
    else
    {
        throw std::runtime_error { "Invalid IpV4 address." };
    }
}

template <>
void WindowsNetworkImpl<Utils::NetworkWindowsHelper::IPV6>::buildNetworkData(nlohmann::json& networkV6)
{
    const auto address { m_interfaceAddress->addressV6() };

    if (!address.empty())
    {
        nlohmann::json ipv6JS { };
        ipv6JS["network_ip"] = address;
        ipv6JS["network_netmask"] = m_interfaceAddress->netmaskV6();
        ipv6JS["network_broadcast"] = m_interfaceAddress->broadcastV6();
        ipv6JS["network_metric"] = m_interfaceAddress->metricsV6();
        ipv6JS["network_dhcp"] = m_interfaceAddress->dhcp();

        networkV6["IPv6"].push_back(ipv6JS);
    }
    else
    {
        throw std::runtime_error { "Invalid IpV6 address." };
    }
}

template <>
void WindowsNetworkImpl<Utils::NetworkWindowsHelper::COMMON_DATA>::buildNetworkData(nlohmann::json& networkCommon)
{
    // Extraction of common adapter data
    networkCommon["interface_name"]  = m_interfaceAddress->name();
    networkCommon["interface_alias"] = m_interfaceAddress->adapter();
    networkCommon["interface_state"] = m_interfaceAddress->state();
    networkCommon["interface_type"]  = m_interfaceAddress->type();
    networkCommon["host_mac"]        = m_interfaceAddress->MAC();

    const auto stats { m_interfaceAddress->stats() };
    networkCommon["host_network_egress_packages"]  = stats.txPackets;
    networkCommon["host_network_ingress_packages"] = stats.rxPackets;
    networkCommon["host_network_egress_bytes"]     = stats.txBytes;
    networkCommon["host_network_ingress_bytes"]    = stats.rxBytes;
    networkCommon["host_network_egress_errors"]    = stats.txErrors;
    networkCommon["host_network_ingress_errors"]   = stats.rxErrors;
    networkCommon["host_network_egress_drops"]     = stats.txDropped;
    networkCommon["host_network_ingress_drops"]    = stats.rxDropped;

    networkCommon["interface_mtu"]   = m_interfaceAddress->mtu();
    networkCommon["network_gateway"] = m_interfaceAddress->gateway();
}
