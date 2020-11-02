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

#ifndef _NETWORK_BSD_H
#define _NETWORK_BSD_H

#include "inetworkInterface.h"
#include "inetworkWrapper.h"

class FactoryBSDNetwork
{
    public:
    static std::shared_ptr<IOSNetwork>create(const std::shared_ptr<INetworkInterfaceWrapper>& interface);
};

template <sa_family_t osNetworkType>
class BSDNetworkImpl final : public IOSNetwork
{
    const std::shared_ptr<INetworkInterfaceWrapper>& m_interfaceAddress;
public:
    explicit BSDNetworkImpl(const std::shared_ptr<INetworkInterfaceWrapper>& interfaceAddress) 
    : m_interfaceAddress(interfaceAddress)
    { }
    void buildNetworkData(nlohmann::json& /*network*/) override
    {
        throw std::runtime_error("Non implemented specialization.");
    }
};

template <>
void BSDNetworkImpl<AF_INET>::buildNetworkData(nlohmann::json& network);
template <>
void BSDNetworkImpl<AF_INET6>::buildNetworkData(nlohmann::json& network);
#if defined (HAVE_AF_LINK)
template <>
void BSDNetworkImpl<AF_LINK>::buildNetworkData(nlohmann::json& network);
#endif

#endif // _NETWORK_BSD_H