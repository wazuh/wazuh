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

#ifndef _NETWORK_BSD_H
#define _NETWORK_BSD_H

#include "inetworkInterface.h"

class FactoryBSDNetwork
{
    public:
    static std::shared_ptr<IOSNetwork>create(const sa_family_t osNetworkType);
};

template <sa_family_t osNetworkType>
class BSDNetworkImpl final : public IOSNetwork
{
public:
    void buildNetworkData(const ifaddrs* interfaceAddress, nlohmann::json& network) override
    {
        throw std::runtime_error("Non implemented specialization.");
    }
};

template <>
void BSDNetworkImpl<AF_INET>::buildNetworkData(const ifaddrs* interfaceAddress, nlohmann::json& network);
template <>
void BSDNetworkImpl<AF_INET6>::buildNetworkData(const ifaddrs* interfaceAddress, nlohmann::json& network);
#if defined (HAVE_AF_LINK)
template <>
void BSDNetworkImpl<AF_LINK>::buildNetworkData(const ifaddrs* interfaceAddress, nlohmann::json& network);
#endif

#endif // _NETWORK_BSD_H