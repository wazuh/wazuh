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

#ifndef _NETWORK_FAMILY_DATA_AFACTORY_H
#define _NETWORK_FAMILY_DATA_AFACTORY_H

#include "json.hpp"
#include "networkInterfaceLinux.h"
#include "networkInterfaceBSD.h"

enum OSType
{
    LINUX,
    BSDBASED
};

template <OSType osType>
class FactoryNetworkFamilyCreator final
{
public:
    static std::shared_ptr<IOSNetwork> create(const std::shared_ptr<INetworkInterfaceWrapper>& /*interface*/)
    {
        throw std::runtime_error
        {
            "Error creating network data retriever."
        };
    }
};

template <>
class FactoryNetworkFamilyCreator<OSType::LINUX> final
{
public:
    static std::shared_ptr<IOSNetwork> create(const std::shared_ptr<INetworkInterfaceWrapper>& interface)
    {
        return FactoryLinuxNetwork::create(interface);
    }
};

template <>
class FactoryNetworkFamilyCreator<OSType::BSDBASED> final
{
public:
    static std::shared_ptr<IOSNetwork> create(const std::shared_ptr<INetworkInterfaceWrapper>& interface)
    {
        return FactoryBSDNetwork::create(interface);
    }
};    


#endif // _NETWORK_FAMILY_DATA_AFACTORY_H