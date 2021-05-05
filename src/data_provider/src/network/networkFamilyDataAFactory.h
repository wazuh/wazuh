/*
 * Wazuh SYSINFO
 * Copyright (C) 2015-2021, Wazuh Inc.
 * October 24, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _NETWORK_FAMILY_DATA_AFACTORY_H
#define _NETWORK_FAMILY_DATA_AFACTORY_H

#include <memory>
#include "json.hpp"
#include "networkInterfaceLinux.h"
#include "networkInterfaceBSD.h"
#include "networkInterfaceWindows.h"
#include "sharedDefs.h"

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
    static std::shared_ptr<IOSNetwork> create(const std::shared_ptr<INetworkInterfaceWrapper>& interfaceWrapper)
    {
        return FactoryLinuxNetwork::create(interfaceWrapper);
    }
};

template <>
class FactoryNetworkFamilyCreator<OSType::BSDBASED> final
{
public:
    static std::shared_ptr<IOSNetwork> create(const std::shared_ptr<INetworkInterfaceWrapper>& interfaceWrapper)
    {
        return FactoryBSDNetwork::create(interfaceWrapper);
    }
};    

template <>
class FactoryNetworkFamilyCreator<OSType::WINDOWS> final
{
public:
    static std::shared_ptr<IOSNetwork> create(const std::shared_ptr<INetworkInterfaceWrapper>& interfaceWrapper)
    {
        return FactoryWindowsNetwork::create(interfaceWrapper);
    }
};    

#endif // _NETWORK_FAMILY_DATA_AFACTORY_H