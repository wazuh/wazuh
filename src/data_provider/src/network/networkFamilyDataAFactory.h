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

#ifndef _NETWORK_FAMILY_DATA_AFACTORY_H
#define _NETWORK_FAMILY_DATA_AFACTORY_H

#include <memory>
#include "json.hpp"
#include "networkInterfaceLinux.h"
#include "networkInterfaceBSD.h"
#include "networkInterfaceWindows.h"
#include "networkInterfaceSolaris.h"
#include "sharedDefs.h"

template <OSPlatformType osType>
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
class FactoryNetworkFamilyCreator<OSPlatformType::LINUX> final
{
    public:
        static std::shared_ptr<IOSNetwork> create(const std::shared_ptr<INetworkInterfaceWrapper>& interfaceWrapper)
        {
            return FactoryLinuxNetwork::create(interfaceWrapper);
        }
};

template <>
class FactoryNetworkFamilyCreator<OSPlatformType::BSDBASED> final
{
    public:
        static std::shared_ptr<IOSNetwork> create(const std::shared_ptr<INetworkInterfaceWrapper>& interfaceWrapper)
        {
            return FactoryBSDNetwork::create(interfaceWrapper);
        }
};

template <>
class FactoryNetworkFamilyCreator<OSPlatformType::WINDOWS> final
{
    public:
        static std::shared_ptr<IOSNetwork> create(const std::shared_ptr<INetworkInterfaceWrapper>& interfaceWrapper)
        {
            return FactoryWindowsNetwork::create(interfaceWrapper);
        }
};

template <>
class FactoryNetworkFamilyCreator<OSPlatformType::SOLARIS> final
{
    public:
        static std::shared_ptr<IOSNetwork> create(const std::shared_ptr<INetworkInterfaceWrapper>& interfaceWrapper)
        {
            return FactorySolarisNetwork::create(interfaceWrapper);
        }
};

#endif // _NETWORK_FAMILY_DATA_AFACTORY_H
