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

#ifndef _NETWORK_FAMILY_DATA_AFACTORY_H
#define _NETWORK_FAMILY_DATA_AFACTORY_H

#include "json.hpp"
#include "networkInterfaceLinux.h"
#include "networkInterfaceBSD.h"

enum OSType
{
    LINUX,
    BSD,
    MACOS
};

template <OSType osType>
class FactoryNetworkFamilyCreator final
{
public:
    static std::shared_ptr<IOSNetwork> create(const sa_family_t osNetworkType)
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
    static std::shared_ptr<IOSNetwork> create(const sa_family_t osNetworkType)
    {
        return FactoryLinuxNetwork::create(osNetworkType);
    }
};

template <>
class FactoryNetworkFamilyCreator<OSType::BSD> final
{
public:
    static std::shared_ptr<IOSNetwork> create(const sa_family_t osNetworkType)
    {
        return FactoryBSDNetwork::create(osNetworkType);
    }
};    


#endif // _NETWORK_FAMILY_DATA_AFACTORY_H