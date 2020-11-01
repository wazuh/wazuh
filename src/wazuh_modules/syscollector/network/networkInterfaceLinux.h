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

#ifndef _NETWORK_LINUX_H
#define _NETWORK_LINUX_H

#include "inetworkInterface.h"

class FactoryLinuxNetwork
{
    public:
    static std::shared_ptr<IOSNetwork>create(const sa_family_t osNetworkType);
};

template <sa_family_t osNetworkType>
class LinuxNetworkImpl final : public IOSNetwork
{
public:
    // LCOV_EXCL_START
    ~LinuxNetworkImpl() = default;
    // LCOV_EXCL_STOP
    void buildNetworkData(const ifaddrs* /*interfaceAddress*/, nlohmann::json& /*network*/) override
    {
        throw std::runtime_error("Non implemented specialization.");
    }
};

#endif // _NETWORK_LINUX_H