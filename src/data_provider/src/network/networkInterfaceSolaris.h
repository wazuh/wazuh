/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * December 21, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _NETWORK_INTERFACE_SOLARIS_H
#define _NETWORK_INTERFACE_SOLARIS_H
#include <stdexcept>

#include "inetworkInterface.h"
#include "inetworkWrapper.h"

class FactorySolarisNetwork
{
    public:
        static std::shared_ptr<IOSNetwork>create(const std::shared_ptr<INetworkInterfaceWrapper>& interfaceWrapper);
};

template <unsigned short osNetworkType>
class SolarisNetworkImpl final : public IOSNetwork
{
        std::shared_ptr<INetworkInterfaceWrapper> m_interfaceAddress;
    public:
        explicit SolarisNetworkImpl(const std::shared_ptr<INetworkInterfaceWrapper>& interfaceAddress)
            : m_interfaceAddress(interfaceAddress)
        { }
        // LCOV_EXCL_START
        ~SolarisNetworkImpl() = default;
        // LCOV_EXCL_STOP
        void buildNetworkData(nlohmann::json& /*network*/) override
        {
            throw std::runtime_error { "Specialization not implemented" };
        }
};

#endif // _NETWORK_INTERFACE_SOLARIS_H
