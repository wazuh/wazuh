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

#ifndef _NETWORK_LINUX_WRAPPER_H
#define _NETWORK_LINUX_WRAPPER_H

#include "inetworkWrapper.h"

class NetworkSolarisInterface final : public INetworkInterfaceWrapper
{
    public:
        explicit NetworkSolarisInterface(addrs* addrs)
        {
        }

        std::string name() const override
        {
            return "";
        }

        std::string adapter() const override
        {
            return "";
        }

        int family() const override
        {
            return AF_UNSPEC;
        }

        std::string address() const override
        {
            return "";
        }

        std::string netmask() const override
        {
            return "";
        }

        std::string broadcast() const override
        {
            std::string retVal { UNKNOWN_VALUE };
            return retVal;
        }

        std::string addressV6() const override
        {
            return "";
        }

        std::string netmaskV6() const override
        {
            return "";
        }

        std::string broadcastV6() const override
        {
            return "";
        }

        std::string gateway() const override
        {
            return "";
        }

        std::string metrics() const override
        {
            return "";
        }

        std::string metricsV6() const override
        {
            return "";
        }

        std::string dhcp() const override
        {
            std::string retVal { "unknown" };
            return retVal;
        }

        uint32_t mtu() const override
        {
            uint32_t retVal { 0 };
            return retVal;
        }

        LinkStats stats() const override
        {
            return LinkStats();
        }

        std::string type() const override
        {
            std::string type { UNKNOWN_VALUE };
            return type;
        }

        std::string state() const override
        {
            std::string state { UNKNOWN_VALUE };
            return state;
        }

        std::string MAC() const override
        {
            std::string mac { UNKNOWN_VALUE };
            return mac;
        }
};

#endif // _NETWORK_LINUX_WRAPPER_H
