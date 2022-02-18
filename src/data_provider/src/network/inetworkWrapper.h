/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * October 26, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _NETWORK_INTERFACE_WRAPPER_H
#define _NETWORK_INTERFACE_WRAPPER_H
#include "inetworkInterface.h"

class INetworkInterfaceWrapper
{
    public:
        // LCOV_EXCL_START
        virtual ~INetworkInterfaceWrapper() = default;
        // LCOV_EXCL_STOP
        virtual int family() const = 0;
        virtual std::string name() const = 0;
        virtual std::string adapter() const = 0;
        virtual std::string address() const = 0;
        virtual std::string netmask() const = 0;
        virtual std::string broadcast() const = 0;
        virtual std::string addressV6() const = 0;
        virtual std::string netmaskV6() const = 0;
        virtual std::string broadcastV6() const = 0;
        virtual std::string gateway() const = 0;
        virtual std::string metrics() const = 0;
        virtual std::string metricsV6() const = 0;
        virtual std::string dhcp() const = 0;
        virtual uint32_t mtu() const = 0;
        virtual LinkStats stats() const = 0;
        virtual std::string type() const = 0;
        virtual std::string state() const = 0;
        virtual std::string MAC() const = 0;
};
#endif // _NETWORK_INTERFACE_WRAPPER_H
