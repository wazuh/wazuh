/*
 * Wazuh SYSCOLLECTOR
 * Copyright (C) 2015-2020, Wazuh Inc.
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

class INetworkWrappers
{
public:
    // LCOV_EXCL_START
    virtual ~INetworkWrappers() = default;
    // LCOV_EXCL_STOP
    virtual std::string type() = 0;
    virtual std::string name() = 0;
    virtual std::string state() = 0;
    virtual std::string MAC() = 0;
};

class INetworkInterfaceWrapper
{
public:
    // LCOV_EXCL_START
    virtual ~INetworkInterfaceWrapper() = default;
    // LCOV_EXCL_STOP
    virtual int family() = 0;
    virtual std::string name() = 0;
    virtual std::string address() = 0;
    virtual std::string netmask() = 0;
    virtual std::string broadcast() = 0;
    virtual std::string addressV6() = 0;
    virtual std::string netmaskV6() = 0;
    virtual std::string broadcastV6() = 0;
    virtual std::string gateway() = 0;
    virtual std::string dhcp() = 0;
    virtual std::string mtu() = 0;
    virtual LinkStats stats() = 0;
    virtual std::string type() = 0;
    virtual std::string state() = 0;
    virtual std::string MAC() = 0;
};
#endif // _NETWORK_INTERFACE_WRAPPER_H
