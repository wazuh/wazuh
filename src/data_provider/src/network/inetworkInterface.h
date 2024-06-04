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

#ifndef _NETWORK_INTERFACE_H
#define _NETWORK_INTERFACE_H

#include "json.hpp"

class IOSNetwork
{
    public:
        // LCOV_EXCL_START
        virtual ~IOSNetwork() = default;
        // LCOV_EXCL_STOP
        virtual void buildNetworkData(nlohmann::json& network) = 0;
};


struct LinkStats
{
    unsigned int rxPackets;    /* total packets received */
    unsigned int txPackets;    /* total packets transmitted */
    int64_t rxBytes;                /* total bytes received */
    int64_t txBytes;                /* total bytes transmitted */
    unsigned int rxErrors;     /* bad packets received */
    unsigned int txErrors;     /* packet transmit problems */
    unsigned int rxDropped;    /* no space in linux buffers */
    unsigned int txDropped;    /* no space available in linux */
};

#endif // _NETWORK_INTERFACE_H