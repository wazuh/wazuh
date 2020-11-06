/*
 * Wazuh SYSCOLLECTOR
 * Copyright (C) 2015-2020, Wazuh Inc.
 * November 3, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PORT_BSD_WRAPPER_H
#define _PORT_BSD_WRAPPER_H

#include "iportWrapper.h"
#include "sharedDefs.h"


class BSDPortWrapper final : public IPortWrapper
{
    public:
    BSDPortWrapper() = default;
    ~BSDPortWrapper() = default;
    std::string protocol() const override
    {
        return {};
    }
    std::string localIp() const override
    {
        return {};
    }
    int32_t localPort() const override
    {
        return {};
    }
    std::string remoteIP() const override
    {
        return {};
    }
    int32_t remotePort() const override
    {
        return {};
    }
    int32_t txQueue() const override
    {
        return {};
    }
    int32_t rxQueue() const override
    {
        return {};
    }
    int32_t inode() const override
    {
        return {};
    }
    std::string state() const override
    {
        return {};
    }
};


#endif //_PORT_BSD_WRAPPER_H
