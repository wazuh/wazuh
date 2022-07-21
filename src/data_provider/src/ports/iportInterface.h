/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * November 3, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PORT_INTERFACE_H
#define _PORT_INTERFACE_H

#include <memory>
#include "json.hpp"

class IOSPort
{
    public:
        // LCOV_EXCL_START
        virtual ~IOSPort() = default;
        // LCOV_EXCL_STOP
        virtual void buildPortData(nlohmann::json& port) = 0;
};

#endif // _PORT_INTERFACE_H