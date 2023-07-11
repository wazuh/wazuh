/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * May 4, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HARDWARE_INTERFACE_H
#define _HARDWARE_INTERFACE_H

#include "json.hpp"

class IOSHardware
{
    public:
        // LCOV_EXCL_START
        virtual ~IOSHardware() = default;
        // LCOV_EXCL_STOP
        virtual void buildHardwareData(nlohmann::json& hardware) = 0;
};

#endif // _HARDWARE_INTERFACE_H
