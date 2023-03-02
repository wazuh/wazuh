/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * March 9, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PROCESS_INTERFACE_H
#define _PROCESS_INTERFACE_H

#include "json.hpp"

class IOSProcess
{
    public:
        // LCOV_EXCL_START
        virtual ~IOSProcess() = default;
        // LCOV_EXCL_STOP
        virtual void buildProcessData(nlohmann::json& process) = 0;
};

#endif // _PROCESS_INTERFACE_H
