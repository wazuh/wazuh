/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * December 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGE_INTERFACE_H
#define _PACKAGE_INTERFACE_H

#include "json.hpp"

class IPackage
{
    public:
        // LCOV_EXCL_START
        virtual ~IPackage() = default;
        // LCOV_EXCL_STOP
        virtual void buildPackageData(nlohmann::json& package) = 0;
};

#endif // _PACKAGE_INTERFACE_H