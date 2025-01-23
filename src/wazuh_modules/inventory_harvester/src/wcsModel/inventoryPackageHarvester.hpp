/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * January 14, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVENTORY_PACKAGE_HARVESTER_HPP
#define _INVENTORY_PACKAGE_HARVESTER_HPP

#include "reflectiveJson.hpp"
#include "wcsClasses/agent.hpp"
#include "wcsClasses/package.hpp"

struct InventoryPackageHarvester
{
    Agent agent;
    Package package;

    REFLECTABLE(MAKE_FIELD("package", &InventoryPackageHarvester::package),
                MAKE_FIELD("agent", &InventoryPackageHarvester::agent));
};

#endif // _INVENTORY_PACKAGE_HARVESTER_HPP
