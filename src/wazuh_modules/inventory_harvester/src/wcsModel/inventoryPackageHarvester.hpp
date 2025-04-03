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
#include "wcsClasses/wazuh.hpp"

struct InventoryPackageHarvester final
{
    Agent agent;
    Package package;
    Wazuh wazuh;

    REFLECTABLE(MAKE_FIELD("package", &InventoryPackageHarvester::package),
                MAKE_FIELD("agent", &InventoryPackageHarvester::agent),
                MAKE_FIELD("wazuh", &InventoryPackageHarvester::wazuh));
};

#endif // _INVENTORY_PACKAGE_HARVESTER_HPP
