/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * March 21, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVENTORY_HOTFIX_HARVESTER_HPP
#define _INVENTORY_HOTFIX_HARVESTER_HPP

#include "reflectiveJson.hpp"
#include "wcsClasses/agent.hpp"
#include "wcsClasses/hotfix.hpp"

struct InventoryHotfixHarvester final
{
    Agent agent;
    Hotfix package;

    REFLECTABLE(MAKE_FIELD("package", &InventoryHotfixHarvester::package),
                MAKE_FIELD("agent", &InventoryHotfixHarvester::agent));
};

#endif // _INVENTORY_HOTFIX_HARVESTER_HPP
