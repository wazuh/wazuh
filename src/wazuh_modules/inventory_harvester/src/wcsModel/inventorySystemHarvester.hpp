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

#ifndef _INVENTORY_SYSTEM_HARVESTER_HPP
#define _INVENTORY_SYSTEM_HARVESTER_HPP

#include "reflectiveJson.hpp"
#include "wcsClasses/agent.hpp"

struct InventorySystemHarvester
{
    Agent agent;

    REFLECTABLE(MAKE_FIELD("agent", &InventorySystemHarvester::agent));
};

#endif // _INVENTORY_SYSTEM_HARVESTER_HPP
