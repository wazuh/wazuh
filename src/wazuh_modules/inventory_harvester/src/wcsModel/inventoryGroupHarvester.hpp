/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * June 16, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVENTORY_GROUP_HARVESTER_HPP
#define _INVENTORY_GROUP_HARVESTER_HPP

#include "reflectiveJson.hpp"
#include "wcsClasses/agent.hpp"
#include "wcsClasses/wazuh.hpp"
#include "wcsClasses/group.hpp"

struct InventoryGroupHarvester final {
    Agent agent;
    Group group;
    Wazuh wazuh;

    REFLECTABLE(MAKE_FIELD("agent", &InventoryGroupHarvester::agent),
                MAKE_FIELD("group", &InventoryGroupHarvester::group),
                MAKE_FIELD("wazuh", &InventoryGroupHarvester::wazuh));
};

#endif // _INVENTORY_GROUP_HARVESTER_HPP