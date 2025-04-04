/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * March 20, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVENTORY_NETWORK_HARVESTER_HPP
#define _INVENTORY_NETWORK_HARVESTER_HPP

#include "reflectiveJson.hpp"
#include "wcsClasses/agent.hpp"
#include "wcsClasses/networkAddress.hpp"

struct InventoryNetworkHarvester final
{

    Agent agent;
    NetworkAddress network;

    REFLECTABLE(MAKE_FIELD("network", &InventoryNetworkHarvester::network),
                MAKE_FIELD("agent", &InventoryNetworkHarvester::agent));
};

#endif // _INVENTORY_NETWORK_HARVESTER_HPP
