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

#ifndef _INVENTORY_USER_HARVESTER_HPP
#define _INVENTORY_USER_HARVESTER_HPP

#include "reflectiveJson.hpp"
#include "wcsClasses/agent.hpp"
#include "wcsClasses/wazuh.hpp"
#include "wcsClasses/user.hpp"

struct InventoryUserHarvester final {
    Agent agent;
    User user;
    Wazuh wazuh;
    Host host;
    Login login;
    Process process;

    REFLECTABLE(MAKE_FIELD("agent", &InventoryUserHarvester::agent),
                MAKE_FIELD("user", &InventoryUserHarvester::user),
                MAKE_FIELD("wazuh", &InventoryUserHarvester::wazuh),
                MAKE_FIELD("host", &InventoryUserHarvester::host),
                MAKE_FIELD("login", &InventoryUserHarvester::login),
                MAKE_FIELD("process", &InventoryUserHarvester::process));
};

#endif // _INVENTORY_USER_HARVESTER_HPP