/*
 * Wazuh Inventory Harvester - Service element
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVENTORY_SERVICE_HARVESTER_HPP
#define _INVENTORY_SERVICE_HARVESTER_HPP

#include "reflectiveJson.hpp"
#include "wcsClasses/agent.hpp"
#include "wcsClasses/service.hpp"
#include "wcsClasses/wazuh.hpp"

struct InventoryServiceHarvester final
{
    Agent agent;
    Service::ServiceInfo service;
    Service::Process process;
    Service::User user;
    Service::File file;
    Wazuh wazuh;

    REFLECTABLE(MAKE_FIELD("service", &InventoryServiceHarvester::service),
                MAKE_FIELD("process", &InventoryServiceHarvester::process),
                MAKE_FIELD("user", &InventoryServiceHarvester::user),
                MAKE_FIELD("file", &InventoryServiceHarvester::file),
                MAKE_FIELD("agent", &InventoryServiceHarvester::agent),
                MAKE_FIELD("wazuh", &InventoryServiceHarvester::wazuh));
};

#endif // _INVENTORY_SERVICE_HARVESTER_HPP
