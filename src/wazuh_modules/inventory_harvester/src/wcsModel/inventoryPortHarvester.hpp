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

#ifndef _INVENTORY_PORT_HARVESTER_HPP
#define _INVENTORY_PORT_HARVESTER_HPP

#include "reflectiveJson.hpp"
#include "wcsClasses/agent.hpp"
#include "wcsClasses/interface.hpp"
#include "wcsClasses/port.hpp"
#include "wcsClasses/transport.hpp"
#include "wcsClasses/wazuh.hpp"

struct InventoryPortHarvester final
{
    Agent agent;
    NAT destination;
    PortFile file;
    NetHost host;
    NetworkInterface interface;
    NetworkTransport network;
    PortProcess process;
    NAT source;
    Wazuh wazuh;

    REFLECTABLE(MAKE_FIELD("agent", &InventoryPortHarvester::agent),
                MAKE_FIELD("destination", &InventoryPortHarvester::destination),
                MAKE_FIELD("file", &InventoryPortHarvester::file),
                MAKE_FIELD("host", &InventoryPortHarvester::host),
                MAKE_FIELD("interface", &InventoryPortHarvester::interface),
                MAKE_FIELD("network", &InventoryPortHarvester::network),
                MAKE_FIELD("process", &InventoryPortHarvester::process),
                MAKE_FIELD("source", &InventoryPortHarvester::source),
                MAKE_FIELD("wazuh", &InventoryPortHarvester::wazuh));
};

#endif // _INVENTORY_PORT_HARVESTER_HPP
