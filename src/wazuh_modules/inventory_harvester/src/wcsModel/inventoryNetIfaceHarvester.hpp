/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVENTORY_NETIFACE_HARVESTER_HPP
#define _INVENTORY_NETIFACE_HARVESTER_HPP

#include "reflectiveJson.hpp"
#include "wcsClasses/agent.hpp"
#include "wcsClasses/netIface.hpp"
#include "wcsClasses/netpackets.hpp"
#include "wcsClasses/wazuh.hpp"

struct InventoryNetIfaceHarvester final
{
    struct NetIfaceHost final
    {
        struct NetIfaceInOut final
        {
            NetPackets ingress;
            NetPackets egress;

            REFLECTABLE(MAKE_FIELD("ingress", &NetIfaceInOut::ingress), MAKE_FIELD("egress", &NetIfaceInOut::egress));
        };

        std::string_view mac;
        NetIfaceInOut network;

        REFLECTABLE(MAKE_FIELD("mac", &NetIfaceHost::mac), MAKE_FIELD("network", &NetIfaceHost::network));
    };

    struct NetIfaceObserver final
    {
        struct NetIfaceIngress final
        {
            NetIface interface;

            REFLECTABLE(MAKE_FIELD("interface", &NetIfaceIngress::interface));
        };

        NetIfaceIngress ingress;

        REFLECTABLE(MAKE_FIELD("ingress", &NetIfaceObserver::ingress));
    };

    Agent agent;
    NetIfaceHost host;
    NetIfaceObserver observer;
    Wazuh wazuh;

    REFLECTABLE(MAKE_FIELD("agent", &InventoryNetIfaceHarvester::agent),
                MAKE_FIELD("host", &InventoryNetIfaceHarvester::host),
                MAKE_FIELD("observer", &InventoryNetIfaceHarvester::observer),
                MAKE_FIELD("wazuh", &InventoryNetIfaceHarvester::wazuh));
};

#endif // _INVENTORY_NETIFACE_HARVESTER_HPP
