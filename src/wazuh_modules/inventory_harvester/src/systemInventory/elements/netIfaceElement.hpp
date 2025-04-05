/*
 * Wazuh Inventory Harvester - Network Interface element
 * Copyright (C) 2015, Wazuh Inc.
 * Match 25, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _NETIFACE_ELEMENT_HPP
#define _NETIFACE_ELEMENT_HPP

#include "../../wcsModel/data.hpp"
#include "../../wcsModel/inventoryNetIfaceHarvester.hpp"
#include "../../wcsModel/noData.hpp"
#include "../policyHarvesterManager.hpp"
#include "stringHelper.h"
#include <loggerHelper.h>

template<typename TContext>
class NetIfaceElement final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~NetIfaceElement() = default;
    // LCOV_EXCL_STOP

    static DataHarvester<InventoryNetIfaceHarvester> build(TContext* data)
    {
        auto agentId = data->agentId();
        if (agentId.empty())
        {
            throw std::runtime_error("Agent ID is empty");
        }

        auto netIfaceItemId = data->netIfaceItemId();
        if (netIfaceItemId.empty())
        {
            throw std::runtime_error("NetIface item ID is empty");
        }

        DataHarvester<InventoryNetIfaceHarvester> element;
        element.id = agentId;
        element.id += "_";
        element.id += netIfaceItemId;
        element.operation = "INSERTED";

        element.data.agent.id = agentId;
        element.data.agent.name = data->agentName();
        element.data.agent.version = data->agentVersion();

        if (auto agentIp = data->agentIp(); agentIp.compare("any") != 0)
        {
            element.data.agent.host.ip = agentIp;
        }

        element.data.host.mac = data->netIfaceMac();
        element.data.host.network.ingress.bytes = data->netIfaceRxBytes();
        element.data.host.network.ingress.drops = data->netIfaceRxDrops();
        element.data.host.network.ingress.errors = data->netIfaceRxErrors();
        element.data.host.network.ingress.packets = data->netIfaceRxPackets();
        element.data.host.network.egress.bytes = data->netIfaceTxBytes();
        element.data.host.network.egress.drops = data->netIfaceTxDrops();
        element.data.host.network.egress.errors = data->netIfaceTxErrors();
        element.data.host.network.egress.packets = data->netIfaceTxPackets();

        element.data.observer.ingress.interface.alias = data->netIfaceAdapter();
        element.data.observer.ingress.interface.name = data->netIfaceName();
        element.data.observer.ingress.interface.mtu = data->netIfaceMtu();
        element.data.observer.ingress.interface.state = data->netIfaceState();
        element.data.observer.ingress.interface.type = data->netIfaceType();

        auto& instancePolicyManager = PolicyHarvesterManager::instance();
        if (instancePolicyManager.getClusterStatus())
        {
            element.data.wazuh.cluster.name = instancePolicyManager.getClusterName();
            element.data.wazuh.cluster.node = instancePolicyManager.getClusterNodeName();
        }

        return element;
    }

    static NoDataHarvester deleteElement(TContext* data)
    {
        auto agentId = data->agentId();
        if (agentId.empty())
        {
            throw std::runtime_error("Agent ID is empty");
        }

        auto netIfaceItemId = data->netIfaceItemId();
        if (netIfaceItemId.empty())
        {
            throw std::runtime_error("NetIface item ID is empty");
        }

        NoDataHarvester element;
        element.operation = "DELETED";
        element.id = agentId;
        element.id += "_";
        element.id += netIfaceItemId;
        return element;
    }
};

#endif // _NETIFACE_ELEMENT_HPP
