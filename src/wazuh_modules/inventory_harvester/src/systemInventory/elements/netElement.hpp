/*
 * Wazuh Inventory Harvester - Net address element
 * Copyright (C) 2015, Wazuh Inc.
 * March 20, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _NET_ELEMENT_HPP
#define _NET_ELEMENT_HPP

#include "../../wcsModel/data.hpp"
#include "../../wcsModel/inventoryNetworkHarvester.hpp"
#include "../../wcsModel/noData.hpp"
#include "../policyHarvesterManager.hpp"
#include <stdexcept>

template<typename TContext>
class NetElement final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~NetElement() = default;
    // LCOV_EXCL_STOP

    static DataHarvester<InventoryNetworkHarvester> build(TContext* data)
    {
        auto agentId = data->agentId();
        if (agentId.empty())
        {
            throw std::runtime_error("Agent ID is empty, cannot upsert network element.");
        }
        auto netItemId = data->netAddressItemId();
        if (netItemId.empty())
        {
            throw std::runtime_error("NetAddress item ID is empty, cannot upsert network element.");
        }

        DataHarvester<InventoryNetworkHarvester> element;
        element.id = agentId;
        element.id += "_";
        element.id += netItemId;
        element.operation = "INSERTED";
        element.data.agent.id = agentId;
        element.data.agent.name = data->agentName();
        element.data.agent.version = data->agentVersion();

        if (auto agentIp = data->agentIp(); agentIp.compare("any") != 0)
        {
            element.data.agent.host.ip = agentIp;
        }

        // Ex: 192.168.0.255
        element.data.network.broadcast = data->broadcast();

        // Ex: 192.168.0.30
        element.data.network.ip = data->agentIp();

        // Ex: eth0
        element.data.network.name = data->netAddressName();

        // 255.255.255.0
        element.data.network.netmask = data->netmask();

        // Ex: IPv4
        if (!data->protocol())
        {
            element.data.network.protocol = "IPv4";
        }
        else
        {
            element.data.network.protocol = "IPv6";
        }

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
            throw std::runtime_error("Agent ID is empty, cannot delete network element.");
        }

        auto netItemId = data->netAddressItemId();
        if (netItemId.empty())
        {
            throw std::runtime_error("NetAddress item ID is empty, cannot delete network element.");
        }

        NoDataHarvester element;
        element.operation = "DELETED";
        element.id = agentId;
        element.id += "_";
        element.id += netItemId;
        return element;
    }
};

#endif // _NET_ELEMENT_HPP
