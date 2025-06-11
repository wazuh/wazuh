/*
 * Wazuh Inventory Harvester - Network Protocol element
 * Copyright (C) 2015, Wazuh Inc.
 * March 27, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _NETWORK_PROTOCOL_ELEMENT_HPP
#define _NETWORK_PROTOCOL_ELEMENT_HPP

#include "../../wcsModel/data.hpp"
#include "../../wcsModel/inventoryNetworkProtocolHarvester.hpp"
#include "../../wcsModel/noData.hpp"
#include "../policyHarvesterManager.hpp"
#include <stdexcept>

template<typename TContext>
class NetworkProtocolElement final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~NetworkProtocolElement() = default;
    // LCOV_EXCL_STOP

    static DataHarvester<InventoryNetworkProtocolHarvester> build(TContext* data)
    {
        auto agentId = data->agentId();
        if (agentId.empty())
        {
            throw std::runtime_error("Agent ID is empty, cannot upsert network protocol element.");
        }

        auto netProtoItemId = data->netProtoItemId();
        if (netProtoItemId.empty())
        {
            throw std::runtime_error("Network Protocol ID is empty, cannot upsert network protocol element.");
        }

        DataHarvester<InventoryNetworkProtocolHarvester> element;
        element.id = agentId;
        element.id += "_";
        element.id += netProtoItemId;

        element.operation = "INSERTED";

        element.data.agent.id = agentId;
        element.data.agent.name = data->agentName();
        element.data.agent.version = data->agentVersion();

        if (auto agentIp = data->agentIp(); agentIp.compare("any") != 0)
        {
            element.data.agent.host.ip = agentIp;
        }

        element.data.network.dhcp = data->netProtoDhcp().compare("enabled") == 0 ? true : false;

        // Gateway separator ","
        if (auto networkGateway = data->netProtoGateway();
            networkGateway.compare(" ") != 0 && networkGateway.find(',') == std::string_view::npos)
        {
            element.data.network.gateway = networkGateway;
        }

        element.data.network.metric = data->netProtoMetric();
        element.data.network.type = data->netProtoType();

        element.data.interface.name = data->netProtoIface();

        auto& instancePolicyManager = PolicyHarvesterManager::instance();
        element.data.wazuh.cluster.name = instancePolicyManager.getClusterName();
        if (instancePolicyManager.getClusterStatus())
        {
            element.data.wazuh.cluster.node = instancePolicyManager.getClusterNodeName();
        }

        return element;
    }

    static NoDataHarvester deleteElement(TContext* data)
    {
        auto agentId = data->agentId();
        if (agentId.empty())
        {
            throw std::runtime_error("Agent ID is empty, cannot delete network protocol element.");
        }

        auto netProtoItemId = data->netProtoItemId();
        if (netProtoItemId.empty())
        {
            throw std::runtime_error("Network Protocol ID is empty, cannot delete network protocol element.");
        }

        NoDataHarvester element;

        element.id = agentId;
        element.id += "_";
        element.id += netProtoItemId;

        element.operation = "DELETED";

        return element;
    }
};

#endif // _NETWORK_PROTOCOL_ELEMENT_HPP
