/*
 * Wazuh Inventory Harvester - Port element
 * Copyright (C) 2015, Wazuh Inc.
 * March 20, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PORT_ELEMENT_HPP
#define _PORT_ELEMENT_HPP

#include "../../wcsModel/data.hpp"
#include "../../wcsModel/inventoryPortHarvester.hpp"
#include "../../wcsModel/noData.hpp"
#include "../policyHarvesterManager.hpp"
#include <stdexcept>

template<typename TContext>
class PortElement final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~PortElement() = default;
    // LCOV_EXCL_STOP

    static DataHarvester<InventoryPortHarvester> build(TContext* data)
    {
        auto agentId = data->agentId();
        if (agentId.empty())
        {
            throw std::runtime_error("Agent ID is empty, cannot upsert port element.");
        }

        auto portItemId = data->portItemId();
        if (portItemId.empty())
        {
            throw std::runtime_error("Item ID is empty, cannot upsert port element.");
        }

        DataHarvester<InventoryPortHarvester> element;
        element.id = agentId;
        element.id += "_";
        element.id += portItemId;
        element.operation = "INSERTED";
        element.data.agent.id = agentId;
        element.data.agent.name = data->agentName();
        element.data.agent.version = data->agentVersion();

        if (auto agentIp = data->agentIp(); agentIp.compare("any") != 0)
        {
            element.data.agent.host.ip = agentIp;
        }

        element.data.destination.ip = data->portRemoteIp();
        element.data.destination.port = data->portRemotePort();
        element.data.file.inode = std::to_string(data->portInode());
        element.data.host.network.egress.queue = data->portTxQueue();
        element.data.host.network.ingress.queue = data->portRxQueue();
        element.data.interface.state = data->portState();
        element.data.network.transport = data->portProtocol();
        element.data.process.name = data->portProcess();
        element.data.process.pid = data->portPid();
        element.data.source.ip = data->portLocalIp();
        element.data.source.port = data->portLocalPort();

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
            throw std::runtime_error("Agent ID is empty, cannot delete port element.");
        }

        auto portItemId = data->portItemId();
        if (portItemId.empty())
        {
            throw std::runtime_error("Item ID is empty, cannot delete port element.");
        }

        NoDataHarvester element;
        element.operation = "DELETED";
        element.id = agentId;
        element.id += "_";
        element.id += portItemId;
        return element;
    }
};

#endif // _PORT_ELEMENT_HPP
