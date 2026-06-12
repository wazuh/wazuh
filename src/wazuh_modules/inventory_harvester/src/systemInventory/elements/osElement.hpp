/*
 * Wazuh Inventory Harvester - OS element
 * Copyright (C) 2015, Wazuh Inc.
 * January 22, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OS_ELEMENT_HPP
#define _OS_ELEMENT_HPP

#include "../../wcsModel/data.hpp"
#include "../../wcsModel/inventorySystemHarvester.hpp"
#include "../../wcsModel/noData.hpp"
#include "../policyHarvesterManager.hpp"
#include <stdexcept>

template<typename TContext>
class OsElement final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~OsElement() = default;
    // LCOV_EXCL_STOP

    static DataHarvester<InventorySystemHarvester> build(TContext* data)
    {
        auto agentId = data->agentId();
        if (agentId.empty())
        {
            throw std::runtime_error("Agent ID is empty, cannot upsert system element.");
        }

        DataHarvester<InventorySystemHarvester> element;
        element.id = agentId;
        element.id += "_";
        auto osName = data->osName();
        element.id += osName;

        element.operation = "INSERTED";
        element.data.agent.id = agentId;
        element.data.agent.name = data->agentName();
        element.data.agent.version = data->agentVersion();

        if (auto agentIp = data->agentIp(); agentIp.compare("any") != 0)
        {
            element.data.agent.host.ip = agentIp;
        }

        element.data.host.architecture = data->osArchitecture();
        element.data.host.hostname = data->osHostName();

        element.data.host.os.kernel.release = data->osKernelRelease();
        element.data.host.os.kernel.name = data->osKernelSysName();
        element.data.host.os.kernel.version = data->osKernelVersion();

        element.data.host.os.codename = data->osCodeName();
        element.data.host.os.name = osName;
        element.data.host.os.platform = data->osPlatform();
        element.data.host.os.version = data->osVersion();

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
            throw std::runtime_error("Agent ID is empty, cannot delete system element.");
        }

        NoDataHarvester element;
        element.operation = "DELETED";

        element.id = agentId;
        element.id += "_";
        auto osName = data->osName();
        element.id += osName;

        return element;
    }
};

#endif // _OS_ELEMENT_HPP
