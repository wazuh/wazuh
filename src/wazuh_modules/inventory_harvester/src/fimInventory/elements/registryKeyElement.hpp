/*
 * Wazuh Vulnerability scanner - Scan Orchestrator
 * Copyright (C) 2015, Wazuh Inc.
 * January 22, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REGISTRY_KEY_ELEMENT_HPP
#define _REGISTRY_KEY_ELEMENT_HPP

#include "../../wcsModel/data.hpp"
#include "../../wcsModel/fimRegistryHarvester.hpp"
#include "../../wcsModel/noData.hpp"
#include "../policyHarvesterManager.hpp"
#include "stringHelper.h"
#include "timeHelper.h"

template<typename TContext>
class RegistryKeyElement final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~RegistryKeyElement() = default;
    // LCOV_EXCL_STOP

    static DataHarvester<FimRegistryInventoryHarvester> build(TContext* data)
    {
        DataHarvester<FimRegistryInventoryHarvester> element;

        auto agentId = data->agentId();
        if (agentId.empty())
        {
            throw std::runtime_error("Agent ID is empty, cannot upsert FIM registry key element.");
        }

        element.id = agentId;
        element.id += "_";
        element.id += data->index();
        element.operation = "INSERTED";

        element.data.agent.id = agentId;
        element.data.agent.name = data->agentName();
        element.data.agent.version = data->agentVersion();

        if (auto agentIp = data->agentIp(); agentIp.compare("any") != 0)
        {
            element.data.agent.host.ip = agentIp;
        }

        element.data.registry.hive = data->hive();
        element.data.registry.key = data->key();
        element.data.registry.uid = data->uid();
        element.data.registry.owner = data->userName();
        element.data.registry.gid = data->gid();
        element.data.registry.group = data->groupName();
        element.data.registry.architecture = data->arch();
        element.data.registry.mtime = data->mtimeISO8601();
        element.data.registry.path = data->path();

        element.data.event.category = data->elementType();

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
        NoDataHarvester element;

        auto agentId = data->agentId();
        if (agentId.empty())
        {
            throw std::runtime_error("Agent ID is empty, cannot delete FIM registry key element.");
        }

        element.operation = "DELETED";
        element.id = agentId;
        element.id += "_";
        element.id += data->index();
        return element;
    }
};

#endif // _REGISTRY_KEY_ELEMENT_HPP
