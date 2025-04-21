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

#ifndef _REGISTRY_VALUE_ELEMENT_HPP
#define _REGISTRY_VALUE_ELEMENT_HPP

#include "../../wcsModel/data.hpp"
#include "../../wcsModel/fimRegistryHarvester.hpp"
#include "../../wcsModel/noData.hpp"
#include "../policyHarvesterManager.hpp"
#include "stringHelper.h"

template<typename TContext>
class RegistryValueElement final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~RegistryValueElement() = default;
    // LCOV_EXCL_STOP

    static DataHarvester<FimRegistryInventoryHarvester> build(TContext* data)
    {
        DataHarvester<FimRegistryInventoryHarvester> element;

        auto agentId = data->agentId();
        if (agentId.empty())
        {
            throw std::runtime_error("Agent ID is empty, cannot upsert FIM value element.");
        }

        element.id = agentId;
        element.id += "_";
        element.id += data->hashPath();
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
        element.data.registry.path = data->path();
        element.data.registry.value = data->valueName();

        element.data.registry.data.hash.md5 = data->md5();
        element.data.registry.data.hash.sha1 = data->sha1();
        element.data.registry.data.hash.sha256 = data->sha256();
        element.data.registry.data.type = data->valueType();

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
        NoDataHarvester element;

        auto agentId = data->agentId();
        if (agentId.empty())
        {
            throw std::runtime_error("Agent ID is empty, cannot delete FIM value element.");
        }

        element.operation = "DELETED";
        element.id = agentId;
        element.id += "_";
        element.id += data->hashPath();

        return element;
    }
};

#endif // _REGISTRY_VALUE_ELEMENT_HPP
