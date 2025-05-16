/*
 * Wazuh Inventory Harvester - Process element
 * Copyright (C) 2015, Wazuh Inc.
 * January 22, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PROCESS_ELEMENT_HPP
#define _PROCESS_ELEMENT_HPP

#include "../../wcsModel/data.hpp"
#include "../../wcsModel/inventoryProcessHarvester.hpp"
#include "../../wcsModel/noData.hpp"
#include "../policyHarvesterManager.hpp"
#include "stringHelper.h"
#include <loggerHelper.h>

template<typename TContext>
class ProcessElement final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~ProcessElement() = default;
    // LCOV_EXCL_STOP

    static DataHarvester<InventoryProcessHarvester> build(TContext* data)
    {
        auto agentId = data->agentId();
        if (agentId.empty())
        {
            throw std::runtime_error("Agent ID is empty");
        }

        auto processId = data->processId();
        if (processId.empty())
        {
            throw std::runtime_error("Process ID is empty");
        }

        DataHarvester<InventoryProcessHarvester> element;
        element.id = agentId;
        element.id += "_";
        element.id += processId;
        element.operation = "INSERTED";

        element.data.agent.id = agentId;
        element.data.agent.name = data->agentName();
        element.data.agent.version = data->agentVersion();

        if (auto agentIp = data->agentIp(); agentIp.compare("any") != 0)
        {
            element.data.agent.host.ip = agentIp;
        }

        element.data.process.args = data->processArguments();
        element.data.process.args_count = element.data.process.args.size();
        element.data.process.command_line = data->processCmdline();
        element.data.process.name = data->processName();
        element.data.process.pid = std::stoull(std::string(processId));
        element.data.process.start = data->processStartISO8601();
        element.data.process.parent.pid = data->processParentID();

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
            throw std::runtime_error("Agent ID is empty");
        }

        auto processId = data->processId();
        if (processId.empty())
        {
            throw std::runtime_error("Process ID is empty");
        }

        NoDataHarvester element;
        element.operation = "DELETED";
        element.id = agentId;
        element.id += "_";
        element.id += processId;
        return element;
    }
};

#endif // _PROCESS_ELEMENT_HPP
