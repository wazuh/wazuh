/*
 * Wazuh Inventory Harvester - Hardware element
 * Copyright (C) 2015, Wazuh Inc.
 * March 20, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HW_ELEMENT_HPP
#define _HW_ELEMENT_HPP

#include "../../wcsModel/data.hpp"
#include "../../wcsModel/inventoryHardwareHarvester.hpp"
#include "../../wcsModel/noData.hpp"
#include "../policyHarvesterManager.hpp"
#include <stdexcept>

template<typename TContext>
class HwElement final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~HwElement() = default;
    // LCOV_EXCL_STOP

    static DataHarvester<InventoryHardwareHarvester> build(TContext* data)
    {
        auto agentId = data->agentId();
        if (agentId.empty())
        {
            throw std::runtime_error("Agent ID is empty, cannot upsert hardware element.");
        }

        auto boardId = data->boardInfo();
        if (boardId.empty())
        {
            boardId = "unknown";
        }

        DataHarvester<InventoryHardwareHarvester> element;
        element.id = agentId;
        element.id += "_";
        element.id += boardId;
        element.operation = "INSERTED";
        element.data.agent.id = agentId;
        element.data.agent.name = data->agentName();
        element.data.agent.version = data->agentVersion();

        if (auto agentIp = data->agentIp(); agentIp.compare("any") != 0)
        {
            element.data.agent.host.ip = agentIp;
        }

        // Ex: 2, 4 u 8
        element.data.host.cpu.cores = data->cpuCores();

        // Ex: Intel(R) Core(TM) i5-10500H CPU @ 2.50GHz
        element.data.host.cpu.name = data->cpuName();

        // Ex: 2497.0, 3192.0 u 4192.0
        element.data.host.cpu.speed = data->cpuFrequency();

        // Ex: Any value greater than 0
        element.data.host.memory.free = data->freeMem();

        // Ex: Any value greater than 0
        element.data.host.memory.total = data->totalMem();

        // Ex: Any value greater than 0. Calculated as total - free, check
        // if the value is greater than 0, if not set it to 0.
        auto usedMem = data->totalMem() - data->freeMem();
        element.data.host.memory.used = (usedMem > 0) ? usedMem : 0;

        // Ex: AA320
        element.data.observer.serial_number = boardId;

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
            throw std::runtime_error("Agent ID is empty, cannot delete hardware element.");
        }

        auto boardId = data->boardInfo();
        if (boardId.empty())
        {
            boardId = "unknown";
        }

        NoDataHarvester element;
        element.operation = "DELETED";
        element.id = agentId;
        element.id += "_";
        element.id += boardId;
        return element;
    }
};

#endif // _HW_ELEMENT_HPP
