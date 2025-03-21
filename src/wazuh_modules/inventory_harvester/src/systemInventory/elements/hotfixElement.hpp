/*
 * Wazuh Vulnerability scanner - Scan Orchestrator
 * Copyright (C) 2015, Wazuh Inc.
 * March 21, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OS_HOTFIX_HPP
#define _OS_HOTFIX_HPP

#include "../../wcsModel/data.hpp"
#include "../../wcsModel/inventoryHotfixHarvester.hpp"
#include "../../wcsModel/noData.hpp"
#include <stdexcept>

template<typename TContext>
class HotfixElement final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~HotfixElement() = default;
    // LCOV_EXCL_STOP

    static DataHarvester<InventoryHotfixHarvester> build(TContext* data)
    {
        auto agentId = data->agentId();
        if (agentId.empty())
        {
            throw std::runtime_error("Agent ID is empty, cannot upsert hotfix element.");
        }

        auto hotfixName = data->hotfixName();
        if (hotfixName.empty())
        {
            throw std::runtime_error("Hotfix ID is empty, cannot upsert hotfix element.");
        }

        DataHarvester<InventoryHotfixHarvester> element;
        element.id = agentId;
        element.id += "_";
        element.id += hotfixName;
        element.operation = "INSERTED";

        element.data.agent.ip = data->agentIp();
        element.data.agent.id = agentId;
        element.data.agent.name = data->agentName();
        element.data.agent.version = data->agentVersion();

        element.data.package.hotfix.name = hotfixName;

        return element;
    }

    static NoDataHarvester deleteElement(TContext* data)
    {
        auto agentId = data->agentId();
        if (agentId.empty())
        {
            throw std::runtime_error("Agent ID is empty, cannot delete hotfix element.");
        }

        auto hotfixName = data->hotfixName();
        if (hotfixName.empty())
        {
            throw std::runtime_error("Hotfix ID is empty, cannot delete hotfix element.");
        }

        NoDataHarvester element;
        element.id = agentId;
        element.id += "_";
        element.id += hotfixName;
        element.operation = "DELETED";

        return element;
    }
};

#endif // _OS_HOTFIX_HPP
