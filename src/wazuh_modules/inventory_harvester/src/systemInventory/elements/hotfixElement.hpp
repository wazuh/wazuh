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
#include "../../wcsModel/inventorySystemHarvester.hpp"
#include "../../wcsModel/noData.hpp"
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

        auto hotfix = data->hotfix();
        if (hotfix.empty())
        {
            throw std::runtime_error("Hotfix is empty, cannot upsert system element.");
        }

        DataHarvester<InventoryHotfixHarvester> element;
        element.id = agentId;
        element.operation = "INSERTED";
        element.data.agent.id = agentId;
        element.data.agent.name = data->agentName();
        element.data.agent.version = data->agentVersion();
        element.data.agent.ip = data->agentIp();

        element.data.hotfix.hotfix = data->hotfix();

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
        return element;
    }
};

#endif // _OS_HOTFIX_HPP
