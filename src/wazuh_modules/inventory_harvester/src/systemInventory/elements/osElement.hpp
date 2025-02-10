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

#ifndef _OS_ELEMENT_HPP
#define _OS_ELEMENT_HPP

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

        DataHarvester<InventorySystemHarvester> element;
        element.id = agentId;
        element.operation = "INSERTED";
        element.data.agent.id = agentId;
        element.data.agent.name = data->agentName();
        element.data.agent.version = data->agentVersion();
        element.data.agent.ip = data->agentIp();

        // 22.04.5 LTS (Jammy Jellyfish), 15.1.1, 10.0.19045.5371
        element.data.host.os.version = data->osVersion();

        // Ex: macOS, Ubuntu, Microsoft Windows 10 Pro
        element.data.host.os.name = data->osName();

        // Ex: 4.15.0-112-generic, 24.1.0 (for macos)
        element.data.host.os.kernel = data->osKernelRelease();

        // TODO: windows not report anything in this field.
        // Ex: ubuntu, centos, darwin
        element.data.host.os.platform = data->osPlatform();

        // TODO: windows not report anything in this field.
        // Ex: Linux, Windows NT, Darwin
        element.data.host.os.type = data->osKernelSysName();

        // Ex: x86_64, arm64
        element.data.host.architecture = data->osArchitecture();

        // Ex: DESKTOP-5RL9J34, Octavios-MacBook-Pro.local, dwordcito-MS-7D25
        element.data.host.hostname = data->osHostName();
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

#endif // _OS_ELEMENT_HPP
