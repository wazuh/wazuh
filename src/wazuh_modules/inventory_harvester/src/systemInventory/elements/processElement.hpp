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

#ifndef _PROCESS_ELEMENT_HPP
#define _PROCESS_ELEMENT_HPP

#include "../../wcsModel/data.hpp"
#include "../../wcsModel/inventoryProcessHarvester.hpp"
#include "../../wcsModel/noData.hpp"
#include "stringHelper.h"
#include "timeHelper.h"

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
        std::string commandLine = data->processCmdline().data();
        Utils::replaceAll(commandLine, "\\", "/");
        Utils::replaceAll(commandLine, "//", "/");

        DataHarvester<InventoryProcessHarvester> element;
        element.id = data->agentId();
        element.id += "_";
        element.id += data->processId();
        element.operation = "INSERTED";

        element.data.agent.id = data->agentId();
        element.data.agent.name = data->agentName();
        element.data.agent.version = data->agentVersion();
        element.data.agent.ip = data->agentIp();

        if (data->processArgvs().empty() == false)
        {
            element.data.process.args = Utils::split(data->processArgvs(), ' ');
            element.data.process.args_count = element.data.process.args.size();
        }
        element.data.process.command_line = commandLine;
        element.data.process.name = data->processName();
        element.data.process.pid = std::stoull(data->processId().data());
        element.data.process.start = Utils::rawTimestampToISO8601(data->processStart());
        element.data.process.ppid = data->processParentID();

        return element;
    }

    static NoDataHarvester deleteElement(TContext* data)
    {
        NoDataHarvester element;
        element.operation = "DELETED";
        element.id = data->agentId();
        element.id += "_";
        element.id += data->processId();
        return element;
    }
};

#endif // _PROCESS_ELEMENT_HPP
