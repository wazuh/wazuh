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

#ifndef _FILE_ELEMENT_HPP
#define _FILE_ELEMENT_HPP

#include "../../wcsModel/data.hpp"
#include "../../wcsModel/fimFileHarvester.hpp"
#include "../../wcsModel/noData.hpp"
#include "stringHelper.h"
#include "timeHelper.h"

template<typename TContext>
class FileElement final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~FileElement() = default;
    // LCOV_EXCL_STOP

    static DataHarvester<FimFileInventoryHarvester> build(TContext* data)
    {
        DataHarvester<FimFileInventoryHarvester> element;

        element.id = data->agentId();
        element.id += "_";
        element.id += data->path();
        element.operation = "INSERTED";

        element.data.agent.id = data->agentId();
        element.data.agent.name = data->agentName();
        element.data.agent.version = data->agentVersion();
        element.data.agent.ip = data->agentIp();

        element.data.file.hash.sha1 = data->sha1();
        element.data.file.hash.sha256 = data->sha256();
        element.data.file.hash.md5 = data->md5();
        element.data.file.path = data->path();
        element.data.file.gid = data->gid();
        element.data.file.group = data->groupName();
        element.data.file.uid = data->uid();
        element.data.file.owner = data->userName();
        element.data.file.size = data->size();

        element.data.file.mtime = data->mtimeISO8601();

        return element;
    }

    static NoDataHarvester deleteElement(TContext* data)
    {
        NoDataHarvester element;
        element.operation = "DELETED";
        element.id = data->agentId();
        element.id += "_";
        element.id += data->path();
        return element;
    }
};

#endif // _FILE_ELEMENT_HPP
