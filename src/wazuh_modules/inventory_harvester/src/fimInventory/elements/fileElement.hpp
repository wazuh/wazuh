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
#include "../policyHarvesterManager.hpp"
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

        auto agentId = data->agentId();
        if (agentId.empty())
        {
            throw std::runtime_error("Agent ID is empty, cannot upsert FIM file element.");
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

        element.data.file.hash.sha1 = data->sha1();
        element.data.file.hash.sha256 = data->sha256();
        element.data.file.hash.md5 = data->md5();
        element.data.file.path = data->path();
        element.data.file.gid = data->gid();
        element.data.file.group = data->groupName();
        element.data.file.uid = data->uid();
        element.data.file.owner = data->userName();
        element.data.file.size = data->size();
        element.data.file.inode = std::to_string(data->inode());

        element.data.file.mtime = data->mtimeISO8601();

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
            throw std::runtime_error("Agent ID is empty, cannot delete FIM file element.");
        }

        element.operation = "DELETED";
        element.id = agentId;
        element.id += "_";
        element.id += data->hashPath();
        return element;
    }
};

#endif // _FILE_ELEMENT_HPP
