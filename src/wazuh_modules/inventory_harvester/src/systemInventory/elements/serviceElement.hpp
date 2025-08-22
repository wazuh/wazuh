/*
 * Wazuh Inventory Harvester - Service element
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _SERVICE_ELEMENT_HPP
#define _SERVICE_ELEMENT_HPP

#include "../../wcsModel/data.hpp"
#include "../../wcsModel/inventoryServiceHarvester.hpp"
#include "../../wcsModel/noData.hpp"
#include "../policyHarvesterManager.hpp"
#include <stdexcept>

template<typename TContext>
class ServiceElement final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~ServiceElement() = default;
    // LCOV_EXCL_STOP

    static DataHarvester<InventoryServiceHarvester> build(TContext* data)
    {
        auto agentId = data->agentId();
        if (agentId.empty())
        {
            throw std::runtime_error("ServiceElement::build: Agent ID is empty.");
        }

        auto serviceName = data->serviceName();
        if (serviceName.empty())
        {
            throw std::runtime_error("ServiceElement::build: Service name is empty.");
        }

        DataHarvester<InventoryServiceHarvester> element;

        // Key
        element.id = agentId;
        element.id += "_";
        element.id += serviceName;

        // Operation
        element.operation = "INSERTED";

        // Agent
        element.data.agent.id = agentId;
        element.data.agent.name = data->agentName();
        element.data.agent.version = data->agentVersion();
        if (auto agentIp = data->agentIp(); agentIp.compare("any") != 0)
        {
            element.data.agent.host.ip = agentIp;
        }

        // Service information
        element.data.service.id = serviceName;
        element.data.service.name = data->serviceDisplayName();
        element.data.service.description = data->serviceDescription();
        element.data.service.state = data->serviceState();
        element.data.service.sub_state = data->serviceSubState();
        element.data.service.start_type = data->serviceStartType();
        element.data.service.type = data->serviceType();
        element.data.service.exit_code = data->serviceExitCode();
        element.data.service.enabled = data->serviceEnabled();

        // Process information
        element.data.process.pid = data->servicePid();
        element.data.process.executable = data->processExecutable();
        element.data.process.args = data->processArgs();
        element.data.process.working_directory = data->processWorkingDir();
        element.data.process.root_directory = data->processRootDir();

        // Process User and Group information
        element.data.process.user.name = data->processUserName();
        element.data.process.group.name = data->processGroupName();

        // Service additional fields
        element.data.service.restart = data->serviceRestart();
        element.data.service.frequency = data->serviceFrequency();
        element.data.service.starts_on_mount = data->serviceStartsOnMount();
        element.data.service.starts_on_path_modified = data->serviceStartsOnPathModified();
        element.data.service.starts_on_not_empty_directory = data->serviceStartsOnNotEmptyDirectory();
        element.data.service.inetd_compatibility = data->serviceInetdCompatibility();
        element.data.service.address = data->serviceAddress();
        element.data.service.win32_exit_code = data->serviceWin32ExitCode();
        element.data.service.following = data->serviceFollowing();
        element.data.service.object_path = data->serviceObjectPath();

        // File information
        element.data.file.path = data->filePath();

        // Log information
        element.data.log.file.path = data->logFilePath();
        element.data.error.log.file.path = data->errorLogFilePath();

        // Target information
        element.data.target.ephemeral_id = data->serviceTargetEphemeralId();
        element.data.target.type = data->serviceTargetType();
        element.data.target.address = data->serviceTargetAddress();

        // Wazuh cluster information
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
            throw std::runtime_error("ServiceElement::deleteElement: Agent ID is empty.");
        }

        auto serviceName = data->serviceName();
        if (serviceName.empty())
        {
            throw std::runtime_error("ServiceElement::deleteElement: Service name is empty.");
        }

        NoDataHarvester element;
        // Key
        element.id = agentId;
        element.id += "_";
        element.id += serviceName;

        // Operation
        element.operation = "DELETED";

        return element;
    }
};

#endif // _SERVICE_ELEMENT_HPP
