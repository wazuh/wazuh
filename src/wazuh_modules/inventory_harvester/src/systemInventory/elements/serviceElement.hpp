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

        auto itemId = data->serviceItemId();
        if (itemId.empty())
        {
            throw std::runtime_error("ServiceElement::build: Service Item ID is empty.");
        }

        auto serviceId = data->serviceId();
        if (serviceId.empty())
        {
            throw std::runtime_error("ServiceElement::build: Service ID is empty.");
        }

        DataHarvester<InventoryServiceHarvester> element;

        // Key
        element.id = agentId;
        element.id += "_";
        element.id += itemId;

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

        // File information
        element.data.file.path = data->serviceFilePath();

        // Process information
        if (auto serviceProcessArgs = data->serviceProcessArgs();
            !serviceProcessArgs.empty() && serviceProcessArgs.compare(" ") != 0)
        {
            element.data.process.args = Utils::splitView(serviceProcessArgs, ',');
        }
        element.data.process.executable = data->serviceProcessExecutable();
        element.data.process.group.name = data->serviceProcessGroupName();
        if (auto serviceProcessPid = data->serviceProcessPid(); serviceProcessPid >= 0)
        {
            element.data.process.pid = serviceProcessPid;
        }
        element.data.process.root_directory = data->serviceProcessRootDir();
        element.data.process.user.name = data->serviceProcessUserName();
        element.data.process.working_directory = data->serviceProcessWorkingDir();

        // Service information
        element.data.service.address = data->serviceAddress();
        element.data.service.description = data->serviceDescription();
        element.data.service.enabled = data->serviceEnabled();
        if (auto serviceExitCode = data->serviceExitCode(); serviceExitCode >= 0)
        {
            element.data.service.exit_code = serviceExitCode;
        }
        element.data.service.following = data->serviceFollowing();
        if (auto serviceFrequency = data->serviceFrequency(); serviceFrequency >= 0)
        {
            element.data.service.frequency = serviceFrequency;
        }
        element.data.service.id = serviceId;
        if (auto serviceInetdCompatibility = data->serviceInetdCompatibility(); serviceInetdCompatibility >= 0)
        {
            element.data.service.inetd_compatibility = serviceInetdCompatibility;
        }
        element.data.service.name = data->serviceName();
        element.data.service.object_path = data->serviceObjectPath();
        element.data.service.restart = data->serviceRestart();
        element.data.service.start_type = data->serviceStartType();
        if (auto serviceOnMount = data->serviceStartsOnMount(); serviceOnMount >= 0)
        {
            element.data.service.starts.on_mount = serviceOnMount;
        }
        if (auto serviceOnNotEmptyDirectory = data->serviceStartsOnNotEmptyDirectory();
            !serviceOnNotEmptyDirectory.empty() && serviceOnNotEmptyDirectory.compare(" ") != 0)
        {
            element.data.service.starts.on_not_empty_directory = Utils::splitView(serviceOnNotEmptyDirectory, ',');
        }
        if (auto serviceOnPathModified = data->serviceStartsOnPathModified();
            !serviceOnPathModified.empty() && serviceOnPathModified.compare(" ") != 0)
        {
            element.data.service.starts.on_path_modified = Utils::splitView(serviceOnPathModified, ',');
        }
        element.data.service.state = data->serviceState();
        element.data.service.sub_state = data->serviceSubState();
        element.data.service.target.address = data->serviceTargetAddress();
        if (auto serviceTargetEphemeralId = data->serviceTargetEphemeralId(); serviceTargetEphemeralId >= 0)
        {
            element.data.service.target.ephemeral_id = std::to_string(serviceTargetEphemeralId);
        }
        element.data.service.target.type = data->serviceTargetType();
        element.data.service.type = data->serviceType();
        if (auto serviceWin32ExitCode = data->serviceWin32ExitCode(); serviceWin32ExitCode >= 0)
        {
            element.data.service.win32_exit_code = serviceWin32ExitCode;
        }

        // Log information
        element.data.log.file.path = data->serviceLogFilePath();

        // Error information
        element.data.error.log.file.path = data->serviceErrorLogFilePath();

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

        auto itemId = data->serviceItemId();
        if (itemId.empty())
        {
            throw std::runtime_error("ServiceElement::deleteElement: Service Item ID is empty.");
        }

        NoDataHarvester element;
        // Key
        element.id = agentId;
        element.id += "_";
        element.id += itemId;

        // Operation
        element.operation = "DELETED";

        return element;
    }
};

#endif // _SERVICE_ELEMENT_HPP
