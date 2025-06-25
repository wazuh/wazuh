/*
 * Wazuh Inventory Harvester - User element builder
 * Copyright (C) 2015, Wazuh Inc.
 * June 16, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef GROUP_ELEMENT_HPP
#define GROUP_ELEMENT_HPP

#include "../../wcsModel/data.hpp"
#include "../../wcsModel/inventoryGroupHarvester.hpp"
#include "../../wcsModel/noData.hpp"
#include "../policyHarvesterManager.hpp"
#include "../systemContext.hpp"
#include "stringHelper.h"
#include "timeHelper.h"

#include <stdexcept>

template<typename TContext>
class GroupElement final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~GroupElement() = default;
    // LCOV_EXCL_STOP

    static DataHarvester<InventoryGroupHarvester> build(TContext* data)
    {
        auto agentId = data->agentId();
        if (agentId.empty())
        {
            throw std::runtime_error("GroupElement::build: Agent ID is empty.");
        }

        auto groupId = data->groupId();
        if (groupId < 0)
        {
            throw std::runtime_error("GroupElement::build: Group ID is invalid.");
        }

        DataHarvester<InventoryGroupHarvester> element;
        element.id = agentId;
        element.id += "_";
        element.id += std::to_string(groupId);

        element.operation = "INSERTED";

        element.data.group.id = groupId;
        element.data.group.name = data->groupName();
        element.data.group.description = data->groupDescription();
        element.data.group.id_signed = data->groupIdSigned();
        element.data.group.uuid = data->groupUuid();
        element.data.group.is_hidden = data->groupIsHidden();

        std::string_view groupUsersView = data->groupUsers();
        if (!groupUsersView.empty())
        {
            element.data.group.users = Utils::splitView(groupUsersView, ',');
        }

        element.data.agent.id = agentId;
        element.data.agent.name = data->agentName();
        element.data.agent.version = data->agentVersion();

        if (auto agentIp = data->agentIp(); agentIp.compare("any") != 0)
        {
            element.data.agent.host.ip = agentIp;
        }

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
            throw std::runtime_error("GroupElement::deleteElement: Agent ID is empty.");
        }

        auto groupId = data->groupId();
        if (groupId < 0)
        {
            throw std::runtime_error("GroupElement::deleteElement: Group ID is invalid.");
        }

        NoDataHarvester element;
        element.id = agentId;
        element.id += "_";
        element.id += std::to_string(groupId);
        element.operation = "DELETED";

        return element;
    }
};

#endif // GROUP_ELEMENT_HPP
