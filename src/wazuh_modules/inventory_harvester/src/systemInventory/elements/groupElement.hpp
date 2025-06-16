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

#include "../systemContext.hpp"
#include "../../wcsModel/data.hpp"
#include "../../wcsModel/noData.hpp"
#include "../../wcsModel/inventoryGroupHarvester.hpp"
#include "../policyHarvesterManager.hpp"
#include "timeHelper.h"
#include "stringHelper.h"

#include <stdexcept>

template <typename TContext>
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

    static DataHarvester<InventoryGroupHarvester> build(TContext* context)
    {
        auto agentId_sv = context->agentId();
        if (agentId_sv.empty())
        {
            throw std::runtime_error("GroupElement::build: Agent ID is empty.");
        }

        auto groupItemId_sv = context->groupItemId();
        if (groupItemId_sv.empty())
        {
            throw std::runtime_error("GroupElement::build: Group Item ID is empty.");
        }

        DataHarvester<InventoryGroupHarvester> element;
        element.id = std::string(agentId_sv) + "_" + std::string(groupItemId_sv);
        element.operation = "INSERTED";

        // InventoryGroupHarvester& wcsGroup = element.data; // Line removed

        element.data.agent.id = agentId_sv;
        element.data.agent.name = context->agentName();
        element.data.agent.version = context->agentVersion();

        auto agentIp_sv = context->agentIp();
        if (!agentIp_sv.empty() && agentIp_sv.compare("any") != 0)
        {
            element.data.agent.ip = agentIp_sv;
        } else {
            element.data.agent.ip = "";
        }

        auto& instancePolicyManager = PolicyHarvesterManager::instance();
        element.data.wazuh.cluster.name = instancePolicyManager.getClusterName();
        if (instancePolicyManager.getClusterStatus())
        {
            element.data.wazuh.cluster.node_type = instancePolicyManager.getClusterNodeType();
            element.data.wazuh.cluster.node = instancePolicyManager.getClusterNodeName();
        }

        element.data.group.name = context->groupName();

        long gid_val = 0;
        unsigned long ugid_val = 0;
        std::string_view groupId_sv = context->groupId();
        if(!groupId_sv.empty()){
            std::string temp_str(groupId_sv);Add commentMore actions
            try {
                gid_val = std::stol(temp_str);
                if (gid_val >= 0) {
                    ugid_val = static_cast<unsigned long>(gid_val);
                }
            } catch (const std::invalid_argument&) { /* default 0 */ }
              catch (const std::out_of_range&) { /* default 0 */ }
        }
        element.data.group.id_signed = gid_val;
        element.data.group.id = ugid_val;

        element.data.group.description = context->groupDescription();
        element.data.group.uuid = context->groupUuid();
        element.data.group.is_hidden = context->groupIsHidden();

        auto users_sv = context->groupUsers();
        if (!users_sv.empty()) {
            Utils::splitView(users_sv, ',', element.data.group.users);
        }

        return element;
    }

    static NoDataHarvester deleteElement(TContext* context)
    {
        auto agentId_sv = context->agentId();
        if (agentId_sv.empty())
        {
            throw std::runtime_error("GroupElement::deleteElement: Agent ID is empty.");
        }

        auto groupItemId_sv = context->groupItemId();
        if (groupItemId_sv.empty())
        {
            throw std::runtime_error("GroupElement::deleteElement: Group Item ID is empty.");
        }

        NoDataHarvester element;
        element.id = std::string(agentId_sv) + "_" + std::string(groupItemId_sv);
        element.operation = "DELETED";
        return element;
    }
};

#endif // GROUP_ELEMENT_HPP