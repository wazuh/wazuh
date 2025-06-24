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

#ifndef USER_ELEMENT_HPP
#define USER_ELEMENT_HPP

#include "../../wcsModel/data.hpp"
#include "../../wcsModel/inventoryUserHarvester.hpp"
#include "../../wcsModel/noData.hpp"
#include "../policyHarvesterManager.hpp"
#include "../systemContext.hpp"
#include "stringHelper.h"
#include "timeHelper.h"

#include <stdexcept>

template<typename TContext>
class UserElement final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~UserElement() = default;
    // LCOV_EXCL_STOP

    static DataHarvester<InventoryUserHarvester> build(TContext* data)
    {
        auto agentId = data->agentId();
        if (agentId.empty())
        {
            throw std::runtime_error("UserElement::build: Agent ID is empty.");
        }

        auto userName = data->userName();
        if (userName.empty())
        {
            throw std::runtime_error("UserElement::build: User name is empty.");
        }

        DataHarvester<InventoryUserHarvester> element;
        element.id = agentId;
        element.id += "_";
        element.id += userName;

        element.operation = "INSERTED";

        if (!data->userHostIp().empty())
        {
            element.data.host.ip = Utils::splitView(data->userHostIp(), ',');
        }

        element.data.login.status = data->userLoginStatus();
        element.data.login.tty = data->userLoginTty();
        element.data.login.type = data->userLoginType();

        element.data.process.pid = data->userProcessPid();
        element.data.user.id = std::to_string(data->userId());
        element.data.user.name = userName;
        element.data.user.full_name = data->userFullName();
        element.data.user.created = data->userCreated();
        element.data.user.home = data->userHome();
        element.data.user.shell = data->userShell();
        element.data.user.type = data->userType();
        element.data.user.last_login = data->userLastLogin();
        element.data.user.uid_signed = data->userUidSigned();
        element.data.user.uuid = data->userUuid();
        element.data.user.is_hidden = data->userIsHidden();
        element.data.user.is_remote = data->userIsRemote();

        element.data.user.group.id = data->userGroupId();
        element.data.user.group.id_signed = data->userGroupIdSigned();

        if (!data->userGroups().empty())
        {
            element.data.user.groups = Utils::splitView(data->userGroups(), ',');
        }

        element.data.user.auth_failures.count = data->userAuthFailedCount();
        element.data.user.auth_failures.timestamp = data->userAuthFailedTimestamp();

        element.data.user.password.status = data->userPasswordStatus();
        element.data.user.password.last_change = data->userPasswordLastChange();
        element.data.user.password.expiration_date = data->userPasswordExpirationDate();
        element.data.user.password.hash_algorithm = data->userPasswordHashAlgorithm();
        element.data.user.password.inactive_days = data->userPasswordInactiveDays();
        element.data.user.password.last_set_time = data->userPasswordLastSetTime();
        element.data.user.password.max_days_between_changes = data->userPasswordMaxDays();
        element.data.user.password.min_days_between_changes = data->userPasswordMinDays();
        element.data.user.password.warning_days_before_expiration = data->userPasswordWarningDays();

        if (!data->userRoles().empty())
        {
            element.data.user.roles = Utils::splitView(data->userRoles(), ',');
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
            throw std::runtime_error("UserElement::deleteElement: Agent ID is empty.");
        }

        auto userName = data->userName();
        if (userName.empty())
        {
            throw std::runtime_error("UserElement::deleteElement: User name is empty.");
        }

        NoDataHarvester element;
        element.id = agentId;
        element.id += "_";
        element.id += userName;

        element.operation = "DELETED";

        return element;
    }
};

#endif // USER_ELEMENT_HPP
