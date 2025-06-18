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

#include "../systemContext.hpp"
#include "../../wcsModel/data.hpp"
#include "../../wcsModel/noData.hpp"
#include "../../wcsModel/inventoryUserHarvester.hpp"
#include "../policyHarvesterManager.hpp"
#include "timeHelper.h"
#include "stringHelper.h"

#include <stdexcept>

template <typename TContext>
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

    static DataHarvester<InventoryUserHarvester> build(TContext* context)
    {
        auto agentId_sv = context->agentId();
        if (agentId_sv.empty())
        {
            throw std::runtime_error("UserElement::build: Agent ID is empty.");
        }

        DataHarvester<InventoryUserHarvester> element;
        // element.id = std::string(agentId_sv) + "_" + std::string(userItemId_sv);
        element.operation = "INSERTED";

        element.data.agent.id = agentId_sv;
        element.data.agent.name = context->agentName();
        element.data.agent.version = context->agentVersion();

        auto agentIp_sv = context->agentIp();
        if (!agentIp_sv.empty() && agentIp_sv.compare("any") != 0)
        {
            element.data.agent.host.ip = agentIp_sv;
            element.data.host.ip = agentIp_sv;
        } else {
            element.data.agent.host.ip = "";
            element.data.host.ip = "";
        }

        auto& instancePolicyManager = PolicyHarvesterManager::instance();
        element.data.wazuh.cluster.name = instancePolicyManager.getClusterName();
        if (instancePolicyManager.getClusterStatus())
        {
            element.data.wazuh.cluster.node = instancePolicyManager.getClusterNodeName();
        }

        // element.data.login.status = context->userLoginStatus();
        // element.data.login.tty = context->userLoginTty();
        // element.data.login.type = context->userLoginType();

        // element.data.user.id = context->userId();
        // element.data.user.name = context->userName();

        long gid_val = 0;
        unsigned long ugid_val = 0;
        // std::string_view userGroupId_sv = context->userGroupId();
        // if (!userGroupId_sv.empty()) {
        //     std::string temp_str(userGroupId_sv);
        //     try {
        //         gid_val = std::stol(temp_str);
        //         if (gid_val >= 0) {
        //             ugid_val = static_cast<unsigned long>(gid_val);
        //         }
        //     } catch (const std::invalid_argument&) { /* default 0 */ }
        //       catch (const std::out_of_range&) { /* default 0 */ }
        // }
        // element.data.user.group.id_signed = gid_val;
        // element.data.user.group.id = ugid_val;

        // element.data.user.home = context->userHome();
        // element.data.user.shell = context->userShell();
        // element.data.user.uuid = context->userUuid();
        // element.data.user.full_name = context->userFullName();
        // element.data.user.is_hidden = context->userIsHidden();
        // element.data.user.is_remote = context->userIsRemote();
        // element.data.user.created = context->userCreated();
        // element.data.user.last_login = context->userLastLogin();

        long uid_signed_val = 0;
        // std::string_view userId_sv = context->userId();
        // if (!userId_sv.empty()) {
        //      std::string temp_str(userId_sv);
        //     try {
        //         uid_signed_val = std::stol(temp_str);
        //     } catch (const std::invalid_argument&) { /* default 0 */ }
        //       catch (const std::out_of_range&) { /* default 0 */ }
        // }
        // element.data.user.uid_signed = uid_signed_val;

        // element.data.user.password.status = context->userPasswordStatus();
        // element.data.user.password.last_change = context->userPasswordLastChange();
        // element.data.user.password.expiration_date = context->userPasswordExpirationDate();
        // element.data.user.password.hash_algorithm = context->userPasswordHashAlgorithm();
        // element.data.user.password.inactive_days = context->userPasswordInactiveDays();
        // element.data.user.password.last_set_time = context->userPasswordLastSetTime();
        // element.data.user.password.max_days_between_changes = context->userPasswordMaxDays();
        // element.data.user.password.min_days_between_changes = context->userPasswordMinDays();
        // element.data.user.password.warning_days_before_expiration = context->userPasswordWarningDays();

        // element.data.user.roles = context->userRoles();
        // element.data.user.groups = context->userGroups();

        // element.data.user.auth_failures.count = context->userAuthFailuresCount();
        // element.data.user.auth_failures.timestamp = context->userAuthFailuresTimestamp();

        return element;
    }

    static NoDataHarvester deleteElement(TContext* context)
    {
        auto agentId_sv = context->agentId();
        if (agentId_sv.empty())
        {
            throw std::runtime_error("UserElement::deleteElement: Agent ID is empty.");
        }

        NoDataHarvester element;
        // element.id = std::string(agentId_sv) + "_" + std::string(userItemId_sv);
        element.operation = "DELETED";
        return element;
    }
};

#endif // USER_ELEMENT_HPP
