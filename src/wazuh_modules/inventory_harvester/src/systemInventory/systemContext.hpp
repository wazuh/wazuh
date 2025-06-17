/*
 * Wazuh inventory harvester - System context
 * Copyright (C) 2015, Wazuh Inc.
 * January 21, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYSTEM_CONTEXT_HPP
#define _SYSTEM_CONTEXT_HPP

#include "flatbuffers/include/rsync_generated.h"
#include "flatbuffers/include/syscollector_deltas_generated.h"
#include "stringHelper.h"
#include "timeHelper.h"
#include <json.hpp>
#include <variant>

struct SystemContext final
{
private:
    enum class VariantType : std::uint8_t
    {
        Delta,
        SyncMsg,
        Json,
        Invalid
    };

public:
    enum class Operation : std::uint8_t
    {
        Delete,
        Upsert,
        DeleteAgent,
        DeleteAllEntries,
        IndexSync,
        UpgradeAgentDB,
        Invalid,
    };
    enum class AffectedComponentType : std::uint8_t
    {
        Package,
        Process,
        System,
        Port,
        Hotfix,
        Hardware,
        NetProto,
        NetIface,
        NetworkAddress,
        User,
        Group,
        Invalid
    };

    enum class OriginTable : std::uint8_t
    {
        Packages,
        Processes,
        Os,
        Hotfixes,
        Hw,
        Ports,
        NetworkProtocol,
        NetIfaces,
        NetAddress,
        Users,
        Groups,
        Invalid
    };
    explicit SystemContext(
        std::variant<const SyscollectorDeltas::Delta*, const Synchronization::SyncMsg*, const nlohmann::json*> data)
    {
        std::visit(
            [this](auto&& arg)
            {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, const SyscollectorDeltas::Delta*>)
                {
                    m_data = std::forward<decltype(arg)>(arg);
                    m_type = VariantType::Delta;

                    buildDeltaContext(std::get<const SyscollectorDeltas::Delta*>(m_data));
                }
                else if constexpr (std::is_same_v<T, const Synchronization::SyncMsg*>)
                {
                    m_data = std::forward<decltype(arg)>(arg);
                    m_type = VariantType::SyncMsg;

                    buildSyncContext(std::get<const Synchronization::SyncMsg*>(m_data));
                }
                else if constexpr (std::is_same_v<T, const nlohmann::json*>)
                {
                    m_data = std::forward<decltype(arg)>(arg);
                    m_type = VariantType::Json;
                    buildJsonContext(std::get<const nlohmann::json*>(m_data));
                }
                else
                {
                    throw std::runtime_error("Unable to build scan context. Unknown type");
                }
            },
            data);
    }

    std::string_view agentId()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->agent_info() && m_delta->agent_info()->agent_id())
            {
                return m_delta->agent_info()->agent_id()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->agent_info() && m_syncMsg->agent_info()->agent_id())
            {
                return m_syncMsg->agent_info()->agent_id()->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/agent_info/agent_id"_json_pointer))
            {
                return m_jsonData->at("/agent_info/agent_id"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    // Group data fields

    std::string_view groupName() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_groups() && m_delta->data_as_dbsync_groups()->name())
            {
                return m_delta->data_as_dbsync_groups()->name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_groups() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->name())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->name()->string_view();
            }
        }
        return "";
    }

    std::string_view groupId() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_groups() && m_delta->data_as_dbsync_groups()->gid())
            {
                return m_delta->data_as_dbsync_groups()->gid()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_groups() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->gid())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->gid()->string_view();
            }
        }
        return "";
    }

    std::string_view groupDescription() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_groups() && m_delta->data_as_dbsync_groups()->description())
            {
                return m_delta->data_as_dbsync_groups()->description()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_groups() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->description())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->description()->string_view();
            }
        }
        return "";
    }

    std::string_view groupUuid() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_groups() && m_delta->data_as_dbsync_groups()->uuid())
            {
                return m_delta->data_as_dbsync_groups()->uuid()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_groups() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->uuid())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->uuid()->string_view();
            }
        }
        return "";
    }

    bool groupIsHidden() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_groups())
            {
                return m_delta->data_as_dbsync_groups()->is_hidden();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_groups())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->is_hidden();
            }
        }
        return false;
    }

    std::string_view groupUsers() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_groups() && m_delta->data_as_dbsync_groups()->users())
            {
                return m_delta->data_as_dbsync_groups()->users()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_groups() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->users())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->users()->string_view();
            }
        }
        return "";
    }

    std::string_view groupItemId() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_groups() && m_delta->data_as_dbsync_groups()->item_id())
            {
                return m_delta->data_as_dbsync_groups()->item_id()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_groups() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->item_id())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->item_id()->string_view();
            }
        }
        else
        {
            if (m_jsonData && m_jsonData->contains("/data/item_id"_json_pointer))
            {
                if (m_affectedComponentType == AffectedComponentType::Group)
                {
                    return m_jsonData->at("/data/item_id"_json_pointer).get<std::string_view>();
                }
            }
        }
        return "";
    }

    // User data fields

    std::string_view userName() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->name())
            {
                return m_delta->data_as_dbsync_users()->name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->name())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->name()->string_view();
            }
        }
        return "";
    }

    std::string_view userId() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->uid())
            {
                return m_delta->data_as_dbsync_users()->uid()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->uid())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->uid()->string_view();
            }
        }
        return "";
    }

    std::string_view userGroupId() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->gid())
            {
                return m_delta->data_as_dbsync_users()->gid()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->gid())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->gid()->string_view();
            }
        }
        return "";
    }

    std::string_view userHome() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->home())
            {
                return m_delta->data_as_dbsync_users()->home()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->home())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->home()->string_view();
            }
        }
        return "";
    }

    std::string_view userShell() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->shell())
            {
                return m_delta->data_as_dbsync_users()->shell()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->shell())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->shell()->string_view();
            }
        }
        return "";
    }

    std::string_view userUuid() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->uuid())
            {
                return m_delta->data_as_dbsync_users()->uuid()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->uuid())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->uuid()->string_view();
            }
        }
        return "";
    }

    std::string_view userFullName() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->full_name())
            {
                return m_delta->data_as_dbsync_users()->full_name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->full_name())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->full_name()->string_view();
            }
        }
        return "";
    }

    bool userIsHidden() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users())
            {
                return m_delta->data_as_dbsync_users()->is_hidden();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->is_hidden();
            }
        }
        return false;
    }

    bool userIsRemote() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users())
            {
                return m_delta->data_as_dbsync_users()->is_remote();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->is_remote();
            }
        }
        return false;
    }

    std::string_view userPasswordHashAlgorithm() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->password_hash_algorithm())
            {
                return m_delta->data_as_dbsync_users()->password_hash_algorithm()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->password_hash_algorithm())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_users()
                    ->password_hash_algorithm()
                    ->string_view();
            }
        }
        return "";
    }

    long userPasswordLastChange() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users())
            {
                return m_delta->data_as_dbsync_users()->password_last_change();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->password_last_change();
            }
        }
        return 0;
    }

    int userPasswordMaxDays() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users())
            {
                return m_delta->data_as_dbsync_users()->password_max_days_between_changes();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_users()
                    ->password_max_days_between_changes();
            }
        }
        return 0;
    }

    int userPasswordMinDays() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users())
            {
                return m_delta->data_as_dbsync_users()->password_min_days_between_changes();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_users()
                    ->password_min_days_between_changes();
            }
        }
        return 0;
    }

    int userPasswordWarningDays() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users())
            {
                return m_delta->data_as_dbsync_users()->password_warning_days_before_expiration();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_users()
                    ->password_warning_days_before_expiration();
            }
        }
        return 0;
    }

    std::string_view userPasswordExpirationDate() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->password_expiration_date())
            {
                return m_delta->data_as_dbsync_users()->password_expiration_date()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->password_expiration_date())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_users()
                    ->password_expiration_date()
                    ->string_view();
            }
        }
        return "";
    }

    std::string_view userPasswordStatus() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->password_status())
            {
                return m_delta->data_as_dbsync_users()->password_status()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->password_status())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->password_status()->string_view();
            }
        }
        return "";
    }

    std::string_view userPasswordLastSetTime() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->password_last_set_time())
            {
                return m_delta->data_as_dbsync_users()->password_last_set_time()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->password_last_set_time())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_users()
                    ->password_last_set_time()
                    ->string_view();
            }
        }
        return "";
    }

    int userPasswordInactiveDays() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users())
            {
                return m_delta->data_as_dbsync_users()->password_inactive_days();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->password_inactive_days();
            }
        }
        return 0;
    }

    std::string_view userCreated() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->created())
            {
                return m_delta->data_as_dbsync_users()->created()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->created())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->created()->string_view();
            }
        }
        return "";
    }

    std::string_view userLastLogin() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->last_login())
            {
                return m_delta->data_as_dbsync_users()->last_login()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->last_login())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->last_login()->string_view();
            }
        }
        return "";
    }

    std::string_view userRoles() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->roles())
            {
                return m_delta->data_as_dbsync_users()->roles()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->roles())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->roles()->string_view();
            }
        }
        return "";
    }

    std::string_view userGroups() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->groups())
            {
                return m_delta->data_as_dbsync_users()->groups()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->groups())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->groups()->string_view();
            }
        }
        return "";
    }

    int userAuthFailuresCount() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users())
            {
                return m_delta->data_as_dbsync_users()->auth_failures_count();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->auth_failures_count();
            }
        }
        return 0;
    }

    std::string_view userAuthFailuresTimestamp() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->auth_failures_timestamp())
            {
                return m_delta->data_as_dbsync_users()->auth_failures_timestamp()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->auth_failures_timestamp())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_users()
                    ->auth_failures_timestamp()
                    ->string_view();
            }
        }
        return "";
    }

    bool userLoginStatus() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users())
            {
                return m_delta->data_as_dbsync_users()->login_status();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->login_status();
            }
        }
        return false;
    }

    std::string_view userLoginType() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->login_type())
            {
                return m_delta->data_as_dbsync_users()->login_type()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->login_type())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->login_type()->string_view();
            }
        }
        return "";
    }

    std::string_view userLoginTty() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->login_tty())
            {
                return m_delta->data_as_dbsync_users()->login_tty()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->login_tty())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->login_tty()->string_view();
            }
        }
        return "";
    }

    std::string_view userItemId() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->item_id())
            {
                return m_delta->data_as_dbsync_users()->item_id()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->item_id())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->item_id()->string_view();
            }
        }
        else
        {
            if (m_jsonData && m_jsonData->contains("/data/item_id"_json_pointer))
            {
                if (m_affectedComponentType == AffectedComponentType::User)
                {
                    return m_jsonData->at("/data/item_id"_json_pointer).get<std::string_view>();
                }
            }
        }
        return "";
    }

    std::string_view agentName()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->agent_info() && m_delta->agent_info()->agent_name())
            {
                return m_delta->agent_info()->agent_name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->agent_info() && m_syncMsg->agent_info()->agent_name())
            {
                return m_syncMsg->agent_info()->agent_name()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    int64_t cpuCores()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_hwinfo() && m_delta->data_as_dbsync_hwinfo()->cpu_cores())
            {
                return m_delta->data_as_dbsync_hwinfo()->cpu_cores();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo()->cpu_cores())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo()->cpu_cores();
            }
        }
        return 0;
    }

    int64_t cpuFrequency()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_hwinfo() && m_delta->data_as_dbsync_hwinfo()->cpu_mhz())
            {
                return static_cast<int64_t>(m_delta->data_as_dbsync_hwinfo()->cpu_mhz());
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo()->cpu_mhz())
            {
                return static_cast<int64_t>(m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo()->cpu_mhz());
            }
        }
        return 0;
    }

    double usedMem()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_hwinfo() && m_delta->data_as_dbsync_hwinfo()->ram_usage())
            {
                return m_delta->data_as_dbsync_hwinfo()->ram_usage() * 0.01;
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo()->ram_usage())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo()->ram_usage() * 0.01;
            }
        }
        return 0.0;
    }

    std::string_view cpuName()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_hwinfo() && m_delta->data_as_dbsync_hwinfo()->cpu_name())
            {
                return m_delta->data_as_dbsync_hwinfo()->cpu_name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo()->cpu_name())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo()->cpu_name()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    int64_t freeMem()
    {
        // Return on Bytes
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_hwinfo() && m_delta->data_as_dbsync_hwinfo()->ram_free())
            {
                return m_delta->data_as_dbsync_hwinfo()->ram_free() * 1024;
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo()->ram_free())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo()->ram_free() * 1024;
            }
        }
        return 0;
    }

    int64_t totalMem()
    {
        // Return on Bytes
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_hwinfo() && m_delta->data_as_dbsync_hwinfo()->ram_total())
            {
                return m_delta->data_as_dbsync_hwinfo()->ram_total() * 1024;
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo()->ram_total())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo()->ram_total() * 1024;
            }
        }
        return 0;
    }

    std::string_view boardInfo()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_hwinfo() && m_delta->data_as_dbsync_hwinfo()->board_serial())
            {
                return m_delta->data_as_dbsync_hwinfo()->board_serial()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo()->board_serial())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo()->board_serial()->string_view();
            }
        }
        else if (m_jsonData->contains("/data/board_serial"_json_pointer))
        {
            return m_jsonData->at("/data/board_serial"_json_pointer).get<std::string_view>();
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view netAddressItemId()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_address() && m_delta->data_as_dbsync_network_address()->item_id())
            {
                return m_delta->data_as_dbsync_network_address()->item_id()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_address() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_address()->item_id())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_network_address()
                    ->item_id()
                    ->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/item_id"_json_pointer))
            {
                return m_jsonData->at("/data/item_id"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view broadcast()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_address() && m_delta->data_as_dbsync_network_address()->broadcast())
            {
                return m_delta->data_as_dbsync_network_address()->broadcast()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_address() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_address()->broadcast())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_network_address()
                    ->broadcast()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view netAddressName()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_address() && m_delta->data_as_dbsync_network_address()->iface())
            {
                return m_delta->data_as_dbsync_network_address()->iface()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_address() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_address()->iface())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_network_address()->iface()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view netmask()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_address() && m_delta->data_as_dbsync_network_address()->netmask())
            {
                return m_delta->data_as_dbsync_network_address()->netmask()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_address() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_address()->netmask())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_network_address()
                    ->netmask()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view address()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_address() && m_delta->data_as_dbsync_network_address()->address())
            {
                return m_delta->data_as_dbsync_network_address()->address()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_address() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_address()->address())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_network_address()
                    ->address()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    int64_t protocol()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_address() && m_delta->data_as_dbsync_network_address()->proto())
            {
                return m_delta->data_as_dbsync_network_address()->proto();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_address() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_address()->proto())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_network_address()->proto();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    std::string_view agentIp()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->agent_info() && m_delta->agent_info()->agent_ip())
            {
                return m_delta->agent_info()->agent_ip()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->agent_info() && m_syncMsg->agent_info()->agent_ip())
            {
                return m_syncMsg->agent_info()->agent_ip()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view agentVersion()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->agent_info() && m_delta->agent_info()->agent_version())
            {
                return m_delta->agent_info()->agent_version()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->agent_info() && m_syncMsg->agent_info()->agent_version())
            {
                return m_syncMsg->agent_info()->agent_version()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view packageName() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_packages() && m_delta->data_as_dbsync_packages()->name())
            {
                return m_delta->data_as_dbsync_packages()->name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_packages() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->name())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->name()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view packageVersion() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_packages() && m_delta->data_as_dbsync_packages()->version())
            {
                return m_delta->data_as_dbsync_packages()->version()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_packages() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->version())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->version()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view packageVendor() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_packages() && m_delta->data_as_dbsync_packages()->vendor())
            {
                return m_delta->data_as_dbsync_packages()->vendor()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_packages() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->vendor())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->vendor()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view packageInstallTimeRaw() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_packages() && m_delta->data_as_dbsync_packages()->install_time())
            {
                return m_delta->data_as_dbsync_packages()->install_time()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_packages() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->install_time())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->install_time()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view packageLocation() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_packages() && m_delta->data_as_dbsync_packages()->location())
            {
                return m_delta->data_as_dbsync_packages()->location()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_packages() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->location())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->location()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view packageArchitecture() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_packages() && m_delta->data_as_dbsync_packages()->architecture())
            {
                return m_delta->data_as_dbsync_packages()->architecture()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_packages() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->architecture())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->architecture()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view packageGroups() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_packages() && m_delta->data_as_dbsync_packages()->groups())
            {
                return m_delta->data_as_dbsync_packages()->groups()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_packages() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->groups())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->groups()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view packageDescription() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_packages() && m_delta->data_as_dbsync_packages()->description())
            {
                return m_delta->data_as_dbsync_packages()->description()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_packages() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->description())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->description()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    int64_t packageSize() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_packages())
            {
                return m_delta->data_as_dbsync_packages()->size();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_packages())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->size();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    std::string_view packagePriority() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_packages() && m_delta->data_as_dbsync_packages()->priority())
            {
                return m_delta->data_as_dbsync_packages()->priority()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_packages() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->priority())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->priority()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view packageMultiarch() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_packages() && m_delta->data_as_dbsync_packages()->multiarch())
            {
                return m_delta->data_as_dbsync_packages()->multiarch()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_packages() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->multiarch())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->multiarch()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view packageSource() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_packages() && m_delta->data_as_dbsync_packages()->source())
            {
                return m_delta->data_as_dbsync_packages()->source()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_packages() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->source())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->source()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view packageFormat() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_packages() && m_delta->data_as_dbsync_packages()->format())
            {
                return m_delta->data_as_dbsync_packages()->format()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_packages() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->format())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->format()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view packageItemId() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_packages() && m_delta->data_as_dbsync_packages()->item_id())
            {
                return m_delta->data_as_dbsync_packages()->item_id()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_packages() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->item_id())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_packages()->item_id()->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/item_id"_json_pointer))
            {
                return m_jsonData->at("/data/item_id"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view osHostName() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_osinfo() && m_delta->data_as_dbsync_osinfo()->hostname())
            {
                return m_delta->data_as_dbsync_osinfo()->hostname()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->hostname())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->hostname()->string_view();
            }
        }
        else
        {
            return "";
        }

        return "";
    }

    std::string_view osArchitecture() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_osinfo() && m_delta->data_as_dbsync_osinfo()->architecture())
            {
                return m_delta->data_as_dbsync_osinfo()->architecture()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->architecture())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->architecture()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view osName() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_osinfo() && m_delta->data_as_dbsync_osinfo()->os_name())
            {
                return m_delta->data_as_dbsync_osinfo()->os_name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->os_name())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->os_name()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view osVersion() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_osinfo() && m_delta->data_as_dbsync_osinfo()->os_version())
            {
                return m_delta->data_as_dbsync_osinfo()->os_version()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->os_version())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->os_version()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view osCodeName() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_osinfo() && m_delta->data_as_dbsync_osinfo()->os_codename())
            {
                return m_delta->data_as_dbsync_osinfo()->os_codename()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->os_codename())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->os_codename()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view osMajorVersion() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_osinfo() && m_delta->data_as_dbsync_osinfo()->os_major())
            {
                return m_delta->data_as_dbsync_osinfo()->os_major()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->os_major())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->os_major()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view osMinorVersion() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_osinfo() && m_delta->data_as_dbsync_osinfo()->os_minor())
            {
                return m_delta->data_as_dbsync_osinfo()->os_minor()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->os_minor())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->os_minor()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view osPatch() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_osinfo() && m_delta->data_as_dbsync_osinfo()->os_patch())
            {
                return m_delta->data_as_dbsync_osinfo()->os_patch()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->os_patch())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->os_patch()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view osBuild() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_osinfo() && m_delta->data_as_dbsync_osinfo()->os_build())
            {
                return m_delta->data_as_dbsync_osinfo()->os_build()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->os_build())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->os_build()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view osPlatform() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_osinfo() && m_delta->data_as_dbsync_osinfo()->os_platform())
            {
                return m_delta->data_as_dbsync_osinfo()->os_platform()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->os_platform())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->os_platform()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view osKernelSysName() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_osinfo() && m_delta->data_as_dbsync_osinfo()->sysname())
            {
                return m_delta->data_as_dbsync_osinfo()->sysname()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->sysname())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->sysname()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view osKernelRelease() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_osinfo() && m_delta->data_as_dbsync_osinfo()->release())
            {
                return m_delta->data_as_dbsync_osinfo()->release()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->release())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->release()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view osKernelVersion() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_osinfo() && m_delta->data_as_dbsync_osinfo()->version())
            {
                return m_delta->data_as_dbsync_osinfo()->version()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->version())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->version()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view osRelease() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_osinfo() && m_delta->data_as_dbsync_osinfo()->os_release())
            {
                return m_delta->data_as_dbsync_osinfo()->os_release()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->os_release())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->os_release()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view osDisplayVersion() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_osinfo() && m_delta->data_as_dbsync_osinfo()->os_display_version())
            {
                return m_delta->data_as_dbsync_osinfo()->os_display_version()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_osinfo()->os_display_version())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_osinfo()
                    ->os_display_version()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view processName() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_processes() && m_delta->data_as_dbsync_processes()->name())
            {
                return m_delta->data_as_dbsync_processes()->name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_processes() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_processes()->name())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_processes()->name()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view processId() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_processes() && m_delta->data_as_dbsync_processes()->pid())
            {
                return m_delta->data_as_dbsync_processes()->pid()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_processes() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_processes()->pid())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_processes()->pid()->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/pid"_json_pointer))
            {
                return m_jsonData->at("/data/pid"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view processCmdlineRaw() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_processes() && m_delta->data_as_dbsync_processes()->cmd())
            {
                return m_delta->data_as_dbsync_processes()->cmd()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_processes() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_processes()->cmd())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_processes()->cmd()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view processCmdline()
    {
        if (m_commandLineSanitized.empty())
        {
            m_commandLineSanitized = processCmdlineRaw();
            Utils::replaceAll(m_commandLineSanitized, "\\", "/");
            Utils::replaceAll(m_commandLineSanitized, "//", "/");
        }
        return m_commandLineSanitized;
    }

    std::string_view processArgvs() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_processes() && m_delta->data_as_dbsync_processes()->argvs())
            {
                return m_delta->data_as_dbsync_processes()->argvs()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_processes() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_processes()->argvs())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_processes()->argvs()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    int64_t processParentID() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_processes() && m_delta->data_as_dbsync_processes()->ppid())
            {
                return m_delta->data_as_dbsync_processes()->ppid();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_processes() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_processes()->ppid())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_processes()->ppid();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    int64_t processStartRaw() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_processes() && m_delta->data_as_dbsync_processes()->start_time())
            {
                return m_delta->data_as_dbsync_processes()->start_time();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_processes() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_processes()->start_time())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_processes()->start_time();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    std::string_view processStartISO8601()
    {
        if (m_processStartISO8601.empty())
        {
            m_processStartISO8601 = Utils::rawTimestampToISO8601(static_cast<uint32_t>(processStartRaw()));
        }
        return m_processStartISO8601;
    }

    std::vector<std::string_view> processArguments()
    {
        if (m_processArguments.empty())
        {
            std::string_view argvs = processArgvs();
            if (!argvs.empty())
            {
                m_processArguments = Utils::splitView(argvs, ' ');
            }
        }
        return m_processArguments;
    }

    std::string_view packageInstallTime()
    {
        auto installTimeRaw = packageInstallTimeRaw();
        if (installTimeRaw.compare(" ") == 0)
        {
            return "";
        }
        m_installTimeISO8601 = Utils::rawTimestampToISO8601(installTimeRaw);
        return m_installTimeISO8601;
    }

    std::string_view hotfixName()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_hotfixes() && m_delta->data_as_dbsync_hotfixes()->hotfix())
            {
                return m_delta->data_as_dbsync_hotfixes()->hotfix()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_hotfixes() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_hotfixes()->hotfix())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_hotfixes()->hotfix()->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/hotfix"_json_pointer))
            {
                return m_jsonData->at("/data/hotfix"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view portProtocol() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_ports() && m_delta->data_as_dbsync_ports()->protocol())
            {
                return m_delta->data_as_dbsync_ports()->protocol()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_ports() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->protocol())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->protocol()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view portLocalIpRaw() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_ports() && m_delta->data_as_dbsync_ports()->local_ip())
            {
                return m_delta->data_as_dbsync_ports()->local_ip()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_ports() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->local_ip())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->local_ip()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view portLocalIp()
    {
        m_portLocalIpSanitized = portLocalIpRaw();
        if (m_portLocalIpSanitized.compare(" ") == 0)
        {
            return "";
        }
        Utils::replaceAll(m_portLocalIpSanitized, ":::", "::");

        return m_portLocalIpSanitized;
    }

    int64_t portLocalPort() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_ports() && m_delta->data_as_dbsync_ports()->local_port())
            {
                return m_delta->data_as_dbsync_ports()->local_port();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_ports() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->local_port())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->local_port();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    std::string_view portRemoteIpRaw() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_ports() && m_delta->data_as_dbsync_ports()->remote_ip())
            {
                return m_delta->data_as_dbsync_ports()->remote_ip()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_ports() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->remote_ip())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->remote_ip()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view portRemoteIp()
    {
        m_portRemoteIpSanitized = portRemoteIpRaw();
        if (m_portRemoteIpSanitized.compare(" ") == 0)
        {
            return "";
        }
        Utils::replaceAll(m_portRemoteIpSanitized, ":::", "::");

        return m_portRemoteIpSanitized;
    }

    int64_t portRemotePort() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_ports() && m_delta->data_as_dbsync_ports()->remote_port())
            {
                return m_delta->data_as_dbsync_ports()->remote_port();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_ports() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->remote_port())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->remote_port();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    int64_t portInode() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_ports() && m_delta->data_as_dbsync_ports()->inode())
            {
                return m_delta->data_as_dbsync_ports()->inode();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_ports() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->inode())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->inode();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    int64_t portTxQueue() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_ports() && m_delta->data_as_dbsync_ports()->tx_queue())
            {
                return m_delta->data_as_dbsync_ports()->tx_queue();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_ports() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->tx_queue())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->tx_queue();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    int64_t portRxQueue() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_ports() && m_delta->data_as_dbsync_ports()->rx_queue())
            {
                return m_delta->data_as_dbsync_ports()->rx_queue();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_ports() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->rx_queue())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->rx_queue();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    std::string_view portState() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_ports() && m_delta->data_as_dbsync_ports()->state())
            {
                return m_delta->data_as_dbsync_ports()->state()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_ports() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->state())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->state()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view portProcess() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_ports() && m_delta->data_as_dbsync_ports()->process())
            {
                return m_delta->data_as_dbsync_ports()->process()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_ports() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->process())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->process()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    int64_t portPid() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_ports() && m_delta->data_as_dbsync_ports()->pid())
            {
                return m_delta->data_as_dbsync_ports()->pid();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_ports() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->pid())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->pid();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    std::string_view portItemId() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_ports() && m_delta->data_as_dbsync_ports()->item_id())
            {
                return m_delta->data_as_dbsync_ports()->item_id()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_ports() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->item_id())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_ports()->item_id()->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/item_id"_json_pointer))
            {
                return m_jsonData->at("/data/item_id"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }
    std::string_view netProtoIface()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_protocol() && m_delta->data_as_dbsync_network_protocol()->iface())
            {
                return m_delta->data_as_dbsync_network_protocol()->iface()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_protocol() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_protocol()->iface())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_network_protocol()
                    ->iface()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view netProtoType()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_protocol() && m_delta->data_as_dbsync_network_protocol()->type())
            {
                return m_delta->data_as_dbsync_network_protocol()->type()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_protocol() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_protocol()->type())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_network_protocol()->type()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view netProtoGateway()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_protocol() && m_delta->data_as_dbsync_network_protocol()->gateway())
            {
                return m_delta->data_as_dbsync_network_protocol()->gateway()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_protocol() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_protocol()->gateway())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_network_protocol()
                    ->gateway()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view netProtoDhcp()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_protocol() && m_delta->data_as_dbsync_network_protocol()->dhcp())
            {
                return m_delta->data_as_dbsync_network_protocol()->dhcp()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_protocol() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_protocol()->dhcp())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_network_protocol()->dhcp()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    int64_t netProtoMetric()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_protocol() && m_delta->data_as_dbsync_network_protocol()->metric())
            {
                return std::strtol(
                    m_delta->data_as_dbsync_network_protocol()->metric()->string_view().data(), NULL, 10);
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_protocol() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_protocol()->metric())
            {
                return std::strtol(m_syncMsg->data_as_state()
                                       ->attributes_as_syscollector_network_protocol()
                                       ->metric()
                                       ->string_view()
                                       .data(),
                                   NULL,
                                   10);
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    std::string_view netProtoItemId()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_protocol() && m_delta->data_as_dbsync_network_protocol()->item_id())
            {
                return m_delta->data_as_dbsync_network_protocol()->item_id()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_protocol() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_protocol()->item_id())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_network_protocol()
                    ->item_id()
                    ->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/item_id"_json_pointer))
            {
                return m_jsonData->at("/data/item_id"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    // NetIface

    std::string_view netIfaceName() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_iface() && m_delta->data_as_dbsync_network_iface()->name())
            {
                return m_delta->data_as_dbsync_network_iface()->name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface()->name())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface()->name()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view netIfaceMac() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_iface() && m_delta->data_as_dbsync_network_iface()->mac())
            {
                return m_delta->data_as_dbsync_network_iface()->mac()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface()->mac())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface()->mac()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    int64_t netIfaceRxBytes() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_iface())
            {
                return m_delta->data_as_dbsync_network_iface()->rx_bytes();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface()->rx_bytes();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    int64_t netIfaceRxDrops() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_iface())
            {
                return m_delta->data_as_dbsync_network_iface()->rx_dropped();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface()->rx_dropped();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    int64_t netIfaceRxErrors() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_iface())
            {
                return m_delta->data_as_dbsync_network_iface()->rx_errors();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface()->rx_errors();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    int64_t netIfaceRxPackets() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_iface())
            {
                return m_delta->data_as_dbsync_network_iface()->rx_packets();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface()->rx_packets();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    int64_t netIfaceTxBytes() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_iface())
            {
                return m_delta->data_as_dbsync_network_iface()->tx_bytes();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface()->tx_bytes();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    int64_t netIfaceTxDrops() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_iface())
            {
                return m_delta->data_as_dbsync_network_iface()->tx_dropped();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface()->tx_dropped();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    int64_t netIfaceTxErrors() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_iface())
            {
                return m_delta->data_as_dbsync_network_iface()->tx_errors();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface()->tx_errors();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    int64_t netIfaceTxPackets() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_iface())
            {
                return m_delta->data_as_dbsync_network_iface()->tx_packets();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface()->tx_packets();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    std::string_view netIfaceAdapter() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_iface() && m_delta->data_as_dbsync_network_iface()->adapter())
            {
                return m_delta->data_as_dbsync_network_iface()->adapter()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface()->adapter())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface()->adapter()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    int64_t netIfaceMtu() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_iface())
            {
                return m_delta->data_as_dbsync_network_iface()->mtu();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface()->mtu();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    std::string_view netIfaceState() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_iface() && m_delta->data_as_dbsync_network_iface()->state())
            {
                return m_delta->data_as_dbsync_network_iface()->state()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface()->state())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface()->state()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view netIfaceType() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_iface() && m_delta->data_as_dbsync_network_iface()->type())
            {
                return m_delta->data_as_dbsync_network_iface()->type()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface()->type())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface()->type()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view netIfaceItemId() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_iface() && m_delta->data_as_dbsync_network_iface()->item_id())
            {
                return m_delta->data_as_dbsync_network_iface()->item_id()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface()->item_id())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_network_iface()->item_id()->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/item_id"_json_pointer))
            {
                return m_jsonData->at("/data/item_id"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    Operation operation() const
    {
        return m_operation;
    }

    AffectedComponentType affectedComponentType() const
    {
        return m_affectedComponentType;
    }

    OriginTable originTable() const
    {
        return m_originTable;
    }

    std::string m_serializedElement;

private:
    Operation m_operation = Operation::Invalid;
    AffectedComponentType m_affectedComponentType = AffectedComponentType::Invalid;
    OriginTable m_originTable = OriginTable::Invalid;
    VariantType m_type = VariantType::Invalid;

    const SyscollectorDeltas::Delta* m_delta = nullptr;
    const Synchronization::SyncMsg* m_syncMsg = nullptr;
    const nlohmann::json* m_jsonData = nullptr;

    std::string m_commandLineSanitized;
    std::string m_processStartISO8601;
    std::vector<std::string_view> m_processArguments;
    std::string m_installTimeISO8601;
    std::string m_portLocalIpSanitized;
    std::string m_portRemoteIpSanitized;

    /**
     * @brief Scan context.
     *
     */
    std::variant<const SyscollectorDeltas::Delta*, const Synchronization::SyncMsg*, const nlohmann::json*> m_data;

    void buildDeltaContext(const SyscollectorDeltas::Delta* delta)
    {
        m_delta = delta;
        if (delta->operation())
        {
            std::string_view operation = delta->operation()->string_view();
            // Modify events not exist for packages, because all fields that change in an update are PK.
            if (operation.compare("INSERTED") == 0 || operation.compare("MODIFIED") == 0)
            {
                m_operation = Operation::Upsert;
            }
            else if (operation.compare("DELETED") == 0)
            {
                m_operation = Operation::Delete;
            }
            else
            {
                throw std::runtime_error("Operation not found in delta.");
            }

            if (delta->data_type() == SyscollectorDeltas::Provider_dbsync_packages)
            {
                m_affectedComponentType = AffectedComponentType::Package;
                m_originTable = OriginTable::Packages;
            }
            else if (delta->data_type() == SyscollectorDeltas::Provider_dbsync_osinfo)
            {
                m_affectedComponentType = AffectedComponentType::System;
                m_originTable = OriginTable::Os;
            }
            else if (delta->data_type() == SyscollectorDeltas::Provider_dbsync_processes)
            {
                m_affectedComponentType = AffectedComponentType::Process;
                m_originTable = OriginTable::Processes;
            }
            else if (delta->data_type() == SyscollectorDeltas::Provider_dbsync_ports)
            {
                m_affectedComponentType = AffectedComponentType::Port;
                m_originTable = OriginTable::Ports;
            }
            else if (delta->data_type() == SyscollectorDeltas::Provider_dbsync_hotfixes)
            {
                m_affectedComponentType = AffectedComponentType::Hotfix;
                m_originTable = OriginTable::Hotfixes;
            }
            else if (delta->data_type() == SyscollectorDeltas::Provider_dbsync_hwinfo)
            {
                m_affectedComponentType = AffectedComponentType::Hardware;
                m_originTable = OriginTable::Hw;
            }
            else if (delta->data_type() == SyscollectorDeltas::Provider_dbsync_network_protocol)
            {
                m_affectedComponentType = AffectedComponentType::NetProto;
                m_originTable = OriginTable::NetworkProtocol;
            }
            else if (delta->data_type() == SyscollectorDeltas::Provider_dbsync_network_iface)
            {
                m_affectedComponentType = AffectedComponentType::NetIface;
                m_originTable = OriginTable::NetIfaces;
            }
            else if (delta->data_type() == SyscollectorDeltas::Provider_dbsync_network_address)
            {
                m_affectedComponentType = AffectedComponentType::NetworkAddress;
                m_originTable = OriginTable::NetAddress;
            }
            else if (delta->data_type() == SyscollectorDeltas::Provider_dbsync_users)
            {
                m_affectedComponentType = AffectedComponentType::User;
                m_originTable = OriginTable::Users;
            }
            else if (delta->data_type() == SyscollectorDeltas::Provider_dbsync_groups)
            {
                m_affectedComponentType = AffectedComponentType::Group;
                m_originTable = OriginTable::Groups;
            }
            else
            {
                // TO DO: Add log.
                // throw std::runtime_error("Attributes type not found in delta.");
            }
        }
        else
        {
            throw std::runtime_error("Operation not found in delta.");
        }
    }

    void buildSyncContext(const Synchronization::SyncMsg* syncMsg)
    {
        m_syncMsg = syncMsg;
        if (syncMsg->data_type() == Synchronization::DataUnion_state)
        {
            if (syncMsg->data_as_state()->attributes_type() == Synchronization::AttributesUnion_syscollector_osinfo)
            {
                m_operation = Operation::Upsert;
                m_affectedComponentType = AffectedComponentType::System;
                m_originTable = OriginTable::Os;
            }
            else if (syncMsg->data_as_state()->attributes_type() ==
                     Synchronization::AttributesUnion_syscollector_packages)
            {
                m_operation = Operation::Upsert;
                m_affectedComponentType = AffectedComponentType::Package;
                m_originTable = OriginTable::Packages;
            }
            else if (syncMsg->data_as_state()->attributes_type() ==
                     Synchronization::AttributesUnion_syscollector_processes)
            {
                m_operation = Operation::Upsert;
                m_affectedComponentType = AffectedComponentType::Process;
                m_originTable = OriginTable::Processes;
            }
            else if (syncMsg->data_as_state()->attributes_type() == Synchronization::AttributesUnion_syscollector_ports)
            {
                m_operation = Operation::Upsert;
                m_affectedComponentType = AffectedComponentType::Port;
                m_originTable = OriginTable::Ports;
            }
            else if (syncMsg->data_as_state()->attributes_type() ==
                     Synchronization::AttributesUnion_syscollector_hwinfo)
            {
                m_operation = Operation::Upsert;
                m_affectedComponentType = AffectedComponentType::Hardware;
                m_originTable = OriginTable::Hw;
            }
            else if (syncMsg->data_as_state()->attributes_type() ==
                     Synchronization::AttributesUnion_syscollector_hotfixes)
            {
                m_operation = Operation::Upsert;
                m_affectedComponentType = AffectedComponentType::Hotfix;
                m_originTable = OriginTable::Hotfixes;
            }
            else if (syncMsg->data_as_state()->attributes_type() ==
                     Synchronization::AttributesUnion_syscollector_network_protocol)
            {
                m_operation = Operation::Upsert;
                m_affectedComponentType = AffectedComponentType::NetProto;
                m_originTable = OriginTable::NetworkProtocol;
            }
            else if (syncMsg->data_as_state()->attributes_type() ==
                     Synchronization::AttributesUnion_syscollector_network_address)
            {
                m_operation = Operation::Upsert;
                m_affectedComponentType = AffectedComponentType::NetworkAddress;
                m_originTable = OriginTable::NetAddress;
            }
            else if (syncMsg->data_as_state()->attributes_type() ==
                     Synchronization::AttributesUnion_syscollector_network_iface)
            {
                m_operation = Operation::Upsert;
                m_affectedComponentType = AffectedComponentType::NetIface;
                m_originTable = OriginTable::NetIfaces;
            }
            else if (syncMsg->data_as_state()->attributes_type() == Synchronization::AttributesUnion_syscollector_users)
            {
                m_operation = Operation::Upsert;
                m_affectedComponentType = AffectedComponentType::User;
                m_originTable = OriginTable::Users;
            }
            else if (syncMsg->data_as_state()->attributes_type() ==
                     Synchronization::AttributesUnion_syscollector_groups)
            {
                m_operation = Operation::Upsert;
                m_affectedComponentType = AffectedComponentType::Group;
                m_originTable = OriginTable::Groups;
            }
            else
            {
                throw std::runtime_error("Attributes type not found in sync message. => " +
                                         std::to_string(syncMsg->data_as_state()->attributes_type()));
            }
        }
        else if (syncMsg->data_type() == Synchronization::DataUnion_integrity_clear)
        {
            if (auto attributesType = syncMsg->data_as_integrity_clear()->attributes_type(); attributesType)
            {
                auto attributesTypeStr = attributesType->string_view();
                if (attributesTypeStr.compare("syscollector_packages") == 0)
                {
                    m_operation = Operation::DeleteAllEntries;
                    m_affectedComponentType = AffectedComponentType::Package;
                    m_originTable = OriginTable::Packages;
                }
                else if (attributesTypeStr.compare("syscollector_osinfo") == 0)
                {
                    m_operation = Operation::DeleteAllEntries;
                    m_affectedComponentType = AffectedComponentType::System;
                    m_originTable = OriginTable::Os;
                }
                else if (attributesTypeStr.compare("syscollector_processes") == 0)
                {
                    m_operation = Operation::DeleteAllEntries;
                    m_affectedComponentType = AffectedComponentType::Process;
                    m_originTable = OriginTable::Processes;
                }
                else if (attributesTypeStr.compare("syscollector_ports") == 0)
                {
                    m_operation = Operation::DeleteAllEntries;
                    m_affectedComponentType = AffectedComponentType::Port;
                    m_originTable = OriginTable::Ports;
                }
                else if (attributesTypeStr.compare("syscollector_hwinfo") == 0)
                {
                    m_operation = Operation::DeleteAllEntries;
                    m_affectedComponentType = AffectedComponentType::Hardware;
                    m_originTable = OriginTable::Hw;
                }
                else if (attributesTypeStr.compare("syscollector_hotfixes") == 0)
                {
                    m_operation = Operation::DeleteAllEntries;
                    m_affectedComponentType = AffectedComponentType::Hotfix;
                    m_originTable = OriginTable::Hotfixes;
                }
                else if (attributesTypeStr.compare("syscollector_network_protocol") == 0)
                {
                    m_operation = Operation::DeleteAllEntries;
                    m_affectedComponentType = AffectedComponentType::NetProto;
                    m_originTable = OriginTable::NetworkProtocol;
                }
                else if (attributesTypeStr.compare("syscollector_network_iface") == 0)
                {
                    m_operation = Operation::DeleteAllEntries;
                    m_affectedComponentType = AffectedComponentType::NetIface;
                    m_originTable = OriginTable::NetIfaces;
                }
                else if (attributesTypeStr.compare("syscollector_network_address") == 0)
                {
                    m_operation = Operation::DeleteAllEntries;
                    m_affectedComponentType = AffectedComponentType::NetworkAddress;
                    m_originTable = OriginTable::NetAddress;
                }
                else if (attributesTypeStr.compare("syscollector_users") == 0)
                {
                    m_operation = Operation::DeleteAllEntries;
                    m_affectedComponentType = AffectedComponentType::User;
                    m_originTable = OriginTable::Users;
                }
                else if (attributesTypeStr.compare("syscollector_groups") == 0)
                {
                    m_operation = Operation::DeleteAllEntries;
                    m_affectedComponentType = AffectedComponentType::Group;
                    m_originTable = OriginTable::Groups;
                }
                else
                {
                    throw std::runtime_error("Attributes type not found in sync message.");
                }
            }
            else
            {
                throw std::runtime_error("Attributes type not found in sync message.");
            }
        }
        else if (syncMsg->data_type() == Synchronization::DataUnion_integrity_check_global)
        {
            if (auto attributesType = syncMsg->data_as_integrity_check_global()->attributes_type(); attributesType)
            {
                auto attributesTypeStr = attributesType->string_view();
                if (attributesTypeStr.compare("syscollector_packages") == 0)
                {
                    m_operation = Operation::IndexSync;
                    m_affectedComponentType = AffectedComponentType::Package;
                    m_originTable = OriginTable::Packages;
                }
                else if (attributesTypeStr.compare("syscollector_osinfo") == 0)
                {
                    m_operation = Operation::IndexSync;
                    m_affectedComponentType = AffectedComponentType::System;
                    m_originTable = OriginTable::Os;
                }
                else if (attributesTypeStr.compare("syscollector_processes") == 0)
                {
                    m_operation = Operation::IndexSync;
                    m_affectedComponentType = AffectedComponentType::Process;
                    m_originTable = OriginTable::Processes;
                }
                else if (attributesTypeStr.compare("syscollector_ports") == 0)
                {
                    m_operation = Operation::IndexSync;
                    m_affectedComponentType = AffectedComponentType::Port;
                    m_originTable = OriginTable::Ports;
                }
                else if (attributesTypeStr.compare("syscollector_hwinfo") == 0)
                {
                    m_operation = Operation::IndexSync;
                    m_affectedComponentType = AffectedComponentType::Hardware;
                    m_originTable = OriginTable::Hw;
                }
                else if (attributesTypeStr.compare("syscollector_hotfixes") == 0)
                {
                    m_operation = Operation::IndexSync;
                    m_affectedComponentType = AffectedComponentType::Hotfix;
                    m_originTable = OriginTable::Hotfixes;
                }
                else if (attributesTypeStr.compare("syscollector_network_protocol") == 0)
                {
                    m_operation = Operation::IndexSync;
                    m_affectedComponentType = AffectedComponentType::NetProto;
                    m_originTable = OriginTable::NetworkProtocol;
                }
                else if (attributesTypeStr.compare("syscollector_network_iface") == 0)
                {
                    m_operation = Operation::IndexSync;
                    m_affectedComponentType = AffectedComponentType::NetIface;
                    m_originTable = OriginTable::NetIfaces;
                }
                else if (attributesTypeStr.compare("syscollector_network_address") == 0)
                {
                    m_operation = Operation::IndexSync;
                    m_affectedComponentType = AffectedComponentType::NetworkAddress;
                    m_originTable = OriginTable::NetAddress;
                }
                else if (attributesTypeStr.compare("syscollector_users") == 0)
                {
                    m_operation = Operation::IndexSync;
                    m_affectedComponentType = AffectedComponentType::User;
                    m_originTable = OriginTable::Users;
                }
                else if (attributesTypeStr.compare("syscollector_groups") == 0)
                {
                    m_operation = Operation::IndexSync;
                    m_affectedComponentType = AffectedComponentType::Group;
                    m_originTable = OriginTable::Groups;
                }
                else
                {
                    // TO DO: Add log.
                    // throw std::runtime_error("Attributes type not found in sync message.");
                }
            }
            else
            {
                throw std::runtime_error("Attributes type not found in sync message.");
            }
        }
    }

    void buildJsonContext(const nlohmann::json* data)
    {
        if (std::string_view action = data->at("/action"_json_pointer).get<std::string_view>();
            action.compare("deleteAgent") == 0)
        {
            m_operation = Operation::DeleteAgent;
        }
        else if (action.compare("deletePackage") == 0)
        {
            m_operation = Operation::Delete;
            m_affectedComponentType = AffectedComponentType::Package;
            m_originTable = OriginTable::Packages;
        }
        else if (action.compare("deleteProcess") == 0)
        {
            m_operation = Operation::Delete;
            m_affectedComponentType = AffectedComponentType::Process;
            m_originTable = OriginTable::Processes;
        }
        else if (action.compare("deletePort") == 0)
        {
            m_operation = Operation::Delete;
            m_affectedComponentType = AffectedComponentType::Port;
            m_originTable = OriginTable::Ports;
        }
        else if (action.compare("deleteHardware") == 0)
        {
            m_operation = Operation::Delete;
            m_affectedComponentType = AffectedComponentType::Hardware;
            m_originTable = OriginTable::Hw;
        }
        else if (action.compare("deleteHotfix") == 0)
        {
            m_operation = Operation::Delete;
            m_affectedComponentType = AffectedComponentType::Hotfix;
            m_originTable = OriginTable::Hotfixes;
        }
        else if (action.compare("deleteNetProto") == 0)
        {
            m_operation = Operation::Delete;
            m_affectedComponentType = AffectedComponentType::NetProto;
            m_originTable = OriginTable::NetworkProtocol;
        }
        else if (action.compare("deleteNetIface") == 0)
        {
            m_operation = Operation::Delete;
            m_affectedComponentType = AffectedComponentType::NetIface;
            m_originTable = OriginTable::NetIfaces;
        }
        else if (action.compare("deleteNetworkAddress") == 0)
        {
            m_operation = Operation::Delete;
            m_affectedComponentType = AffectedComponentType::NetworkAddress;
            m_originTable = OriginTable::NetAddress;
        }
        else if (action.compare("deleteUser") == 0)
        {
            m_operation = Operation::Delete;
            m_affectedComponentType = AffectedComponentType::User;
            m_originTable = OriginTable::Users;
        }
        else if (action.compare("deleteGroup") == 0)
        {
            m_operation = Operation::Delete;
            m_affectedComponentType = AffectedComponentType::Group;
            m_originTable = OriginTable::Groups;
        }
        else if (action.compare("upgradeAgentDB") == 0)
        {
            m_operation = Operation::UpgradeAgentDB;
        }
        else
        {
            throw std::runtime_error("Operation not implemented: " + std::string(action));
        }
        m_jsonData = data;
    }
};

#endif // _SYSTEM_CONTEXT_HPP
