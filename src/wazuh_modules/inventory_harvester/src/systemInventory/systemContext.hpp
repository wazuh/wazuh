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
#include <loggerHelper.h>
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
        BrowserExtension,
        Service,
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
        BrowserExtensions,
        Services,
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
            if (m_delta->data_as_dbsync_groups() && m_delta->data_as_dbsync_groups()->group_name())
            {
                return m_delta->data_as_dbsync_groups()->group_name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_groups() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->group_name())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->group_name()->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/group_name"_json_pointer))
            {
                return m_jsonData->at("/data/group_name"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    int64_t groupId() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_groups() && m_delta->data_as_dbsync_groups()->group_id() &&
                std::optional<int64_t>(m_delta->data_as_dbsync_groups()->group_id()).has_value())
            {
                return std::optional<int64_t>(m_delta->data_as_dbsync_groups()->group_id()).value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_groups() &&
                std::optional<int64_t>(m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->group_id())
                    .has_value())
            {
                return std::optional<int64_t>(
                           m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->group_id())
                    .value();
            }
        }
        else
        {
            return -1;
        }
        return -1;
    }

    int64_t groupIdSigned() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_groups() &&
                std::optional<int64_t>(m_delta->data_as_dbsync_groups()->group_id_signed()).has_value())
            {
                return std::optional<int64_t>(m_delta->data_as_dbsync_groups()->group_id_signed()).value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_groups() &&
                std::optional<int64_t>(
                    m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->group_id_signed())
                    .has_value())
            {
                return std::optional<int64_t>(
                           m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->group_id_signed())
                    .value();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    std::string_view groupDescription() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_groups() && m_delta->data_as_dbsync_groups()->group_description())
            {
                return m_delta->data_as_dbsync_groups()->group_description()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_groups() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->group_description())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_groups()
                    ->group_description()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view groupUuid() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_groups() && m_delta->data_as_dbsync_groups()->group_uuid())
            {
                return m_delta->data_as_dbsync_groups()->group_uuid()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_groups() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->group_uuid())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->group_uuid()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    bool groupIsHidden() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_groups() &&
                std::optional<bool>(m_delta->data_as_dbsync_groups()->group_is_hidden()).has_value())
            {
                return std::optional<bool>(m_delta->data_as_dbsync_groups()->group_is_hidden()).value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_groups() &&
                std::optional<bool>(m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->group_is_hidden())
                    .has_value())
            {
                return std::optional<bool>(
                           m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->group_is_hidden())
                    .value();
            }
        }
        else
        {
            return false;
        }
        return false;
    }

    std::string_view groupUsers() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_groups() && m_delta->data_as_dbsync_groups()->group_users())
            {
                return m_delta->data_as_dbsync_groups()->group_users()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_groups() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->group_users())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_groups()->group_users()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    // Service data fields
    std::string_view serviceName() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->name())
            {
                return m_delta->data_as_dbsync_services()->name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->name())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_services()->name()->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/name"_json_pointer))
            {
                return m_jsonData->at("/data/name"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view serviceDisplayName() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->display_name())
            {
                return m_delta->data_as_dbsync_services()->display_name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->display_name())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_services()->display_name()->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/display_name"_json_pointer))
            {
                return m_jsonData->at("/data/display_name"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view serviceDescription() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->description())
            {
                return m_delta->data_as_dbsync_services()->description()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->description())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_services()->description()->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/description"_json_pointer))
            {
                return m_jsonData->at("/data/description"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view serviceType() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->service_type())
            {
                return m_delta->data_as_dbsync_services()->service_type()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->service_type())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_services()->service_type()->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/service_type"_json_pointer))
            {
                return m_jsonData->at("/data/service_type"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view serviceStartType() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->start_type())
            {
                return m_delta->data_as_dbsync_services()->start_type()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->start_type())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_services()->start_type()->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/start_type"_json_pointer))
            {
                return m_jsonData->at("/data/start_type"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view serviceState() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->state())
            {
                return m_delta->data_as_dbsync_services()->state()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->state())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_services()->state()->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/state"_json_pointer))
            {
                return m_jsonData->at("/data/state"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view serviceSubState() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->sub_state())
            {
                return m_delta->data_as_dbsync_services()->sub_state()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->sub_state())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_services()->sub_state()->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/sub_state"_json_pointer))
            {
                return m_jsonData->at("/data/sub_state"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    long servicePid() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services())
            {
                return m_delta->data_as_dbsync_services()->pid() ? m_delta->data_as_dbsync_services()->pid().value()
                                                                 : 0;
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_services()->pid()
                           ? m_syncMsg->data_as_state()->attributes_as_syscollector_services()->pid().value()
                           : 0;
            }
        }
        else
        {
            if (m_jsonData->contains("/data/pid"_json_pointer))
            {
                return m_jsonData->at("/data/pid"_json_pointer).get<long>();
            }
        }
        return 0;
    }

    std::string_view serviceBinaryPath() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->binary_path())
            {
                return m_delta->data_as_dbsync_services()->binary_path()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->binary_path())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_services()->binary_path()->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/binary_path"_json_pointer))
            {
                return m_jsonData->at("/data/binary_path"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view serviceEnabled() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->unit_file_state())
            {
                return m_delta->data_as_dbsync_services()->unit_file_state()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->unit_file_state())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_services()
                    ->unit_file_state()
                    ->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/unit_file_state"_json_pointer))
            {
                return m_jsonData->at("/data/unit_file_state"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    long serviceExitCode() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services())
            {
                return m_delta->data_as_dbsync_services()->service_exit_code()
                           ? m_delta->data_as_dbsync_services()->service_exit_code().value()
                           : 0;
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_services()->service_exit_code()
                           ? m_syncMsg->data_as_state()
                                 ->attributes_as_syscollector_services()
                                 ->service_exit_code()
                                 .value()
                           : 0;
            }
        }
        else
        {
            if (m_jsonData->contains("/data/service_exit_code"_json_pointer))
            {
                return m_jsonData->at("/data/service_exit_code"_json_pointer).get<long>();
            }
        }
        return 0;
    }

    std::string_view serviceUser() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->user())
            {
                return m_delta->data_as_dbsync_services()->user()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->user())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_services()->user()->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/user"_json_pointer))
            {
                return m_jsonData->at("/data/user"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    // New macOS launchd service fields
    std::string_view serviceNameECS() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->service_name())
            {
                return m_delta->data_as_dbsync_services()->service_name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->service_name())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_services()->service_name()->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/service_name"_json_pointer))
            {
                return m_jsonData->at("/data/service_name"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view processExecutable() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->process_executable())
            {
                return m_delta->data_as_dbsync_services()->process_executable()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->process_executable())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_services()
                    ->process_executable()
                    ->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/process_executable"_json_pointer))
            {
                return m_jsonData->at("/data/process_executable"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view processArgs() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->process_args())
            {
                return m_delta->data_as_dbsync_services()->process_args()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->process_args())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_services()->process_args()->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/process_args"_json_pointer))
            {
                return m_jsonData->at("/data/process_args"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view filePath() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->file_path())
            {
                return m_delta->data_as_dbsync_services()->file_path()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->file_path())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_services()->file_path()->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/file_path"_json_pointer))
            {
                return m_jsonData->at("/data/file_path"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view processUserName() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->process_user_name())
            {
                return m_delta->data_as_dbsync_services()->process_user_name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->process_user_name())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_services()
                    ->process_user_name()
                    ->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/process_user_name"_json_pointer))
            {
                return m_jsonData->at("/data/process_user_name"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view processGroupName() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->process_group_name())
            {
                return m_delta->data_as_dbsync_services()->process_group_name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->process_group_name())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_services()
                    ->process_group_name()
                    ->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/process_group_name"_json_pointer))
            {
                return m_jsonData->at("/data/process_group_name"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view serviceEnabledText() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->service_enabled())
            {
                return m_delta->data_as_dbsync_services()->service_enabled()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->service_enabled())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_services()
                    ->service_enabled()
                    ->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/service_enabled"_json_pointer))
            {
                return m_jsonData->at("/data/service_enabled"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view serviceRestart() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->service_restart())
            {
                return m_delta->data_as_dbsync_services()->service_restart()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->service_restart())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_services()
                    ->service_restart()
                    ->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/service_restart"_json_pointer))
            {
                return m_jsonData->at("/data/service_restart"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    long serviceFrequency() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services())
            {
                return m_delta->data_as_dbsync_services()->service_frequency()
                           ? m_delta->data_as_dbsync_services()->service_frequency().value()
                           : 0;
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_services()->service_frequency()
                           ? m_syncMsg->data_as_state()
                                 ->attributes_as_syscollector_services()
                                 ->service_frequency()
                                 .value()
                           : 0;
            }
        }
        else
        {
            if (m_jsonData->contains("/data/service_frequency"_json_pointer))
            {
                return m_jsonData->at("/data/service_frequency"_json_pointer).get<long>();
            }
        }
        return 0;
    }

    std::string_view logFilePath() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->log_file_path())
            {
                return m_delta->data_as_dbsync_services()->log_file_path()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->log_file_path())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_services()
                    ->log_file_path()
                    ->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/log_file_path"_json_pointer))
            {
                return m_jsonData->at("/data/log_file_path"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view errorLogFilePath() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->error_log_file_path())
            {
                return m_delta->data_as_dbsync_services()->error_log_file_path()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->error_log_file_path())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_services()
                    ->error_log_file_path()
                    ->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/error_log_file_path"_json_pointer))
            {
                return m_jsonData->at("/data/error_log_file_path"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view processWorkingDir() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->process_working_dir())
            {
                return m_delta->data_as_dbsync_services()->process_working_dir()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->process_working_dir())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_services()
                    ->process_working_dir()
                    ->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/process_working_dir"_json_pointer))
            {
                return m_jsonData->at("/data/process_working_dir"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view processRootDir() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() && m_delta->data_as_dbsync_services()->process_root_dir())
            {
                return m_delta->data_as_dbsync_services()->process_root_dir()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->process_root_dir())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_services()
                    ->process_root_dir()
                    ->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/process_root_dir"_json_pointer))
            {
                return m_jsonData->at("/data/process_root_dir"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    bool serviceStartsOnMount() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services())
            {
                return m_delta->data_as_dbsync_services()->service_starts_on_mount()
                           ? m_delta->data_as_dbsync_services()->service_starts_on_mount().value()
                           : false;
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_services()->service_starts_on_mount()
                           ? m_syncMsg->data_as_state()
                                 ->attributes_as_syscollector_services()
                                 ->service_starts_on_mount()
                                 .value()
                           : false;
            }
        }
        else
        {
            if (m_jsonData->contains("/data/service_starts_on_mount"_json_pointer))
            {
                return m_jsonData->at("/data/service_starts_on_mount"_json_pointer).get<bool>();
            }
        }
        return false;
    }

    std::string_view serviceStartsOnPathModified() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() &&
                m_delta->data_as_dbsync_services()->service_starts_on_path_modified())
            {
                return m_delta->data_as_dbsync_services()->service_starts_on_path_modified()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_services()->service_starts_on_path_modified())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_services()
                    ->service_starts_on_path_modified()
                    ->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/service_starts_on_path_modified"_json_pointer))
            {
                return m_jsonData->at("/data/service_starts_on_path_modified"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view serviceStartsOnNotEmptyDirectory() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services() &&
                m_delta->data_as_dbsync_services()->service_starts_on_not_empty_directory())
            {
                return m_delta->data_as_dbsync_services()->service_starts_on_not_empty_directory()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services() &&
                m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_services()
                    ->service_starts_on_not_empty_directory())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_services()
                    ->service_starts_on_not_empty_directory()
                    ->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/service_starts_on_not_empty_directory"_json_pointer))
            {
                return m_jsonData->at("/data/service_starts_on_not_empty_directory"_json_pointer)
                    .get<std::string_view>();
            }
        }
        return "";
    }

    bool serviceInetdCompatibility() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_services())
            {
                return m_delta->data_as_dbsync_services()->service_inetd_compatibility()
                           ? m_delta->data_as_dbsync_services()->service_inetd_compatibility().value()
                           : false;
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_services())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_services()->service_inetd_compatibility()
                           ? m_syncMsg->data_as_state()
                                 ->attributes_as_syscollector_services()
                                 ->service_inetd_compatibility()
                                 .value()
                           : false;
            }
        }
        else
        {
            if (m_jsonData->contains("/data/service_inetd_compatibility"_json_pointer))
            {
                return m_jsonData->at("/data/service_inetd_compatibility"_json_pointer).get<bool>();
            }
        }
        return false;
    }

    // User data fields
    std::string_view userName() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->user_name())
            {
                return m_delta->data_as_dbsync_users()->user_name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_name())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_name()->string_view();
            }
        }
        else
        {
            if (m_jsonData->contains("/data/user_name"_json_pointer))
            {
                return m_jsonData->at("/data/user_name"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    int64_t userId() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() &&
                std::optional<int64_t>(m_delta->data_as_dbsync_users()->user_id()).has_value())
            {
                return std::optional<int64_t>(m_delta->data_as_dbsync_users()->user_id()).value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                std::optional<int64_t>(m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_id())
                    .has_value())
            {
                return std::optional<int64_t>(m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_id())
                    .value();
            }
        }
        else
        {
            return -1;
        }
        return -1;
    }

    int64_t userUidSigned() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() &&
                std::optional<int64_t>(m_delta->data_as_dbsync_users()->user_uid_signed()).has_value())
            {
                return std::optional<int64_t>(m_delta->data_as_dbsync_users()->user_uid_signed()).value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                std::optional<int64_t>(
                    m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_uid_signed())
                    .has_value())
            {
                return std::optional<int64_t>(
                           m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_uid_signed())
                    .value();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    int64_t userGroupId() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() &&
                std::optional<int64_t>(m_delta->data_as_dbsync_users()->user_group_id()).has_value())
            {
                return std::optional<int64_t>(m_delta->data_as_dbsync_users()->user_group_id()).value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                std::optional<int64_t>(m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_group_id())
                    .has_value())
            {
                return std::optional<int64_t>(
                           m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_group_id())
                    .value();
            }
        }
        else
        {
            return -1;
        }
        return -1;
    }

    int64_t userGroupIdSigned() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() &&
                std::optional<int64_t>(m_delta->data_as_dbsync_users()->user_group_id_signed()).has_value())
            {
                return std::optional<int64_t>(m_delta->data_as_dbsync_users()->user_group_id_signed()).value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                std::optional<int64_t>(
                    m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_group_id_signed())
                    .has_value())
            {
                return std::optional<int64_t>(
                           m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_group_id_signed())
                    .value();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    std::string_view userHome() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->user_home())
            {
                return m_delta->data_as_dbsync_users()->user_home()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_home())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_home()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view userShell() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->user_shell())
            {
                return m_delta->data_as_dbsync_users()->user_shell()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_shell())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_shell()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view userType() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->user_type())
            {
                return m_delta->data_as_dbsync_users()->user_type()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_type())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_type()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view userUuid() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->user_uuid())
            {
                return m_delta->data_as_dbsync_users()->user_uuid()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_uuid())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_uuid()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view userFullName() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->user_full_name())
            {
                return m_delta->data_as_dbsync_users()->user_full_name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_full_name())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_full_name()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    bool userIsHidden() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() &&
                std::optional<bool>(m_delta->data_as_dbsync_users()->user_is_hidden()).has_value())
            {
                return std::optional<bool>(m_delta->data_as_dbsync_users()->user_is_hidden()).value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                std::optional<bool>(m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_is_hidden())
                    .has_value())
            {
                return std::optional<bool>(
                           m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_is_hidden())
                    .value();
            }
        }
        else
        {
            return false;
        }
        return false;
    }

    bool userIsRemote() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() &&
                std::optional<bool>(m_delta->data_as_dbsync_users()->user_is_remote()).has_value())
            {
                return std::optional<bool>(m_delta->data_as_dbsync_users()->user_is_remote()).value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                std::optional<bool>(m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_is_remote())
                    .has_value())
            {
                return std::optional<bool>(
                           m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_is_remote())
                    .value();
            }
        }
        else
        {
            return false;
        }
        return false;
    }

    std::string_view userPasswordHashAlgorithm() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->user_password_hash_algorithm())
            {
                return m_delta->data_as_dbsync_users()->user_password_hash_algorithm()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_password_hash_algorithm())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_users()
                    ->user_password_hash_algorithm()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    int userPasswordLastChange() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() &&
                std::optional<int>(m_delta->data_as_dbsync_users()->user_password_last_change()).has_value())
            {
                return std::optional<int>(m_delta->data_as_dbsync_users()->user_password_last_change()).value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                std::optional<int>(
                    m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_password_last_change())
                    .has_value())
            {
                return std::optional<int>(
                           m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_password_last_change())
                    .value();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    int userPasswordMaxDays() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() &&
                std::optional<int>(m_delta->data_as_dbsync_users()->user_password_max_days_between_changes())
                    .has_value())
            {
                return std::optional<int>(m_delta->data_as_dbsync_users()->user_password_max_days_between_changes())
                    .value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                std::optional<int>(m_syncMsg->data_as_state()
                                       ->attributes_as_syscollector_users()
                                       ->user_password_max_days_between_changes())
                    .has_value())
            {
                return std::optional<int>(m_syncMsg->data_as_state()
                                              ->attributes_as_syscollector_users()
                                              ->user_password_max_days_between_changes())
                    .value();
            }
        }
        else
        {
            return -1;
        }
        return -1;
    }

    int userPasswordMinDays() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() &&
                std::optional<int>(m_delta->data_as_dbsync_users()->user_password_min_days_between_changes())
                    .has_value())
            {
                return std::optional<int>(m_delta->data_as_dbsync_users()->user_password_min_days_between_changes())
                    .value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                std::optional<int>(m_syncMsg->data_as_state()
                                       ->attributes_as_syscollector_users()
                                       ->user_password_min_days_between_changes())
                    .has_value())
            {
                return std::optional<int>(m_syncMsg->data_as_state()
                                              ->attributes_as_syscollector_users()
                                              ->user_password_min_days_between_changes())
                    .value();
            }
        }
        else
        {
            return -1;
        }
        return -1;
    }

    int userPasswordWarningDays() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() &&
                std::optional<int>(m_delta->data_as_dbsync_users()->user_password_warning_days_before_expiration())
                    .has_value())
            {
                return std::optional<int>(
                           m_delta->data_as_dbsync_users()->user_password_warning_days_before_expiration())
                    .value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                std::optional<int>(m_syncMsg->data_as_state()
                                       ->attributes_as_syscollector_users()
                                       ->user_password_warning_days_before_expiration())
                    .has_value())
            {
                return std::optional<int>(m_syncMsg->data_as_state()
                                              ->attributes_as_syscollector_users()
                                              ->user_password_warning_days_before_expiration())
                    .value();
            }
        }
        else
        {
            return -1;
        }
        return -1;
    }

    std::string_view userPasswordStatus() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->user_password_status())
            {
                return m_delta->data_as_dbsync_users()->user_password_status()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_password_status())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_users()
                    ->user_password_status()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    double userPasswordLastChangeRaw() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() &&
                std::optional<double>(m_delta->data_as_dbsync_users()->user_password_last_change()).has_value())
            {
                return std::optional<double>(m_delta->data_as_dbsync_users()->user_password_last_change()).value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                std::optional<double>(
                    m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_password_last_change())
                    .has_value())
            {
                return std::optional<double>(
                           m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_password_last_change())
                    .value();
            }
        }
        else
        {
            return 0.0;
        }
        return 0.0;
    }

    std::string_view userPasswordLastChange()
    {
        const auto passwordLastChangeRaw = userPasswordLastChangeRaw();
        // For dates, valid values are > 0.
        if (passwordLastChangeRaw <= 0.0)
        {
            return "";
        }
        m_userPasswordLastChangeISO8601 = Utils::rawTimestampToISO8601(passwordLastChangeRaw);
        return m_userPasswordLastChangeISO8601;
    }

    int userPasswordExpirationDateRaw() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() &&
                std::optional<int>(m_delta->data_as_dbsync_users()->user_password_expiration_date()).has_value())
            {
                return std::optional<int>(m_delta->data_as_dbsync_users()->user_password_expiration_date()).value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                std::optional<int>(
                    m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_password_expiration_date())
                    .has_value())
            {
                return std::optional<int>(m_syncMsg->data_as_state()
                                              ->attributes_as_syscollector_users()
                                              ->user_password_expiration_date())
                    .value();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    std::string_view userPasswordExpirationDate()
    {
        const auto passwordExpirationDateRaw = userPasswordExpirationDateRaw();
        // For dates, valid values are > 0.
        if (passwordExpirationDateRaw <= 0)
        {
            return "";
        }
        m_userPasswordExpirationDateISO8601 =
            Utils::rawTimestampToISO8601(static_cast<uint32_t>(passwordExpirationDateRaw));
        return m_userPasswordExpirationDateISO8601;
    }

    int userPasswordInactiveDays() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() &&
                std::optional<int>(m_delta->data_as_dbsync_users()->user_password_inactive_days()).has_value())
            {
                return std::optional<int>(m_delta->data_as_dbsync_users()->user_password_inactive_days()).value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                std::optional<int>(
                    m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_password_inactive_days())
                    .has_value())
            {
                return std::optional<int>(m_syncMsg->data_as_state()
                                              ->attributes_as_syscollector_users()
                                              ->user_password_inactive_days())
                    .value();
            }
        }
        else
        {
            return -1;
        }
        return -1;
    }

    double userCreatedRaw() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() &&
                std::optional<double>(m_delta->data_as_dbsync_users()->user_created()).has_value())
            {
                return std::optional<double>(m_delta->data_as_dbsync_users()->user_created()).value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                std::optional<double>(m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_created())
                    .has_value())
            {
                return std::optional<double>(
                           m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_created())
                    .value();
            }
        }
        else
        {
            return 0.0;
        }
        return 0.0;
    }

    std::string_view userCreated()
    {
        const auto createdRaw = userCreatedRaw();
        // For dates, valid values are > 0.
        if (createdRaw <= 0.0)
        {
            return "";
        }
        m_userCreatedISO8601 = Utils::rawTimestampToISO8601(createdRaw);
        return m_userCreatedISO8601;
    }

    int64_t userLastLoginRaw() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() &&
                std::optional<int64_t>(m_delta->data_as_dbsync_users()->user_last_login()).has_value())
            {
                return std::optional<int64_t>(m_delta->data_as_dbsync_users()->user_last_login()).value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                std::optional<int64_t>(
                    m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_last_login())
                    .has_value())
            {
                return std::optional<int64_t>(
                           m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_last_login())
                    .value();
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    std::string_view userLastLogin()
    {
        const auto lastLoginRaw = userLastLoginRaw();
        // For dates, valid values are > 0.
        if (lastLoginRaw <= 0)
        {
            return "";
        }
        m_userLastLoginISO8601 = Utils::rawTimestampToISO8601(static_cast<uint32_t>(lastLoginRaw));
        return m_userLastLoginISO8601;
    }

    std::string_view userRoles() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->user_roles())
            {
                return m_delta->data_as_dbsync_users()->user_roles()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_roles())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_roles()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view userGroups() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->user_groups())
            {
                return m_delta->data_as_dbsync_users()->user_groups()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_groups())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_groups()->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    int64_t userAuthFailedCount() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() &&
                std::optional<int64_t>(m_delta->data_as_dbsync_users()->user_auth_failed_count()).has_value())
            {
                return std::optional<int64_t>(m_delta->data_as_dbsync_users()->user_auth_failed_count()).value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                std::optional<int64_t>(
                    m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_auth_failed_count())
                    .has_value())
            {
                return std::optional<int64_t>(
                           m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_auth_failed_count())
                    .value();
            }
        }
        else
        {
            return -1;
        }
        return -1;
    }

    double userAuthFailedTimestampRaw() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() &&
                std::optional<double>(m_delta->data_as_dbsync_users()->user_auth_failed_timestamp()).has_value())
            {
                return std::optional<double>(m_delta->data_as_dbsync_users()->user_auth_failed_timestamp()).value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                std::optional<double>(
                    m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_auth_failed_timestamp())
                    .has_value())
            {
                return std::optional<double>(
                           m_syncMsg->data_as_state()->attributes_as_syscollector_users()->user_auth_failed_timestamp())
                    .value();
            }
        }
        else
        {
            return 0.0;
        }
        return 0.0;
    }

    std::string_view userAuthFailedTimestamp()
    {
        const auto authFailedTimestampRaw = userAuthFailedTimestampRaw();
        // For dates, valid values are > 0.
        if (authFailedTimestampRaw <= 0.0)
        {
            return "";
        }
        m_userAuthFailedTimestampISO8601 = Utils::rawTimestampToISO8601(authFailedTimestampRaw);
        return m_userAuthFailedTimestampISO8601;
    }

    bool userLoginStatus() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() &&
                std::optional<bool>(m_delta->data_as_dbsync_users()->login_status()).has_value())
            {
                return std::optional<bool>(m_delta->data_as_dbsync_users()->login_status()).value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                std::optional<bool>(m_syncMsg->data_as_state()->attributes_as_syscollector_users()->login_status())
                    .has_value())
            {
                return std::optional<bool>(
                           m_syncMsg->data_as_state()->attributes_as_syscollector_users()->login_status())
                    .value();
            }
        }
        else
        {
            return false;
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
        else
        {
            return "";
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
        else
        {
            return "";
        }
        return "";
    }

    int64_t userProcessPid() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() &&
                std::optional<int64_t>(m_delta->data_as_dbsync_users()->process_pid()).has_value())
            {
                return std::optional<int64_t>(m_delta->data_as_dbsync_users()->process_pid()).value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                std::optional<int64_t>(m_syncMsg->data_as_state()->attributes_as_syscollector_users()->process_pid())
                    .has_value())
            {
                return std::optional<int64_t>(
                           m_syncMsg->data_as_state()->attributes_as_syscollector_users()->process_pid())
                    .value();
            }
        }
        else
        {
            return -1;
        }
        return -1;
    }

    std::string_view userHostIp() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_users() && m_delta->data_as_dbsync_users()->host_ip())
            {
                return m_delta->data_as_dbsync_users()->host_ip()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_users() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_users()->host_ip())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_users()->host_ip()->string_view();
            }
        }
        else
        {
            return "";
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
            if (m_jsonData->contains("/data/os_name"_json_pointer))
            {
                return m_jsonData->at("/data/os_name"_json_pointer).get<std::string_view>();
            }
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

    // Browser extensions
    std::string_view browserName() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() &&
                m_delta->data_as_dbsync_browser_extensions()->browser_name())
            {
                return m_delta->data_as_dbsync_browser_extensions()->browser_name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions()->browser_name())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_browser_extensions()
                    ->browser_name()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view browserExtensionUserID() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() && m_delta->data_as_dbsync_browser_extensions()->user_id())
            {
                return m_delta->data_as_dbsync_browser_extensions()->user_id()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions()->user_id())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_browser_extensions()
                    ->user_id()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view browserExtensionPackageName() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() &&
                m_delta->data_as_dbsync_browser_extensions()->package_name())
            {
                return m_delta->data_as_dbsync_browser_extensions()->package_name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions()->package_name())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_browser_extensions()
                    ->package_name()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view browserExtensionPackageID() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() &&
                m_delta->data_as_dbsync_browser_extensions()->package_id())
            {
                return m_delta->data_as_dbsync_browser_extensions()->package_id()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions()->package_id())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_browser_extensions()
                    ->package_id()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view browserExtensionPackageVersion() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() &&
                m_delta->data_as_dbsync_browser_extensions()->package_version())
            {
                return m_delta->data_as_dbsync_browser_extensions()->package_version()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions()->package_version())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_browser_extensions()
                    ->package_version()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view browserExtensionPackageDescription() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() &&
                m_delta->data_as_dbsync_browser_extensions()->package_description())
            {
                return m_delta->data_as_dbsync_browser_extensions()->package_description()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions()->package_description())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_browser_extensions()
                    ->package_description()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view browserExtensionPackageVendor() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() &&
                m_delta->data_as_dbsync_browser_extensions()->package_vendor())
            {
                return m_delta->data_as_dbsync_browser_extensions()->package_vendor()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions()->package_vendor())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_browser_extensions()
                    ->package_vendor()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view browserExtensionPackageBuildVersion() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() &&
                m_delta->data_as_dbsync_browser_extensions()->package_build_version())
            {
                return m_delta->data_as_dbsync_browser_extensions()->package_build_version()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions()->package_build_version())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_browser_extensions()
                    ->package_build_version()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view browserExtensionPackagePath() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() &&
                m_delta->data_as_dbsync_browser_extensions()->package_path())
            {
                return m_delta->data_as_dbsync_browser_extensions()->package_path()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions()->package_path())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_browser_extensions()
                    ->package_path()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view browserProfileName() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() &&
                m_delta->data_as_dbsync_browser_extensions()->browser_profile_name())
            {
                return m_delta->data_as_dbsync_browser_extensions()->browser_profile_name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions()->browser_profile_name())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_browser_extensions()
                    ->browser_profile_name()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view browserProfilePath() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() &&
                m_delta->data_as_dbsync_browser_extensions()->browser_profile_path())
            {
                return m_delta->data_as_dbsync_browser_extensions()->browser_profile_path()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions()->browser_profile_path())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_browser_extensions()
                    ->browser_profile_path()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view browserExtensionPackageReference() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() &&
                m_delta->data_as_dbsync_browser_extensions()->package_reference())
            {
                return m_delta->data_as_dbsync_browser_extensions()->package_reference()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions()->package_reference())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_browser_extensions()
                    ->package_reference()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view browserExtensionPackagePermissions() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() &&
                m_delta->data_as_dbsync_browser_extensions()->package_permissions())
            {
                return m_delta->data_as_dbsync_browser_extensions()->package_permissions()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions()->package_permissions())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_browser_extensions()
                    ->package_permissions()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view browserExtensionPackageType() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() &&
                m_delta->data_as_dbsync_browser_extensions()->package_type())
            {
                return m_delta->data_as_dbsync_browser_extensions()->package_type()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions()->package_type())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_browser_extensions()
                    ->package_type()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view browserExtensionPackageEnabled() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() &&
                m_delta->data_as_dbsync_browser_extensions()->package_enabled())
            {
                return m_delta->data_as_dbsync_browser_extensions()->package_enabled()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions()->package_enabled())

            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_browser_extensions()
                    ->package_enabled()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    bool browserExtensionPackageAutoupdate() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() &&
                std::optional<bool>(m_delta->data_as_dbsync_browser_extensions()->package_autoupdate()).has_value())
            {
                return std::optional<bool>(m_delta->data_as_dbsync_browser_extensions()->package_autoupdate()).value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                std::optional<bool>(
                    m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions()->package_autoupdate())
                    .has_value())
            {
                return std::optional<bool>(m_syncMsg->data_as_state()
                                               ->attributes_as_syscollector_browser_extensions()
                                               ->package_autoupdate())
                    .value();
            }
        }
        else
        {
            return false;
        }
        return false;
    }

    bool browserExtensionPackagePersistent() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() &&
                std::optional<bool>(m_delta->data_as_dbsync_browser_extensions()->package_persistent()).has_value())
            {
                return std::optional<bool>(m_delta->data_as_dbsync_browser_extensions()->package_persistent()).value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                std::optional<bool>(
                    m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions()->package_persistent())
                    .has_value())
            {
                return std::optional<bool>(m_syncMsg->data_as_state()
                                               ->attributes_as_syscollector_browser_extensions()
                                               ->package_persistent())
                    .value();
            }
        }
        else
        {
            return false;
        }
        return false;
    }

    bool browserExtensionPackageFromWebstore() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() &&
                std::optional<bool>(m_delta->data_as_dbsync_browser_extensions()->package_from_webstore()).has_value())
            {
                return std::optional<bool>(m_delta->data_as_dbsync_browser_extensions()->package_from_webstore())
                    .value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                std::optional<bool>(m_syncMsg->data_as_state()
                                        ->attributes_as_syscollector_browser_extensions()
                                        ->package_from_webstore())
                    .has_value())
            {
                return std::optional<bool>(m_syncMsg->data_as_state()
                                               ->attributes_as_syscollector_browser_extensions()
                                               ->package_from_webstore())
                    .value();
            }
        }
        else
        {
            return false;
        }
        return false;
    }

    bool browserProfileReferenced() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() &&
                std::optional<bool>(m_delta->data_as_dbsync_browser_extensions()->browser_profile_referenced())
                    .has_value())
            {
                return std::optional<bool>(m_delta->data_as_dbsync_browser_extensions()->browser_profile_referenced())
                    .value();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                std::optional<bool>(m_syncMsg->data_as_state()
                                        ->attributes_as_syscollector_browser_extensions()
                                        ->browser_profile_referenced())
                    .has_value())
            {
                return std::optional<bool>(m_syncMsg->data_as_state()
                                               ->attributes_as_syscollector_browser_extensions()
                                               ->browser_profile_referenced())
                    .value();
            }
        }
        else
        {
            return false;
        }
        return false;
    }

    std::string_view browserExtensionPackageInstalledRaw() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() &&
                m_delta->data_as_dbsync_browser_extensions()->package_installed())
            {
                return m_delta->data_as_dbsync_browser_extensions()->package_installed()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions()->package_installed())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_browser_extensions()
                    ->package_installed()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view browserExtensionPackageInstalled()
    {
        auto PackageInstalledRaw = browserExtensionPackageInstalledRaw();
        if (PackageInstalledRaw.compare(" ") == 0)
        {
            return "";
        }
        m_browserExtensionPackageInstalled = Utils::rawTimestampToISO8601(PackageInstalledRaw);
        return m_browserExtensionPackageInstalled;
    }

    std::string_view browserExtensionFileHashSha256() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() &&
                m_delta->data_as_dbsync_browser_extensions()->file_hash_sha256())
            {
                return m_delta->data_as_dbsync_browser_extensions()->file_hash_sha256()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions()->file_hash_sha256())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_browser_extensions()
                    ->file_hash_sha256()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view browserExtensionItemId() const
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_browser_extensions() && m_delta->data_as_dbsync_browser_extensions()->item_id())
            {
                return m_delta->data_as_dbsync_browser_extensions()->item_id()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_browser_extensions()->item_id())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_browser_extensions()
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
    std::string m_userPasswordLastChangeISO8601;
    std::string m_userPasswordExpirationDateISO8601;
    std::string m_userCreatedISO8601;
    std::string m_userLastLoginISO8601;
    std::string m_userAuthFailedTimestampISO8601;
    std::string m_browserExtensionPackageInstalled;

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
            else if (delta->data_type() == SyscollectorDeltas::Provider_dbsync_browser_extensions)
            {
                m_affectedComponentType = AffectedComponentType::BrowserExtension;
                m_originTable = OriginTable::BrowserExtensions;
            }
            else if (delta->data_type() == SyscollectorDeltas::Provider_dbsync_services)
            {
                m_affectedComponentType = AffectedComponentType::Service;
                m_originTable = OriginTable::Services;
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
            else if (syncMsg->data_as_state()->attributes_type() ==
                     Synchronization::AttributesUnion_syscollector_browser_extensions)
            {
                m_operation = Operation::Upsert;
                m_affectedComponentType = AffectedComponentType::BrowserExtension;
                m_originTable = OriginTable::BrowserExtensions;
            }
            else if (syncMsg->data_as_state()->attributes_type() ==
                     Synchronization::AttributesUnion_syscollector_services)
            {
                m_operation = Operation::Upsert;
                m_affectedComponentType = AffectedComponentType::Service;
                m_originTable = OriginTable::Services;
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
                else if (attributesTypeStr.compare("syscollector_browser_extensions") == 0)
                {
                    m_operation = Operation::DeleteAllEntries;
                    m_affectedComponentType = AffectedComponentType::BrowserExtension;
                    m_originTable = OriginTable::BrowserExtensions;
                }
                else if (attributesTypeStr.compare("syscollector_services") == 0)
                {
                    m_operation = Operation::DeleteAllEntries;
                    m_affectedComponentType = AffectedComponentType::Service;
                    m_originTable = OriginTable::Services;
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
                else if (attributesTypeStr.compare("syscollector_browser_extensions") == 0)
                {
                    m_operation = Operation::IndexSync;
                    m_affectedComponentType = AffectedComponentType::BrowserExtension;
                    m_originTable = OriginTable::BrowserExtensions;
                }
                else if (attributesTypeStr.compare("syscollector_services") == 0)
                {
                    m_operation = Operation::IndexSync;
                    m_affectedComponentType = AffectedComponentType::Service;
                    m_originTable = OriginTable::Services;
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
        else if (action.compare("deleteOs") == 0)
        {
            m_operation = Operation::Delete;
            m_affectedComponentType = AffectedComponentType::System;
            m_originTable = OriginTable::Os;
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
        else if (action.compare("deleteBrowserExtension") == 0)
        {
            m_operation = Operation::Delete;
            m_affectedComponentType = AffectedComponentType::BrowserExtension;
            m_originTable = OriginTable::BrowserExtensions;
        }
        else if (action.compare("deleteService") == 0)
        {
            m_operation = Operation::Delete;
            m_affectedComponentType = AffectedComponentType::Service;
            m_originTable = OriginTable::Services;
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
