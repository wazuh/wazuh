/*
 * Wazuh inventory harvester
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
        Invalid,
    };
    enum class AffectedComponentType : std::uint8_t
    {
        Package,
        Process,
        System,
        Invalid
    };

    enum class OriginTable : std::uint8_t
    {
        Packages,
        Processes,
        Os,
        Hw,
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
                    auto delta = std::get<const SyscollectorDeltas::Delta*>(m_data);
                    m_type = VariantType::Delta;

                    buildDeltaContext(delta);
                }
                else if constexpr (std::is_same_v<T, const Synchronization::SyncMsg*>)
                {
                    m_data = std::forward<decltype(arg)>(arg);
                    auto syncMsg = std::get<const Synchronization::SyncMsg*>(m_data);
                    m_type = VariantType::SyncMsg;

                    buildSyncContext(syncMsg);
                }
                else if constexpr (std::is_same_v<T, const nlohmann::json*>)
                {
                    m_data = std::forward<decltype(arg)>(arg);
                    m_type = VariantType::Json;
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
            if (m_jsonData->contains("/agent_info/agent_name"_json_pointer))
            {
                return m_jsonData->at("/agent_info/agent_name"_json_pointer).get<std::string_view>();
            }
        }
        return "";
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
            if (m_jsonData->contains("/agent_info/agent_ip"_json_pointer))
            {
                return m_jsonData->at("/agent_info/agent_ip"_json_pointer).get<std::string_view>();
            }
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
            if (m_jsonData->contains("/agent_info/agent_version"_json_pointer))
            {
                return m_jsonData->at("/agent_info/agent_version"_json_pointer).get<std::string_view>();
            }
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
            if (m_jsonData->contains("/data/name"_json_pointer))
            {
                return m_jsonData->at("/data/name"_json_pointer).get<std::string_view>();
            }
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
            if (m_jsonData->contains("/data/version"_json_pointer))
            {
                return m_jsonData->at("/data/version"_json_pointer).get<std::string_view>();
            }
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
            if (m_jsonData->contains("/data/vendor"_json_pointer))
            {
                return m_jsonData->at("/data/vendor"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view packageInstallTime() const
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
            if (m_jsonData->contains("/data/install_time"_json_pointer))
            {
                return m_jsonData->at("/data/install_time"_json_pointer).get<std::string_view>();
            }
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
            if (m_jsonData->contains("/data/location"_json_pointer))
            {
                return m_jsonData->at("/data/location"_json_pointer).get<std::string_view>();
            }
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
            if (m_jsonData->contains("/data/architecture"_json_pointer))
            {
                return m_jsonData->at("/data/architecture"_json_pointer).get<std::string_view>();
            }
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
            if (m_jsonData->contains("/data/groups"_json_pointer))
            {
                return m_jsonData->at("/data/groups"_json_pointer).get<std::string_view>();
            }
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
            if (m_jsonData->contains("/data/description"_json_pointer))
            {
                return m_jsonData->at("/data/description"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    uint64_t packageSize() const
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
            if (m_jsonData->contains("/data/size"_json_pointer))
            {
                return m_jsonData->at("/data/size"_json_pointer).get<uint64_t>();
            }
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
            if (m_jsonData->contains("/data/priority"_json_pointer))
            {
                return m_jsonData->at("/data/priority"_json_pointer).get<std::string_view>();
            }
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
            if (m_jsonData->contains("/data/multiarch"_json_pointer))
            {
                return m_jsonData->at("/data/multiarch"_json_pointer).get<std::string_view>();
            }
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
            if (m_jsonData->contains("/data/source"_json_pointer))
            {
                return m_jsonData->at("/data/source"_json_pointer).get<std::string_view>();
            }
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
            if (m_jsonData->contains("/data/format"_json_pointer))
            {
                return m_jsonData->at("/data/format"_json_pointer).get<std::string_view>();
            }
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
            if (m_jsonData->contains("/data/minor_version"_json_pointer))
            {
                return m_jsonData->at("/data/minor_version"_json_pointer).get<std::string_view>();
            }
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
            if (m_jsonData->contains("/data/name"_json_pointer))
            {
                return m_jsonData->at("/data/name"_json_pointer).get<std::string_view>();
            }
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

    std::string_view processCmdline() const
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
            if (m_jsonData->contains("/data/cmd"_json_pointer))
            {
                return m_jsonData->at("/data/cmd"_json_pointer).get<std::string_view>();
            }
        }
        return "";
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
            if (m_jsonData->contains("/data/argvs"_json_pointer))
            {
                return m_jsonData->at("/data/argvs"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    uint64_t processParentID() const
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
            if (m_jsonData->contains("/data/ppid"_json_pointer))
            {
                return m_jsonData->at("/data/ppid"_json_pointer).get<uint64_t>();
            }
        }
        return 0;
    }

    uint64_t processStart() const
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
            if (m_jsonData->contains("/data/start_time"_json_pointer))
            {
                return m_jsonData->at("/data/start_time"_json_pointer).get<uint64_t>();
            }
        }
        return 0;
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
            // else if (delta->data_type() == SyscollectorDeltas::Provider_dbsync_hwinfo)
            // {
            //     m_affectedComponentType = AffectedComponentType::System;
            //     m_originTable = OriginTable::Hw;
            // }
            else if (delta->data_type() == SyscollectorDeltas::Provider_dbsync_processes)
            {
                m_affectedComponentType = AffectedComponentType::Process;
                m_originTable = OriginTable::Processes;
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
            // else if (syncMsg->data_as_state()->attributes_type() ==
            //          Synchronization::AttributesUnion_syscollector_hwinfo)
            // {
            //     m_operation = Operation::Upsert;
            //     m_affectedComponentType = AffectedComponentType::System;
            //     m_originTable = OriginTable::Hw;
            // }
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
            else
            {
                // TO DO: Add log.
                // throw std::runtime_error("Attributes type not found in sync message.");{
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
                // else if (attributesTypeStr.compare("syscollector_hwinfo") == 0)
                // {
                //     m_operation = Operation::DeleteAllEntries;
                //     m_affectedComponentType = AffectedComponentType::System;
                //     m_originTable = OriginTable::Hw;
                // }
                else if (attributesTypeStr.compare("syscollector_processes") == 0)
                {
                    m_operation = Operation::DeleteAllEntries;
                    m_affectedComponentType = AffectedComponentType::Process;
                    m_originTable = OriginTable::Processes;
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
                // else if ((attributesTypeStr.compare("syscollector_hwinfo") == 0))
                // {
                //     m_operation = Operation::IndexSync;
                //     m_affectedComponentType = AffectedComponentType::System;
                //     m_originTable = OriginTable::Os;
                // }
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
};

#endif // _SYSTEM_CONTEXT_HPP
