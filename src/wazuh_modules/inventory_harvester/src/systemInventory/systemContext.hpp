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
        return "";
    }

    int64_t freeMem()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_hwinfo() && m_delta->data_as_dbsync_hwinfo()->ram_free())
            {
                return m_delta->data_as_dbsync_hwinfo()->ram_free();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo()->ram_free())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo()->ram_free();
            }
        }
        return 0;
    }

    int64_t totalMem()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_hwinfo() && m_delta->data_as_dbsync_hwinfo()->ram_total())
            {
                return m_delta->data_as_dbsync_hwinfo()->ram_total();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo()->ram_total())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo()->ram_total();
            }
        }
        return 0;
    }

    int64_t usedMem()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_hwinfo() && m_delta->data_as_dbsync_hwinfo()->ram_usage())
            {
                return m_delta->data_as_dbsync_hwinfo()->ram_usage();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() && m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo()->ram_usage())
            {
                return m_syncMsg->data_as_state()->attributes_as_syscollector_hwinfo()->ram_usage();
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
            return 0;
        }
        return 0;
    }

    uint64_t processStartRaw() const
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
        return installTimeRaw;
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

    std::string_view portLocalIp() const
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

    std::string_view portRemoteIp() const
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

    std::string_view netProtoMetric()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data_as_dbsync_network_protocol() && m_delta->data_as_dbsync_network_protocol()->metric())
            {
                return m_delta->data_as_dbsync_network_protocol()->metric()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_as_state() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_protocol() &&
                m_syncMsg->data_as_state()->attributes_as_syscollector_network_protocol()->metric())
            {
                return m_syncMsg->data_as_state()
                    ->attributes_as_syscollector_network_protocol()
                    ->metric()
                    ->string_view();
            }
        }
        else
        {
            return "";
        }
        return "";
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
        else
        {
            throw std::runtime_error("Operation not implemented: " + std::string(action));
        }
        m_jsonData = data;
    }
};

#endif // _SYSTEM_CONTEXT_HPP
