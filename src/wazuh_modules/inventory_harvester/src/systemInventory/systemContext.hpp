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
    enum class VariantType
    {
        Delta,
        SyncMsg,
        Json,
        Invalid
    };

public:
    enum class Operation
    {
        Delete,
        Upsert,
        DeleteAgent,
        DeleteAllEntries,
        IndexSync,
        Invalid,
    };
    enum class AffectedComponentType
    {
        Package,
        Process,
        System,
        Invalid
    };

    enum class OriginTable
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
            else if (delta->data_type() == SyscollectorDeltas::Provider_dbsync_hwinfo)
            {
                m_affectedComponentType = AffectedComponentType::System;
                m_originTable = OriginTable::Hw;
            }
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
        if (syncMsg->data_type() == Synchronization::DataUnion_state)
        {
            if (syncMsg->data_as_state()->attributes_type() == Synchronization::AttributesUnion_syscollector_osinfo)
            {
                m_operation = Operation::Upsert;
                m_affectedComponentType = AffectedComponentType::System;
                m_originTable = OriginTable::Os;
            }
            else if (syncMsg->data_as_state()->attributes_type() ==
                     Synchronization::AttributesUnion_syscollector_hwinfo)
            {
                m_operation = Operation::Upsert;
                m_affectedComponentType = AffectedComponentType::System;
                m_originTable = OriginTable::Hw;
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
                else if (attributesTypeStr.compare("syscollector_hwinfo") == 0)
                {
                    m_operation = Operation::DeleteAllEntries;
                    m_affectedComponentType = AffectedComponentType::System;
                    m_originTable = OriginTable::Hw;
                }
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
                else if ((attributesTypeStr.compare("syscollector_hwinfo") == 0))
                {
                    m_operation = Operation::IndexSync;
                    m_affectedComponentType = AffectedComponentType::System;
                    m_originTable = OriginTable::Os;
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
