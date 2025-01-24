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

#ifndef _FIM_CONTEXT_HPP
#define _FIM_CONTEXT_HPP

#include "flatbuffers/include/rsync_generated.h"
#include "flatbuffers/include/syscheck_deltas_generated.h"
#include <json.hpp>
#include <variant>

struct FimContext final
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
        File,
        Registry,
        Invalid
    };

    enum class OriginTable
    {
        File,
        RegistryKey,
        RegistryValue,
        Invalid
    };

    explicit FimContext(
        std::variant<const SyscheckDeltas::Delta*, const Synchronization::SyncMsg*, const nlohmann::json*> data)
    {
        std::visit(
            [this](auto&& arg)
            {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, const SyscheckDeltas::Delta*>)
                {
                    m_data = std::forward<decltype(arg)>(arg);
                    m_delta = std::get<const SyscheckDeltas::Delta*>(m_data);
                    m_type = VariantType::Delta;

                    buildDeltaContext(m_delta);
                }
                else if constexpr (std::is_same_v<T, const Synchronization::SyncMsg*>)
                {
                    m_data = std::forward<decltype(arg)>(arg);
                    m_syncMsg = std::get<const Synchronization::SyncMsg*>(m_data);
                    m_type = VariantType::SyncMsg;

                    buildSyncContext(m_syncMsg);
                }
                else if constexpr (std::is_same_v<T, const nlohmann::json*>)
                {
                    m_data = std::forward<decltype(arg)>(arg);
                    m_jsonData = std::get<const nlohmann::json*>(m_data);
                    m_type = VariantType::Json;
                }
                else
                {
                    throw std::runtime_error("Unknown event type");
                }
            },
            data);
    }
    Operation operation() const
    {
        return m_operation;
    }

    OriginTable originTable() const
    {
        return m_originTable;
    }

    AffectedComponentType affectedComponentType() const
    {
        return m_affectedComponentType;
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

    std::string m_serializedElement;

private:
    Operation m_operation = Operation::Invalid;
    AffectedComponentType m_affectedComponentType = AffectedComponentType::Invalid;
    OriginTable m_originTable = OriginTable::Invalid;
    VariantType m_type = VariantType::Invalid;

    const SyscheckDeltas::Delta* m_delta = nullptr;
    const Synchronization::SyncMsg* m_syncMsg = nullptr;
    const nlohmann::json* m_jsonData = nullptr;

    /**
     * @brief Scan context.
     *
     */
    std::variant<const SyscheckDeltas::Delta*, const Synchronization::SyncMsg*, const nlohmann::json*> m_data;

    void buildDeltaContext(const SyscheckDeltas::Delta* delta)
    {
        if (delta->data() && delta->data()->type())
        {
            std::string_view operation = delta->data()->type()->string_view();
            if ((operation.compare("INSERTED") == 0) || (operation.compare("MODIFIED") == 0))
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
        }

        m_affectedComponentType = AffectedComponentType::File;
        m_originTable = OriginTable::File;
    }

    void buildSyncContext(const Synchronization::SyncMsg* syncMsg)
    {
        if (syncMsg->data_type() == Synchronization::DataUnion_state)
        {
            if (syncMsg->data_as_state()->attributes_type() == Synchronization::AttributesUnion_fim_file)
            {
                m_affectedComponentType = AffectedComponentType::File;
                m_operation = Operation::Upsert;
                m_originTable = OriginTable::File;
            }
            else if (syncMsg->data_as_state()->attributes_type() == Synchronization::AttributesUnion_fim_registry_key)
            {
                m_affectedComponentType = AffectedComponentType::Registry;
                m_operation = Operation::Upsert;
                m_originTable = OriginTable::RegistryKey;
            }
            else if (syncMsg->data_as_state()->attributes_type() == Synchronization::AttributesUnion_fim_registry_value)
            {
                m_affectedComponentType = AffectedComponentType::Registry;
                m_operation = Operation::Upsert;
                m_originTable = OriginTable::RegistryValue;
            }
            else
            {
                throw std::runtime_error("Attributes type not found in sync message.");
            }
        }
        else if (syncMsg->data_type() == Synchronization::DataUnion_integrity_clear)
        {
            if (syncMsg->data_as_integrity_clear()->attributes_type()->str().compare("fim_file") == 0)
            {
                m_affectedComponentType = AffectedComponentType::File;
                m_operation = Operation::DeleteAllEntries;
                m_originTable = OriginTable::File;
            }
            else if (syncMsg->data_as_integrity_clear()->attributes_type()->str().compare("fim_registry_key") == 0)
            {
                m_affectedComponentType = AffectedComponentType::Registry;
                m_operation = Operation::DeleteAllEntries;
                m_originTable = OriginTable::RegistryKey;
            }
            else if (syncMsg->data_as_integrity_clear()->attributes_type()->str().compare("fim_registry_value") == 0)
            {
                m_affectedComponentType = AffectedComponentType::Registry;
                m_operation = Operation::DeleteAllEntries;
                m_originTable = OriginTable::RegistryValue;
            }
            else
            {
                // Integrity clear for othre components not affected by the scanner.
            }
        }
        else if (syncMsg->data_type() == Synchronization::DataUnion_integrity_check_global)
        {
            if (syncMsg->data_as_integrity_check_global()->attributes_type()->str().compare("fim_file") == 0)
            {
                m_affectedComponentType = AffectedComponentType::File;
                m_operation = Operation::IndexSync;
            }
            else if (syncMsg->data_as_integrity_check_global()->attributes_type()->str().compare("fim_registry_key") ==
                         0 ||
                     syncMsg->data_as_integrity_check_global()->attributes_type()->str().compare(
                         "fim_registry_value") == 0)
            {
                // Registry key and values share the same index, so we can use RegistryValue or
                // RegistryKey as the affected component type. The selection of the affected component
                // type is arbitrary.
                m_affectedComponentType = AffectedComponentType::Registry;
                m_operation = Operation::IndexSync;
            }
            else
            {
                throw std::runtime_error("Attributes type not found in sync message.");
            }
        }
    }
};

#endif // _FIM_CONTEXT_HPP
