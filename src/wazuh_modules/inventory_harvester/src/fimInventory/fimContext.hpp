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
public:
    enum class VariantType : std::uint8_t
    {
        Delta,
        SyncMsg,
        Json,
        Invalid
    };
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
        File,
        Registry,
        Invalid
    };

    enum class OriginTable : std::uint8_t
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

                    buildJsonContext(std::get<const nlohmann::json*>(m_data));
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

    VariantType type() const
    {
        return m_type;
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

    std::string_view path()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data() && m_delta->data()->path())
            {
                return m_delta->data()->path()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_type() == Synchronization::DataUnion_state)
            {
                if (m_syncMsg->data_as_state()->attributes_as_fim_file() && m_syncMsg->data_as_state()->index())
                {
                    return m_syncMsg->data_as_state()->index()->string_view();
                }
                else if ((m_syncMsg->data_as_state()->attributes_as_fim_registry_key() ||
                          m_syncMsg->data_as_state()->attributes_as_fim_registry_value()) &&
                         m_syncMsg->data_as_state()->path())
                {
                    return m_syncMsg->data_as_state()->path()->string_view();
                }
            }
        }
        else
        {
            if (m_jsonData->contains("/data/path"_json_pointer))
            {
                return m_jsonData->at("/data/path"_json_pointer).get<std::string_view>();
            }
        }
        return "";
    }

    std::string_view valueName()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data() && m_delta->data()->value_name())
            {
                return m_delta->data()->value_name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_type() == Synchronization::DataUnion_state)
            {
                if (m_syncMsg->data_as_state()->value_name())
                {
                    return m_syncMsg->data_as_state()->value_name()->string_view();
                }
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view arch()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data() && m_delta->data()->arch())
            {
                return m_delta->data()->arch()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_type() == Synchronization::DataUnion_state)
            {
                if (m_syncMsg->data_as_state()->arch())
                {
                    return m_syncMsg->data_as_state()->arch()->string_view();
                }
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view md5()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data() && m_delta->data()->attributes() && m_delta->data()->attributes()->hash_md5())
            {
                return m_delta->data()->attributes()->hash_md5()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_type() == Synchronization::DataUnion_state)
            {
                if (m_syncMsg->data_as_state()->attributes_as_fim_file() &&
                    m_syncMsg->data_as_state()->attributes_as_fim_file()->hash_md5())
                {
                    return m_syncMsg->data_as_state()->attributes_as_fim_file()->hash_md5()->string_view();
                }
                else if (m_syncMsg->data_as_state()->attributes_as_fim_registry_value() &&
                         m_syncMsg->data_as_state()->attributes_as_fim_registry_value()->hash_md5())
                {
                    return m_syncMsg->data_as_state()->attributes_as_fim_registry_value()->hash_md5()->string_view();
                }
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view sha1()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data() && m_delta->data()->attributes() && m_delta->data()->attributes()->hash_sha1())
            {
                return m_delta->data()->attributes()->hash_sha1()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_type() == Synchronization::DataUnion_state)
            {
                if (m_syncMsg->data_as_state()->attributes_as_fim_file() &&
                    m_syncMsg->data_as_state()->attributes_as_fim_file()->hash_sha1())
                {
                    return m_syncMsg->data_as_state()->attributes_as_fim_file()->hash_sha1()->string_view();
                }
                else if (m_syncMsg->data_as_state()->attributes_as_fim_registry_value() &&
                         m_syncMsg->data_as_state()->attributes_as_fim_registry_value()->hash_sha1())
                {
                    return m_syncMsg->data_as_state()->attributes_as_fim_registry_value()->hash_sha1()->string_view();
                }
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view sha256()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data() && m_delta->data()->attributes() && m_delta->data()->attributes()->hash_sha256())
            {
                return m_delta->data()->attributes()->hash_sha256()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_type() == Synchronization::DataUnion_state)
            {
                if (m_syncMsg->data_as_state()->attributes_as_fim_file() &&
                    m_syncMsg->data_as_state()->attributes_as_fim_file()->hash_sha256())
                {
                    return m_syncMsg->data_as_state()->attributes_as_fim_file()->hash_sha256()->string_view();
                }
                else if (m_syncMsg->data_as_state()->attributes_as_fim_registry_value() &&
                         m_syncMsg->data_as_state()->attributes_as_fim_registry_value()->hash_sha256())
                {
                    return m_syncMsg->data_as_state()->attributes_as_fim_registry_value()->hash_sha256()->string_view();
                }
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    uint64_t size()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data() && m_delta->data()->attributes())
            {
                return m_delta->data()->attributes()->size();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_type() == Synchronization::DataUnion_state)
            {
                if (m_syncMsg->data_as_state()->attributes_as_fim_file())
                {
                    return m_syncMsg->data_as_state()->attributes_as_fim_file()->size();
                }
                else if (m_syncMsg->data_as_state()->attributes_as_fim_registry_value())
                {
                    return m_syncMsg->data_as_state()->attributes_as_fim_registry_value()->size();
                }
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    uint64_t inode()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data() && m_delta->data()->attributes())
            {
                return m_delta->data()->attributes()->inode();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_type() == Synchronization::DataUnion_state)
            {
                if (m_syncMsg->data_as_state()->attributes_as_fim_file())
                {
                    return m_syncMsg->data_as_state()->attributes_as_fim_file()->inode();
                }
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }

    std::string_view valueType()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data() && m_delta->data()->attributes() && m_delta->data()->attributes()->value_type())
            {
                return m_delta->data()->attributes()->value_type()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_type() == Synchronization::DataUnion_state)
            {
                if (m_syncMsg->data_as_state()->attributes_as_fim_registry_value() &&
                    m_syncMsg->data_as_state()->attributes_as_fim_registry_value()->value_type())
                {
                    return m_syncMsg->data_as_state()->attributes_as_fim_registry_value()->value_type()->string_view();
                }
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view userName()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data() && m_delta->data()->attributes() && m_delta->data()->attributes()->user_name())
            {
                return m_delta->data()->attributes()->user_name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_type() == Synchronization::DataUnion_state)
            {
                if (m_syncMsg->data_as_state()->attributes_as_fim_file() &&
                    m_syncMsg->data_as_state()->attributes_as_fim_file()->user_name())
                {
                    return m_syncMsg->data_as_state()->attributes_as_fim_file()->user_name()->string_view();
                }
                else if (m_syncMsg->data_as_state()->attributes_as_fim_registry_key() &&
                         m_syncMsg->data_as_state()->attributes_as_fim_registry_key()->user_name())
                {
                    return m_syncMsg->data_as_state()->attributes_as_fim_registry_key()->user_name()->string_view();
                }
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view groupName()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data() && m_delta->data()->attributes() && m_delta->data()->attributes()->group_name())
            {
                return m_delta->data()->attributes()->group_name()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_type() == Synchronization::DataUnion_state)
            {
                if (m_syncMsg->data_as_state()->attributes_as_fim_file() &&
                    m_syncMsg->data_as_state()->attributes_as_fim_file()->group_name())
                {
                    return m_syncMsg->data_as_state()->attributes_as_fim_file()->group_name()->string_view();
                }
                else if (m_syncMsg->data_as_state()->attributes_as_fim_registry_key() &&
                         m_syncMsg->data_as_state()->attributes_as_fim_registry_key()->group_name())
                {
                    return m_syncMsg->data_as_state()->attributes_as_fim_registry_key()->group_name()->string_view();
                }
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view uid()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data() && m_delta->data()->attributes() && m_delta->data()->attributes()->uid())
            {
                return m_delta->data()->attributes()->uid()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_type() == Synchronization::DataUnion_state)
            {
                if (m_syncMsg->data_as_state()->attributes_as_fim_file() &&
                    m_syncMsg->data_as_state()->attributes_as_fim_file()->uid())
                {
                    return m_syncMsg->data_as_state()->attributes_as_fim_file()->uid()->string_view();
                }
                else if (m_syncMsg->data_as_state()->attributes_as_fim_registry_key() &&
                         m_syncMsg->data_as_state()->attributes_as_fim_registry_key()->uid())
                {
                    return m_syncMsg->data_as_state()->attributes_as_fim_registry_key()->uid()->string_view();
                }
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    std::string_view gid()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data() && m_delta->data()->attributes() && m_delta->data()->attributes()->gid())
            {
                return m_delta->data()->attributes()->gid()->string_view();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_type() == Synchronization::DataUnion_state)
            {
                if (m_syncMsg->data_as_state()->attributes_as_fim_file() &&
                    m_syncMsg->data_as_state()->attributes_as_fim_file()->gid())
                {
                    return m_syncMsg->data_as_state()->attributes_as_fim_file()->gid()->string_view();
                }
                else if (m_syncMsg->data_as_state()->attributes_as_fim_registry_key() &&
                         m_syncMsg->data_as_state()->attributes_as_fim_registry_key()->gid())
                {
                    return m_syncMsg->data_as_state()->attributes_as_fim_registry_key()->gid()->string_view();
                }
            }
        }
        else
        {
            return "";
        }
        return "";
    }

    uint64_t mtime()
    {
        if (m_type == VariantType::Delta)
        {
            if (m_delta->data() && m_delta->data()->attributes())
            {
                return m_delta->data()->attributes()->mtime();
            }
        }
        else if (m_type == VariantType::SyncMsg)
        {
            if (m_syncMsg->data_type() == Synchronization::DataUnion_state)
            {
                if (m_syncMsg->data_as_state()->attributes_as_fim_file())
                {
                    return m_syncMsg->data_as_state()->attributes_as_fim_file()->mtime();
                }
                else if (m_syncMsg->data_as_state()->attributes_as_fim_registry_key())
                {
                    return m_syncMsg->data_as_state()->attributes_as_fim_registry_key()->mtime();
                }
            }
        }
        else
        {
            return 0;
        }
        return 0;
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
            if ((operation.compare("added") == 0) || (operation.compare("modified") == 0))
            {
                m_operation = Operation::Upsert;
            }
            else if (operation.compare("deleted") == 0)
            {
                m_operation = Operation::Delete;
            }
            else
            {
                throw std::runtime_error(std::string("Operation not found in delta: ") + std::string(operation));
            }
        }
        else
        {
            throw std::runtime_error("Operation not found in delta.");
        }

        if (m_delta->data() && m_delta->data()->attributes() && m_delta->data()->attributes()->type())
        {
            if (m_delta->data()->attributes()->type()->string_view().compare("registry_key") == 0)
            {
                m_affectedComponentType = AffectedComponentType::Registry;
                m_originTable = OriginTable::RegistryKey;
            }
            else if (m_delta->data()->attributes()->type()->string_view().compare("registry_value") == 0)
            {
                m_affectedComponentType = AffectedComponentType::Registry;
                m_originTable = OriginTable::RegistryValue;
            }
            else if (m_delta->data()->attributes()->type()->string_view().compare("file") == 0)
            {
                m_affectedComponentType = AffectedComponentType::File;
                m_originTable = OriginTable::File;
            }
            else
            {
                throw std::runtime_error(std::string("Attributes type not found in delta: ") +
                                         std::string(m_delta->data()->attributes()->type()->string_view()));
            }
        }
        else
        {
            throw std::runtime_error("Attributes type not found in delta.");
        }
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
            if (syncMsg->data_as_integrity_clear()->attributes_type()->string_view().compare("fim_file") == 0)
            {
                m_affectedComponentType = AffectedComponentType::File;
                m_operation = Operation::DeleteAllEntries;
                m_originTable = OriginTable::File;
            }
            else if (syncMsg->data_as_integrity_clear()->attributes_type()->string_view().compare("fim_registry_key") ==
                     0)
            {
                m_affectedComponentType = AffectedComponentType::Registry;
                m_operation = Operation::DeleteAllEntries;
                m_originTable = OriginTable::RegistryKey;
            }
            else if (syncMsg->data_as_integrity_clear()->attributes_type()->string_view().compare(
                         "fim_registry_value") == 0)
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
            if (syncMsg->data_as_integrity_check_global()->attributes_type()->string_view().compare("fim_file") == 0)
            {
                m_affectedComponentType = AffectedComponentType::File;
                m_operation = Operation::IndexSync;
            }
            else if (syncMsg->data_as_integrity_check_global()->attributes_type()->string_view().compare(
                         "fim_registry_key") == 0 ||
                     syncMsg->data_as_integrity_check_global()->attributes_type()->string_view().compare(
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

    void buildJsonContext(const nlohmann::json* data)
    {
        std::string_view action = data->at("/action"_json_pointer).get<std::string_view>();

        if (action.compare("deleteAgent") == 0)
        {
            m_operation = Operation::DeleteAgent;
        }
        else if (action.compare("deleteFile") == 0)
        {
            m_operation = Operation::Delete;
            m_affectedComponentType = AffectedComponentType::File;
            m_originTable = OriginTable::File;
        }
        else if (action.compare("deleteRegistry") == 0)
        {
            m_operation = Operation::Delete;
            m_affectedComponentType = AffectedComponentType::Registry;
            // Registry key and values share the same index, so we can use RegistryValue or
            // RegistryKey as the affected component type. The selection of the affected component
            // type is arbitrary. Apart from that, the key + value are merged in the origin (wazuh-db), it is the same
            // key/id for the indexer.
            m_originTable = OriginTable::RegistryKey;
        }
        else
        {
            throw std::runtime_error("Operation not implemented: " + std::string(action));
        }
    }
};

#endif // _FIM_CONTEXT_HPP
