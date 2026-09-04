/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "cHostOps.hpp"

#include "taskManagerLog.hpp"

namespace
{
    /// @brief Read a JSON array of agent ids.
    ///
    /// The host returns an array; anything else -- including the discarded value a malformed
    /// document parses to -- is treated as "the query did not complete", which the callers map to
    /// a retry rather than to an empty result. Reading a failure as "no agents" would silently
    /// turn a wedged wazuh-db into a successful no-op sweep.
    std::optional<std::vector<int>> readIdArray(const std::optional<nlohmann::json>& document)
    {
        if (!document.has_value() || !document->is_array())
        {
            return std::nullopt;
        }

        std::vector<int> ids;
        ids.reserve(document->size());
        for (const auto& entry : *document)
        {
            if (entry.is_number_integer())
            {
                ids.push_back(entry.get<int>());
            }
        }
        return ids;
    }
} // namespace

namespace task_manager::host
{
    CHostOps::CHostOps(const task_manager_host_ops_t& ops)
        : m_ops {ops}
    {
    }

    std::vector<std::string> CHostOps::missingOperations() const
    {
        std::vector<std::string> missing;

        if (m_ops.is_worker == nullptr)
        {
            missing.emplace_back("is_worker");
        }
        if (m_ops.disconnect_agents == nullptr)
        {
            missing.emplace_back("disconnect_agents");
        }
        if (m_ops.get_agents_by_status_from == nullptr)
        {
            missing.emplace_back("get_agents_by_status_from");
        }
        if (m_ops.get_agent_info == nullptr)
        {
            missing.emplace_back("get_agent_info");
        }
        if (m_ops.free_json == nullptr)
        {
            missing.emplace_back("free_json");
        }
        if (m_ops.remove_agent == nullptr)
        {
            missing.emplace_back("remove_agent");
        }
        if (m_ops.rotate_log_daily == nullptr)
        {
            missing.emplace_back("rotate_log_daily");
        }
        if (m_ops.rotate_log_size == nullptr)
        {
            missing.emplace_back("rotate_log_size");
        }

        return missing;
    }

    int CHostOps::workerState()
    {
        if (m_ops.is_worker == nullptr)
        {
            // Unknown, not master. A missing operation must never be read as "this node may run
            // master-scoped work".
            return -1;
        }
        return m_ops.is_worker();
    }

    std::optional<nlohmann::json>
    CHostOps::callJson(int (*fn)(int, const char*, char**), const int arg, const std::string& text)
    {
        if (fn == nullptr || m_ops.free_json == nullptr)
        {
            return std::nullopt;
        }

        char* raw {nullptr};
        if (fn(arg, text.c_str(), &raw) != 0 || raw == nullptr)
        {
            if (raw != nullptr)
            {
                m_ops.free_json(raw);
            }
            return std::nullopt;
        }

        auto parsed = nlohmann::json::parse(raw, nullptr, false);
        m_ops.free_json(raw);

        if (parsed.is_discarded())
        {
            return std::nullopt;
        }

        return parsed;
    }

    std::optional<std::vector<int>> CHostOps::disconnectAgents(const long keepAliveBefore,
                                                               const std::string& syncStatus)
    {
        if (m_ops.disconnect_agents == nullptr || m_ops.free_json == nullptr)
        {
            return std::nullopt;
        }

        char* raw {nullptr};
        if (m_ops.disconnect_agents(keepAliveBefore, syncStatus.c_str(), &raw) != 0 || raw == nullptr)
        {
            if (raw != nullptr)
            {
                m_ops.free_json(raw);
            }
            return std::nullopt;
        }

        auto parsed = nlohmann::json::parse(raw, nullptr, false);
        m_ops.free_json(raw);

        return readIdArray(parsed.is_discarded() ? std::optional<nlohmann::json> {} : parsed);
    }

    std::optional<std::vector<int>> CHostOps::agentsByStatusFrom(const int afterId, const std::string& status)
    {
        return readIdArray(callJson(m_ops.get_agents_by_status_from, afterId, status));
    }

    std::optional<nlohmann::json> CHostOps::agentInfo(const int agentId)
    {
        if (m_ops.get_agent_info == nullptr || m_ops.free_json == nullptr)
        {
            return std::nullopt;
        }

        char* raw {nullptr};
        if (m_ops.get_agent_info(agentId, &raw) != 0 || raw == nullptr)
        {
            if (raw != nullptr)
            {
                m_ops.free_json(raw);
            }
            return std::nullopt;
        }

        auto parsed = nlohmann::json::parse(raw, nullptr, false);
        m_ops.free_json(raw);

        if (parsed.is_discarded())
        {
            return std::nullopt;
        }

        return parsed;
    }

    bool CHostOps::removeAgent(const int agentId, const int timeoutSeconds, int& authdError)
    {
        authdError = 0;

        if (m_ops.remove_agent == nullptr)
        {
            return false;
        }

        return m_ops.remove_agent(agentId, timeoutSeconds, &authdError) == 0 || authdError != 0;
    }

    bool CHostOps::rotateLogDaily(const bool compress, const int keepDays, const int maxRotations)
    {
        if (m_ops.rotate_log_daily == nullptr)
        {
            return false;
        }
        return m_ops.rotate_log_daily(compress ? 1 : 0, keepDays, maxRotations) == 0;
    }

    bool
    CHostOps::rotateLogBySize(const bool compress, const int keepDays, const int maxRotations, const long sizeBytes)
    {
        if (m_ops.rotate_log_size == nullptr)
        {
            return false;
        }
        return m_ops.rotate_log_size(compress ? 1 : 0, keepDays, maxRotations, sizeBytes) == 1;
    }
} // namespace task_manager::host
