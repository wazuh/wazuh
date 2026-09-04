/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TASK_MANAGER_HOST_AGENT_ROW_HPP
#define _TASK_MANAGER_HOST_AGENT_ROW_HPP

#include <json.hpp>

#include <string>

namespace task_manager::host
{
    /**
     * @brief Unwrap an agent row from what the host operations return.
     *
     * wazuh-db answers `get-agent-info` with a single-element ARRAY holding the row, and the C shim
     * hands that JSON across the ABI verbatim rather than unwrapping it. Every caller therefore has
     * to cope with both shapes.
     *
     * Shared rather than copied. Two subsystems now read agent rows -- the disconnect sweep and the
     * upgrade path -- and a second private copy of this that forgot the array case would not crash:
     * it would find no fields and report every agent as missing from the database, which reads like
     * a wazuh-db outage rather than a bug here.
     *
     * @return A pointer into `document`, or nullptr when there is no row. Never owns.
     */
    inline const nlohmann::json* agentRow(const nlohmann::json& document)
    {
        if (document.is_array())
        {
            return document.empty() ? nullptr : &document.front();
        }
        return document.is_object() ? &document : nullptr;
    }

    /**
     * @brief Read one string field from an agent row, or the empty string.
     *
     * Absent and null both yield empty, which is normal input: wazuh-db returns whatever the agent
     * last reported, and a never-connected agent reports none of it.
     */
    inline std::string agentField(const nlohmann::json& row, const char* key)
    {
        const auto found {row.find(key)};
        return found != row.end() && found->is_string() ? found->get<std::string>() : std::string {};
    }
} // namespace task_manager::host

#endif // _TASK_MANAGER_HOST_AGENT_ROW_HPP
