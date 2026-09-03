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

#ifndef _TASK_MANAGER_HOST_C_HOST_OPS_HPP
#define _TASK_MANAGER_HOST_C_HOST_OPS_HPP

#include "iHostOps.hpp"
#include "task_manager.h"

namespace task_manager::host
{
    /**
     * @brief IHostOps over the C function-pointer table modulesd hands in at start.
     *
     * Every entry is optional. A null pointer disables the feature that needs it and is reported
     * once at start, rather than crashing a handler hours later -- a stale .so paired with a newer
     * modulesd, or the reverse, should degrade visibly instead of dying.
     *
     * The JSON-returning calls allocate with the host's allocator; this class frees them through
     * the host's own free_json and never touches them with delete.
     */
    class CHostOps final : public IHostOps
    {
    public:
        explicit CHostOps(const task_manager_host_ops_t& ops);

        int workerState() override;
        std::optional<std::vector<int>> disconnectAgents(long keepAliveBefore, const std::string& syncStatus) override;
        std::optional<std::vector<int>> agentsByStatusFrom(int afterId, const std::string& status) override;
        std::optional<nlohmann::json> agentInfo(int agentId) override;
        bool removeAgent(int agentId, int timeoutSeconds, int& authdError) override;
        bool rotateLogDaily(bool compress, int keepDays, int maxRotations) override;
        bool rotateLogBySize(bool compress, int keepDays, int maxRotations, long sizeBytes) override;

        /// @brief Names of the entries that were not supplied, for a single start-up report.
        std::vector<std::string> missingOperations() const;

    private:
        /// @brief Call a JSON-returning host op and take ownership of the result.
        std::optional<nlohmann::json> callJson(int (*fn)(int, const char*, char**), int arg, const std::string& text);

        task_manager_host_ops_t m_ops;
    };
} // namespace task_manager::host

#endif // _TASK_MANAGER_HOST_C_HOST_OPS_HPP
