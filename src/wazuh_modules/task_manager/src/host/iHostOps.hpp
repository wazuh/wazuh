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

#ifndef _TASK_MANAGER_HOST_I_HOST_OPS_HPP
#define _TASK_MANAGER_HOST_I_HOST_OPS_HPP

#include <json.hpp>

#include <optional>
#include <string>
#include <vector>

namespace task_manager::host
{
    /// @brief authd's numeric refusals, as the retention sweep must interpret them.
    enum AuthdError
    {
        AUTHD_NO_SUCH_ID = 9010,
        AUTHD_ID_NOT_FOUND = 9011,
        AUTHD_PENDING_PURGE = 9015,
        AUTHD_DELETE_BACKLOG = 9018,
        AUTHD_WORKER_NODE = 9020
    };

    /**
     * @brief The operations that live in libwazuh, behind an interface this module can mock.
     *
     * A shared object cannot link libwazuh -- modulesd links the static one, and a second copy of
     * its globals in one process is the hazard every other C++ module here avoids -- so these
     * arrive as C function pointers and are wrapped by CHostOps. This interface exists so the
     * handlers depend on behaviour rather than on a struct of function pointers, and so their unit
     * tests can supply a fake without a running manager.
     */
    class IHostOps
    {
    public:
        virtual ~IHostOps() = default;

        /// @return 1 worker, 0 master, -1 unknown. "Unknown" must never be read as master.
        virtual int workerState() = 0;

        /// @brief Transition agents whose last keepalive predates `keepAliveBefore`.
        /// @return The affected agent ids, or nullopt when wazuh-db did not complete the sweep.
        virtual std::optional<std::vector<int>> disconnectAgents(long keepAliveBefore,
                                                                 const std::string& syncStatus) = 0;

        /// @brief Agents in a connection status, with ids strictly greater than `afterId`.
        virtual std::optional<std::vector<int>> agentsByStatusFrom(int afterId,
                                                                   const std::string& status) = 0;

        /// @brief One agent's row.
        virtual std::optional<nlohmann::json> agentInfo(int agentId) = 0;

        /// @brief Ask authd to remove an agent.
        /// @param authdError Set to authd's numeric code when it answered with a refusal.
        /// @return true when authd answered at all. A false return means it could not be reached,
        ///         which is a different thing from a refusal and is mapped differently.
        virtual bool removeAgent(int agentId, int timeoutSeconds, int& authdError) = 0;

        virtual bool rotateLogDaily(bool compress, int keepDays, int maxRotations) = 0;

        /// @return true when it actually rotated, false when the log was under the threshold.
        virtual bool rotateLogBySize(bool compress, int keepDays, int maxRotations, long sizeBytes) = 0;
    };
} // namespace task_manager::host

#endif // _TASK_MANAGER_HOST_I_HOST_OPS_HPP
