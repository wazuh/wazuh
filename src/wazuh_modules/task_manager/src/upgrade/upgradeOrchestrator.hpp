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

#ifndef _TASK_MANAGER_UPGRADE_ORCHESTRATOR_HPP
#define _TASK_MANAGER_UPGRADE_ORCHESTRATOR_HPP

#include "cache/pendingCache.hpp"
#include "deliveryGate.hpp"
#include "host/iHostOps.hpp"
#include "platform.hpp"
#include "repoLayout.hpp"
#include "requestParser.hpp"
#include "responseBuilder.hpp"
#include "storage/iTaskStore.hpp"
#include "versionsCache.hpp"
#include "wpkCache.hpp"

#include <chrono>
#include <string>
#include <vector>

namespace task_manager::upgrade
{
    /// @brief The agent-task type an upgrade produces. PERSISTED, and read by both remoted pollers.
    constexpr const char* REMOTE_UPGRADE_TASK_TYPE {"remote_upgrade"};

    /**
     * @brief Runs one upgrade request end to end.
     *
     * THE SHAPE IS THE POINT. The retired implementation was a single loop over agents that did
     * everything per agent: a wazuh-db connect/query/close, an HTTPS fetch of the `versions` file,
     * a SHA-1 of the whole WPK under a global mutex, and a task-manager POST on a fresh curl handle
     * followed by its own committed transaction. For 500 agents that is 500 of each -- minutes of
     * wall clock during which the module's one thread served nobody else.
     *
     * Here it is three phases, and only the first is per agent:
     *
     *   1. RESOLVE   per agent: read its row, apply the platform, version and delivery gates, and
     *                work out which WPK it needs. Cheap and local; the only I/O is one wazuh-db
     *                round trip on a socket that is already open.
     *   2. MATERIALISE  per DISTINCT WPK, not per agent. Agents that resolved to the same
     *                repository path share one `versions` fetch and one download. A homogeneous
     *                fleet collapses 500 to 1; a mixed one collapses to the number of platforms.
     *   3. PERSIST   every surviving agent in ONE store transaction -- one fsync, not 500.
     *
     * Concrete, not an interface: ITaskStore and IHostOps already exist as seams, and the store
     * tests in this module establish that a real in-memory SQLite beats a mock.
     *
     * One instance shared by every worker; process() holds no member state.
     */
    class UpgradeOrchestrator
    {
    public:
        struct Options
        {
            /// @brief `<task-manager><wpk_repository>`, or empty.
            std::string configuredRepository;
            /// @brief The manager's own version, e.g. "v5.0.0". From __wazuh_version, via the shim.
            std::string managerVersion;
            /// @brief Directory both delivery paths serve WPKs from. Custom files must resolve here.
            std::string upgradeDir {"var/upgrade/"};
            /// @brief Whole-batch budget. Must expire before the peer's timeout -- see UpgradeService.
            std::chrono::seconds batchDeadline {180};
            /// @brief Refuse a batch larger than this outright.
            std::size_t maxAgents {500};
            /**
             * @brief Consecutive wazuh-db failures after which the rest of the batch is abandoned.
             *
             * The host's wazuh-db socket carries a 10 s timeout, so a wedged wazuh-db would cost
             * `agents x 10 s` for one batch while holding a worker the whole time. Five strikes and
             * the remaining agents are failed immediately with the same error they would have got.
             */
            int agentInfoFailureLimit {5};
        };

        /**
         * @brief @param pendingCache MUST be the same instance the pending-tasks route reads.
         *
         * That route answers from a negative cache and never touches the database for an agent
         * recorded as having nothing pending, so writing a row without evicting that agent's entry
         * makes the task INVISIBLE -- not delayed. There is no TTL and no other eviction path, so
         * it would stay invisible until the module restarted, and then expire at task_ttl having
         * never been delivered.
         */
        UpgradeOrchestrator(host::IHostOps& hostOps,
                            storage::ITaskStore& store,
                            cache::PendingCache& pendingCache,
                            WpkCache& wpkCache,
                            VersionsCache& versionsCache,
                            Options options);

        /**
         * @brief Run a repository upgrade request.
         *
         * @param remoted  Read ONCE per batch, not per agent -- the retired code re-parsed all of
         *                 ossec.conf for every agent to obtain these two values.
         * @return One outcome per agent, in the order they were requested.
         */
        std::vector<AgentOutcome>
        process(const UpgradeRequest& request, const RemotedSettings& remoted, const StopToken& stop);

        /**
         * @brief Run a custom-WPK request.
         *
         * Materialisation is a verification rather than a download: the operator put the file in
         * place, so there is nothing to fetch and the digest is COMPUTED rather than compared.
         */
        std::vector<AgentOutcome>
        process(const UpgradeCustomRequest& request, const RemotedSettings& remoted, const StopToken& stop);

    private:
        /// @brief One agent's state as it moves through the three phases.
        struct Candidate
        {
            int agentId {0};
            UpgradeError error {UpgradeError::Success};
            /// @brief Key that decides which agents share a WPK: the resolved destination file.
            std::string wpkKey;
            std::string wpkUrl;
            std::string wpkFile;
            /// @brief The version the file name was built from, carried forward rather than parsed
            ///        back out of it -- the two would otherwise be free to drift apart.
            std::string wpkVersion;
            std::string wpkSha1;
            std::string versionsUrl;
            std::string installer;
        };

        void resolve(const UpgradeRequest& request,
                     const RemotedSettings& remoted,
                     std::vector<Candidate>& candidates,
                     const StopToken& stop);

        void materialise(std::vector<Candidate>& candidates, const StopToken& stop);
        void persist(const std::vector<Candidate>& candidates, Timestamp createTime,
                     std::vector<AgentOutcome>& outcomes);

        host::IHostOps& m_hostOps;
        storage::ITaskStore& m_store;
        cache::PendingCache& m_pendingCache;
        WpkCache& m_wpkCache;
        VersionsCache& m_versionsCache;
        Options m_options;
    };

    /**
     * @brief Resolve a caller-supplied custom WPK path against the directory agents are served from.
     *
     * FIXES A LIVE BUG, and is not the hardening it looks like. The retired code computed the SHA-1
     * over whatever absolute path the caller sent, but put only the BASENAME in the task payload --
     * and both delivery paths resolve that basename under var/upgrade/. So a file_path pointing
     * anywhere else already produced a task naming a file that is not there, or worse, a DIFFERENT
     * file that happens to share the name, whose digest will not match the one recorded. The
     * agent_upgrade CLI has always rejected such paths; only the API did not.
     *
     * Symlinks are resolved before the containment check, so a link inside var/upgrade/ pointing out
     * of it does not slip through.
     *
     * @param fileName Receives the bare file name on success.
     * @return Success, or WpkFileDoesNotExist -- which is what the caller already got, just now
     *         reported at admission instead of discovered by the agent.
     */
    UpgradeError resolveCustomWpkPath(const std::string& filePath,
                                      const std::string& upgradeDir,
                                      std::string& fileName);
} // namespace task_manager::upgrade

#endif // _TASK_MANAGER_UPGRADE_ORCHESTRATOR_HPP
