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

#include "upgradeOrchestrator.hpp"

#include "host/agentRow.hpp"
#include "model/taskId.hpp"
#include "taskManagerLog.hpp"
#include "version.hpp"
#include "versionPolicy.hpp"

#include <climits>
#include <cstdlib>
#include <json.hpp>

#include <map>
#include <utility>

namespace
{
    using namespace task_manager;
    using namespace task_manager::upgrade;

    /// @brief The agent id as the task row spells it. "%03d" is a MINIMUM width, so ids above 999
    ///        widen rather than truncate -- matching remoted's std::setw(3), which both pollers use
    ///        to look their tasks up.
    std::string formatAgentId(const int agentId)
    {
        auto text {std::to_string(agentId)};
        while (text.size() < 3)
        {
            text.insert(text.begin(), '0');
        }
        return text;
    }

    /// @brief Windows agents run a .bat; everything else a shell script.
    std::string defaultInstaller(const std::string& platform)
    {
        return platform == "windows" ? "upgrade.bat" : "upgrade.sh";
    }
} // namespace

namespace task_manager::upgrade
{
    UpgradeError resolveCustomWpkPath(const std::string& filePath, const std::string& upgradeDir, std::string& fileName)
    {
        if (filePath.empty())
        {
            return UpgradeError::WpkFileDoesNotExist;
        }

        // realpath() resolves symlinks AND requires the file to exist, which is exactly the pair of
        // properties this check needs: a link inside var/upgrade/ pointing out of it must not pass.
        char resolvedFile[PATH_MAX] {};
        char resolvedDir[PATH_MAX] {};

        if (::realpath(filePath.c_str(), resolvedFile) == nullptr ||
            ::realpath(upgradeDir.c_str(), resolvedDir) == nullptr)
        {
            return UpgradeError::WpkFileDoesNotExist;
        }

        std::string file {resolvedFile};
        std::string dir {resolvedDir};
        if (dir.empty() || dir.back() != '/')
        {
            dir += '/';
        }

        // Prefix match on the slash-terminated directory, so "/var/upgrade-evil/x.wpk" cannot pass
        // as being inside "/var/upgrade/".
        if (file.rfind(dir, 0) != 0)
        {
            return UpgradeError::WpkFileDoesNotExist;
        }

        const auto relative {file.substr(dir.size())};
        // Directly inside, not in a subdirectory: the delivery paths join a bare name to the
        // directory and would not find anything deeper.
        if (relative.empty() || relative.find('/') != std::string::npos)
        {
            return UpgradeError::WpkFileDoesNotExist;
        }

        fileName = relative;
        return UpgradeError::Success;
    }

    UpgradeOrchestrator::UpgradeOrchestrator(host::IHostOps& hostOps,
                                             storage::ITaskStore& store,
                                             cache::PendingCache& pendingCache,
                                             WpkCache& wpkCache,
                                             VersionsCache& versionsCache,
                                             Options options)
        : m_hostOps {hostOps}
        , m_store {store}
        , m_pendingCache {pendingCache}
        , m_wpkCache {wpkCache}
        , m_versionsCache {versionsCache}
        , m_options {std::move(options)}
    {
        if (!m_options.upgradeDir.empty() && m_options.upgradeDir.back() != '/')
        {
            m_options.upgradeDir += '/';
        }
    }

    void UpgradeOrchestrator::resolve(const UpgradeRequest& request,
                                      const RemotedSettings& remoted,
                                      std::vector<Candidate>& candidates,
                                      const StopToken& stop)
    {
        int consecutiveDbFailures {0};

        for (auto& candidate : candidates)
        {
            if (stop.stopRequested())
            {
                // The SAME code UpgradeService::stop() gives a batch that never started. A client
                // must not see a different answer for the same event depending on whether shutdown
                // caught its request in the queue or a millisecond into the work -- and this is the
                // one code the Server API reacts to by halving the chunk and retrying, which is
                // exactly right for "the manager is going down".
                candidate.error = UpgradeError::TaskManagerCommunication;
                continue;
            }

            if (consecutiveDbFailures >= m_options.agentInfoFailureLimit)
            {
                // Circuit broken. Reporting the same error the query would have produced keeps the
                // Server API's handling identical; what changes is that the batch no longer spends
                // ten seconds per remaining agent discovering it.
                candidate.error = UpgradeError::GlobalDbFailure;
                continue;
            }

            const auto document {m_hostOps.agentInfo(candidate.agentId)};
            const auto* row {document.has_value() ? host::agentRow(*document) : nullptr};
            if (row == nullptr)
            {
                ++consecutiveDbFailures;
                candidate.error = UpgradeError::GlobalDbFailure;
                continue;
            }
            consecutiveDbFailures = 0;

            AgentInfo agent;
            agent.agentId = candidate.agentId;
            agent.platform = host::agentField(*row, "os_platform");
            agent.majorVersion = host::agentField(*row, "os_major");
            agent.minorVersion = host::agentField(*row, "os_minor");
            agent.architecture = host::agentField(*row, "os_arch");
            agent.wazuhVersion = host::agentField(*row, "version");

            if (candidate.agentId <= 0)
            {
                candidate.error = UpgradeError::ParsingRequiredParameter;
                continue;
            }

            const auto platform {
                resolvePackageType(agent.platform, agent.majorVersion, agent.minorVersion, agent.architecture)};
            if (platform.error != UpgradeError::Success)
            {
                candidate.error = platform.error;
                continue;
            }
            agent.packageType = platform.packageType;

            const auto version {checkRepositoryUpgrade(
                agent.wazuhVersion, m_options.managerVersion, request.customVersion, request.forceUpgrade)};
            if (version.error != UpgradeError::Success)
            {
                candidate.error = version.error;
                continue;
            }

            const auto delivery {
                checkRemotedDelivery(agent.wazuhVersion, version.wpkVersion, request.forceUpgrade, remoted)};
            if (delivery.error != UpgradeError::Success)
            {
                candidate.error = delivery.error;
                continue;
            }
            if (delivery.forcedOverUnsafeVerification)
            {
                LOGFN_WARN(upgradeLogFn(),
                           "Agent %d: upgrading to '%s' while remoted's HTTPS verification_mode is not "
                           "'none'; the agent may be unable to reconnect afterward. Proceeding because "
                           "'force' was set (accepted risk).",
                           candidate.agentId,
                           version.wpkVersion.c_str());
            }

            RepoRequest repo;
            repo.wpkVersion = version.wpkVersion;
            repo.requestedRepository = request.wpkRepository;
            repo.configuredRepository = m_options.configuredRepository;
            repo.requestedPackageType = request.packageType;
            repo.useHttp = request.useHttp;
            repo.forceUpgrade = request.forceUpgrade;

            const auto layout {resolveRepoLayout(agent, repo)};
            if (layout.error != UpgradeError::Success)
            {
                candidate.error = layout.error;
                continue;
            }

            switch (layout.notice)
            {
                case PackageTypeNotice::ForcedOverride:
                    LOGFN_DEBUG1(upgradeLogFn(),
                                 "Agent %d (%s): using the requested package type '%s' over the reported one, "
                                 "because 'force' was set.",
                                 candidate.agentId,
                                 agent.platform.c_str(),
                                 layout.layout.packageType.c_str());
                    break;
                case PackageTypeNotice::MismatchIgnored:
                    LOGFN_WARN(upgradeLogFn(),
                               "Agent %d (%s): the requested package type does not match the one the agent "
                               "reports; using the agent's. Set 'force' to override.",
                               candidate.agentId,
                               agent.platform.c_str());
                    break;
                case PackageTypeNotice::DefaultedFromRequest:
                    LOGFN_DEBUG1(upgradeLogFn(),
                                 "Agent %d (%s): no package type reported; using the requested '%s'.",
                                 candidate.agentId,
                                 agent.platform.c_str(),
                                 layout.layout.packageType.c_str());
                    break;
                case PackageTypeNotice::None:
                default: break;
            }

            candidate.wpkUrl = layout.layout.pathUrl + layout.layout.fileName;
            candidate.wpkFile = layout.layout.fileName;
            candidate.wpkVersion = version.wpkVersion;
            candidate.versionsUrl = layout.layout.versionsUrl;
            // Keyed on the DESTINATION file, matching WpkCache: two repositories that publish the
            // same file name resolve to one download, and must therefore share one verdict.
            candidate.wpkKey = layout.layout.fileName;
            candidate.installer = defaultInstaller(agent.platform);
        }
    }

    void UpgradeOrchestrator::materialise(std::vector<Candidate>& candidates, const StopToken& stop)
    {
        // Grouped by WPK, so the work below happens once per distinct package rather than once per
        // agent. This is the difference between one download and five hundred.
        std::map<std::string, std::vector<Candidate*>> groups;
        for (auto& candidate : candidates)
        {
            if (candidate.error == UpgradeError::Success && !candidate.wpkKey.empty())
            {
                groups[candidate.wpkKey].push_back(&candidate);
            }
        }

        const auto deadline {std::chrono::steady_clock::now() + m_options.batchDeadline};

        for (auto& [key, members] : groups)
        {
            // Two different reasons to stop early, and they are NOT the same answer. A shutdown is
            // "try again" (error 4, which the Server API retries with a smaller chunk); an expired
            // budget means we were still waiting on the repository, which is what UrlNotFound says.
            // Either way the module's own budget fires before the peer's timeout, so the caller
            // gets a well-formed per-agent envelope rather than the transport's leak backstop.
            const bool stopping {stop.stopRequested()};
            if (stopping || std::chrono::steady_clock::now() >= deadline)
            {
                for (auto* member : members)
                {
                    member->error = stopping ? UpgradeError::TaskManagerCommunication : UpgradeError::UrlNotFound;
                }
                continue;
            }

            auto* first {members.front()};

            const auto versions {m_versionsCache.get(first->versionsUrl)};
            if (versions.error != UpgradeError::Success)
            {
                for (auto* member : members)
                {
                    member->error = versions.error;
                }
                continue;
            }

            const auto sha1 {findSha1(versions.entries, first->wpkVersion)};
            if (!sha1.has_value())
            {
                for (auto* member : members)
                {
                    member->error = UpgradeError::WpkVersionDoesNotExist;
                }
                continue;
            }

            const auto fetched {m_wpkCache.ensure({first->wpkUrl, first->wpkFile, *sha1}, stop)};
            for (auto* member : members)
            {
                member->error = fetched;
                member->wpkSha1 = *sha1;
            }
        }
    }

    void UpgradeOrchestrator::persist(const std::vector<Candidate>& candidates,
                                      const Timestamp createTime,
                                      std::vector<AgentOutcome>& outcomes)
    {
        std::vector<AgentTask> rows;
        std::vector<std::size_t> rowOwners;
        rows.reserve(candidates.size());
        rowOwners.reserve(candidates.size());

        for (std::size_t index = 0; index < candidates.size(); ++index)
        {
            const auto& candidate {candidates[index]};
            if (candidate.error != UpgradeError::Success)
            {
                continue;
            }

            const auto agentId {formatAgentId(candidate.agentId)};

            AgentTask row;
            // No source_id, matching the retired producer exactly: the id is derived from the four
            // remaining fields, and request_time is what makes every cluster node derive the SAME
            // one for the same request.
            row.taskId = taskId::forAgentTask({}, agentId, REMOTE_UPGRADE_TASK_TYPE, createTime);
            row.agentId = agentId;
            row.taskType = REMOTE_UPGRADE_TASK_TYPE;
            row.createTime = createTime;
            row.payload = nlohmann::json {{"wpk_file", candidate.wpkFile},
                                          {"wpk_sha1", candidate.wpkSha1},
                                          {"installer", candidate.installer}}
                              .dump();

            rows.push_back(std::move(row));
            rowOwners.push_back(index);
        }

        // Evicted BEFORE the write, and for every row rather than only the ones reported created.
        //
        // BEFORE, because a poll racing this write must not be answered "nothing pending" from an
        // entry this batch is about to invalidate. FOR EVERY ROW, because a duplicate id means the
        // row is already there and still pending -- the agent needs to see it either way. The API's
        // bulk create makes the same two choices.
        //
        // Getting this wrong does not merely delay a task: the pending-tasks route skips the
        // database entirely for an agent recorded as empty, and nothing else evicts that entry --
        // no TTL, no sweep. The upgrade would stay invisible until a restart and then expire.
        for (const auto& row : rows)
        {
            m_pendingCache.invalidate(row.agentId);
        }

        std::vector<bool> stored;
        if (!rows.empty())
        {
            try
            {
                // ONE transaction, one fsync -- against 500 committed transactions and 500 HTTP
                // round trips before. Every other route blocks on the store mutex for the few
                // milliseconds this takes, rather than five hundred separate times.
                stored = m_store.createAgentTasks(rows);
            }
            catch (const std::exception& exception)
            {
                LOGFN_ERROR(upgradeLogFn(), "Could not store the upgrade tasks: %s", exception.what());
            }
        }

        for (std::size_t index = 0; index < candidates.size(); ++index)
        {
            outcomes.push_back({candidates[index].agentId, candidates[index].error, {}});
        }

        for (std::size_t row = 0; row < rowOwners.size(); ++row)
        {
            // A rollback fails EVERY row, so each of them reports TaskManagerCommunication -- the
            // one code the Server API reacts to by halving the chunk and retrying, which turns a
            // store hiccup into an automatic smaller attempt instead of a dead request.
            const bool ok {row < stored.size() && stored[row]};
            if (!ok)
            {
                outcomes[rowOwners[row]].error = UpgradeError::TaskManagerCommunication;
            }
        }
    }

    std::vector<AgentOutcome>
    UpgradeOrchestrator::process(const UpgradeRequest& request, const RemotedSettings& remoted, const StopToken& stop)
    {
        std::vector<AgentOutcome> outcomes;

        if (request.agentIds.size() > m_options.maxAgents)
        {
            for (const int agentId : request.agentIds)
            {
                outcomes.push_back({agentId, UpgradeError::ParsingRequiredParameter, {}});
            }
            return outcomes;
        }

        std::vector<Candidate> candidates;
        candidates.reserve(request.agentIds.size());
        for (const int agentId : request.agentIds)
        {
            Candidate candidate;
            candidate.agentId = agentId;
            candidates.push_back(std::move(candidate));
        }

        resolve(request, remoted, candidates, stop);
        materialise(candidates, stop);
        persist(candidates, request.requestTime, outcomes);

        return outcomes;
    }

    std::vector<AgentOutcome> UpgradeOrchestrator::process(const UpgradeCustomRequest& request,
                                                           const RemotedSettings& remoted,
                                                           const StopToken& stop)
    {
        std::vector<AgentOutcome> outcomes;

        if (request.agentIds.size() > m_options.maxAgents)
        {
            for (const int agentId : request.agentIds)
            {
                outcomes.push_back({agentId, UpgradeError::ParsingRequiredParameter, {}});
            }
            return outcomes;
        }

        // Resolved and verified ONCE for the whole batch: there is exactly one file, whatever the
        // agent count, and it is already on disk.
        std::string fileName;
        auto fileError {resolveCustomWpkPath(request.filePath, m_options.upgradeDir, fileName)};
        std::string sha1;
        if (fileError == UpgradeError::Success)
        {
            fileError = m_wpkCache.verifyLocal(fileName, sha1);
        }

        std::vector<Candidate> candidates;
        candidates.reserve(request.agentIds.size());

        for (const int agentId : request.agentIds)
        {
            Candidate candidate;
            candidate.agentId = agentId;
            candidate.wpkFile = fileName;
            candidate.wpkSha1 = sha1;

            if (stop.stopRequested())
            {
                // Same reasoning as the repository path: shutting down is error 4, so the caller
                // retries rather than being told the upgrade could not start.
                candidate.error = UpgradeError::TaskManagerCommunication;
                candidates.push_back(std::move(candidate));
                continue;
            }

            const auto document {m_hostOps.agentInfo(agentId)};
            const auto* row {document.has_value() ? host::agentRow(*document) : nullptr};
            if (row == nullptr)
            {
                candidate.error = UpgradeError::GlobalDbFailure;
                candidates.push_back(std::move(candidate));
                continue;
            }

            const auto platform {host::agentField(*row, "os_platform")};
            const auto wazuhVersion {host::agentField(*row, "version")};

            const auto version {checkCustomUpgrade(wazuhVersion, request.filePath)};
            if (version.error != UpgradeError::Success)
            {
                candidate.error = version.error;
                candidates.push_back(std::move(candidate));
                continue;
            }

            // v5.0.0 unconditionally, and force=false: a custom file's NAME cannot be trusted to say
            // what it installs, so the HTTPS gate is applied as though it might be 5.x. There is no
            // 'force' parameter on this route, so the gate has no override.
            const auto delivery {checkRemotedDelivery(wazuhVersion, FIVE_X_MINIMUM_VERSION, false, remoted)};
            if (delivery.error != UpgradeError::Success)
            {
                candidate.error = delivery.error;
                candidates.push_back(std::move(candidate));
                continue;
            }

            candidate.error = fileError;
            candidate.installer = request.installer.empty() ? defaultInstaller(platform) : request.installer;
            candidates.push_back(std::move(candidate));
        }

        persist(candidates, request.requestTime, outcomes);
        return outcomes;
    }
} // namespace task_manager::upgrade
