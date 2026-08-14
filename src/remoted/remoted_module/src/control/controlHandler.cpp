/*
 * Wazuh remoted module - Control handler
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "controlHandler.hpp"
#include "common/logThrottle.hpp"
#include "common/vdClient.hpp"
#include "json.hpp"
#include "loggerHelper.h"
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <utility>

namespace remoted::control
{
    namespace
    {
        constexpr auto CONTROL_HANDLER_LOGTAG {"wazuh-manager-remoted:control-handler"};

        // Placeholder written to wdb's agent.version column instead of a rejected startup version:
        // the framework's WazuhVersion parser requires a strict MAJOR.MINOR.PATCH shape (or this
        // exact sentinel) and raises on anything else, which used to take down every agent-listing
        // API call the moment one agent ever sent a malformed version. The rejection itself (and
        // the raw string the agent sent) is still visible in the throttled warning log below.
        constexpr auto UNKNOWN_VERSION_PLACEHOLDER {"N/A"};

        // One shared LogFn instance to avoid heap allocations per log call.
        // Kept in .cpp to avoid pulling loggerHelper.h into header.
        const LogFn& logFn()
        {
            static const LogFn instance {CONTROL_HANDLER_LOGTAG};
            return instance;
        }

        // Throttles for error conditions that could flood logs
        remoted::common::LogThrottle& versionRejectionThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        remoted::common::LogThrottle& wdbErrorThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        remoted::common::LogThrottle& invalidHostInfoThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }
        // Wall-clock seconds for timestamps that must be comparable across nodes.
        uint64_t getWallSec()
        {
            return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
        }

        // Numeric-only version comparison of MAJOR.MINOR.PATCH[.EXTRA]. Everything
        // after '-'/'+' is discarded, matching the legacy behavior of
        // compare_wazuh_versions(..., ignore_stage=false).
        int compareVersions(const std::string& v1, const std::string& v2)
        {
            auto parseParts = [](const std::string& v) -> std::array<int, 4>
            {
                std::array<int, 4> parts {0, 0, 0, 0};
                // Strip leading 'v' or 'V' if present
                std::string version = v;
                if (!version.empty() && (version[0] == 'v' || version[0] == 'V'))
                {
                    version = version.substr(1);
                }

                size_t pos = version.find_first_of("+-");
                std::string numericPart = (pos != std::string::npos) ? version.substr(0, pos) : version;

                std::istringstream iss(numericPart);
                std::string token;
                int i = 0;
                while (std::getline(iss, token, '.') && i < static_cast<int>(parts.size()))
                {
                    try
                    {
                        parts[i++] = std::stoi(token);
                    }
                    catch (...)
                    {
                        break;
                    }
                }
                return parts;
            };

            auto p1 = parseParts(v1);
            auto p2 = parseParts(v2);

            for (size_t i = 0; i < p1.size(); ++i)
            {
                if (p1[i] < p2[i])
                    return -1;
                if (p1[i] > p2[i])
                    return 1;
            }
            return 0;
        }

        // Rebuild the raw group CSV wdb returned (no URL-encoding, matches wdb).
        std::string toGroupsCsv(const std::vector<std::string>& groups)
        {
            std::string out;
            for (size_t i = 0; i < groups.size(); ++i)
            {
                if (i > 0)
                    out.push_back(',');
                out.append(groups[i]);
            }
            return out;
        }
    } // namespace

    class ControlHandler::Impl
    {
    public:
        Impl(std::shared_ptr<AgentRegistry> registry,
             std::shared_ptr<WazuhDBClient> wdbClient,
             std::shared_ptr<TaskClient> taskClient,
             std::shared_ptr<HashCache> hashCache,
             std::shared_ptr<remoted::common::VdClient> vdClient,
             ControlMetrics& metrics,
             Config config)
            : m_registry(std::move(registry))
            , m_wdbClient(std::move(wdbClient))
            , m_taskClient(std::move(taskClient))
            , m_hashCache(std::move(hashCache))
            , m_vdClient(std::move(vdClient))
            , m_metrics(metrics)
            , m_config(std::move(config))
            , m_stopping(false)
        {
            startRegistryEvictionThread();
        }

        ~Impl()
        {
            // Stop the eviction thread first so it can't touch the registry
            // while destructors run.
            {
                std::lock_guard<std::mutex> lock(m_evictionMutex);
                m_stopping = true;
            }
            m_evictionCv.notify_one();
            if (m_evictionThread.joinable())
            {
                m_evictionThread.join();
            }

            // Drop the async clients while all captured dependencies
            // (m_registry, m_hashCache, m_config, m_metrics) are still alive.
            // Their destructors join workers and fail any pending callbacks,
            // so no async lambda outlives this destructor body.
            m_wdbClient.reset();
            m_taskClient.reset();
        }

        void handleStartup(AgentId id, const StartupData& data, ResponseCallback callback)
        {
            incStartup(m_metrics);

            const bool versionMalformed = !isValidVersion(data.version);
            const bool versionTooHigh =
                !versionMalformed && !m_config.allowHigherVersions &&
                compareVersions(m_config.managerVersion, data.version) < 0;

            if (versionMalformed || versionTooHigh)
            {
                // Throttle version rejections: bursts of incompatible-version agents shouldn't flood logs
                if (const auto throttle = versionRejectionThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "Agent %u rejected for invalid version '%s' (manager=%s, allow_higher=%d): %llu "
                               "rejection(s) in the last %d s.",
                               id,
                               data.version.c_str(),
                               m_config.managerVersion.c_str(),
                               m_config.allowHigherVersions,
                               throttle.total,
                               remoted::common::LogThrottle::kDefaultWindowSeconds);
                }

                const std::string syncStatus = m_config.isWorkerNode ? "syncreq_status" : "synced";
                // Only malformed versions get the sentinel: they can't be safely stored (the
                // framework's WazuhVersion parser raises on anything outside MAJOR.MINOR.PATCH
                // or this exact placeholder). A well-formed version that's merely too high for
                // this manager's policy is safe to persist as-is and worth keeping visible.
                const std::string& versionToStore = versionMalformed ? UNKNOWN_VERSION_PLACEHOLDER : data.version;
                m_wdbClient->updateStatusCode(
                    id, AgentStatusCode::InvalidVersion, versionToStore, syncStatus, [](SocketError) {});

                HttpResponse response;
                response.status = 400;
                response.body = R"({"error":"invalid_version"})";
                callback(response);
                return;
            }

            m_wdbClient->getAgentGroups(id,
                                        [this, id, version = data.version, callback = std::move(callback)](
                                            SocketError err, std::vector<std::string> groups) mutable
                                        {
                                            if (err != SocketError::None)
                                            {
                                                // Throttle wdb errors during startup to avoid flooding on outages
                                                if (const auto throttle = wdbErrorThrottle().record())
                                                {
                                                    LOGFN_ERROR(logFn(),
                                                                "Failed to get agent groups from wdb for startup: %llu "
                                                                "failure(s) in the last %d s.",
                                                                throttle.total,
                                                                remoted::common::LogThrottle::kDefaultWindowSeconds);
                                                }

                                                HttpResponse response;
                                                response.status = 500;
                                                response.body = R"({"error":"database_error"})";
                                                callback(response);
                                                return;
                                            }

                                            if (groups.empty())
                                            {
                                                groups = {"default"};
                                            }

                                            LOGFN_DEBUG1(logFn(),
                                                         "Agent %u startup: version=%s, groups=%s.",
                                                         id,
                                                         version.c_str(),
                                                         toGroupsCsv(groups).c_str());

                                            const uint64_t now = getWallSec();

                                            m_registry->update(id,
                                                               [&](std::shared_ptr<const AgentEntry> old)
                                                               {
                                                                   auto updated =
                                                                       old ? std::make_shared<AgentEntry>(*old)
                                                                           : std::make_shared<AgentEntry>();
                                                                   updated->groups = groups;
                                                                   updated->groupsRefreshedAtSec = now;
                                                                   updated->lastActivitySec = now;
                                                                   if (updated->createdAtSec == 0)
                                                                   {
                                                                       updated->createdAtSec = now;
                                                                   }
                                                                   return updated;
                                                               });

                                            const std::string syncStatus =
                                                m_config.isWorkerNode ? "syncreq_status" : "synced";
                                            m_wdbClient->updateKeepalive(id, "pending", syncStatus, [](SocketError) {});

                                            nlohmann::json response;
                                            response["limits"] = m_config.limits;
                                            response["cluster"]["name"] = m_config.clusterName;
                                            response["agent"]["groups"] = groups;

                                            HttpResponse httpResp;
                                            httpResp.status = 200;
                                            httpResp.body = response.dump();
                                            callback(httpResp);
                                        });
        }

        void handleNotify(AgentId id, const NotifyData& data, ResponseCallback callback)
        {
            incNotify(m_metrics);

            // Per design, /notify does not validate the version (only /startup does);
            // this keeps the hot path allocation-free. Host bounds are still checked
            // so we don't forward oversized strings to wdb.
            if (data.host && !isValidHostInfo(*data.host))
            {
                // Throttle invalid host info rejections
                if (const auto throttle = invalidHostInfoThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "Agent %u notify rejected for invalid host info: %llu rejection(s) in the last %d s.",
                               id,
                               throttle.total,
                               remoted::common::LogThrottle::kDefaultWindowSeconds);
                }

                HttpResponse response;
                response.status = 400;
                response.body = R"({"error":"invalid_host_info"})";
                callback(response);
                return;
            }

            auto entry = m_registry->get(id);
            const uint64_t now = getWallSec();

            const bool needsRefresh =
                !entry || (now - entry->groupsRefreshedAtSec >= m_config.groupsRefreshIntervalSec);

            if (!needsRefresh)
            {
                processNotify(id, entry, data, now, std::move(callback));
                return;
            }

            m_wdbClient->getAgentGroups(
                id,
                [this, id, entry, data, callback = std::move(callback), now](SocketError err,
                                                                             std::vector<std::string> groups) mutable
                {
                    std::vector<std::string> finalGroups;
                    uint64_t refreshTime = 0;

                    if (err == SocketError::None)
                    {
                        finalGroups = groups.empty() ? std::vector<std::string> {"default"} : std::move(groups);
                        refreshTime = now;
                    }
                    else if (entry)
                    {
                        finalGroups = entry->groups;
                        refreshTime = entry->groupsRefreshedAtSec;
                    }
                    else
                    {
                        finalGroups = {"default"};
                        refreshTime = 0;
                    }

                    auto updated = m_registry->update(id,
                                                      [&](std::shared_ptr<const AgentEntry> old)
                                                      {
                                                          auto e = old ? std::make_shared<AgentEntry>(*old)
                                                                       : std::make_shared<AgentEntry>();
                                                          e->groups = finalGroups;
                                                          e->groupsRefreshedAtSec = refreshTime;
                                                          e->lastActivitySec = now;
                                                          if (e->createdAtSec == 0)
                                                          {
                                                              e->createdAtSec = now;
                                                          }
                                                          return e;
                                                      });

                    processNotify(id, updated, data, now, std::move(callback));
                });
        }

        void handleShutdown(AgentId id, const ShutdownData&, ResponseCallback callback)
        {
            incShutdown(m_metrics);

            LOGFN_DEBUG1(logFn(), "Agent %u: shutdown received, updating registry and wdb.", id);

            const uint64_t now = getWallSec();
            m_registry->update(id,
                               [now](std::shared_ptr<const AgentEntry> old)
                               {
                                   auto updated =
                                       old ? std::make_shared<AgentEntry>(*old) : std::make_shared<AgentEntry>();
                                   updated->lastActivitySec = now;
                                   if (updated->createdAtSec == 0)
                                   {
                                       updated->createdAtSec = now;
                                   }
                                   return updated;
                               });

            // Fire-and-forget: reply 200 immediately, dispatch DB write async.
            // Under stateless LB a stray failed write here is inconsequential
            // (the agent is going down anyway; other paths reconcile status).
            {
                HttpResponse response;
                response.status = 200;
                response.body = "{}";
                callback(response);
            }

            const std::string syncStatus = m_config.isWorkerNode ? "syncreq_status" : "synced";
            m_wdbClient->updateConnectionStatus(
                id, AgentStatusCode::HcShutdownRecv, "disconnected", syncStatus, [](SocketError) {});
        }

    private:
        uint64_t getVdFeedOffset() const
        {
            return m_vdClient->getOffset();
        }

        void processNotify(AgentId id,
                           std::shared_ptr<const AgentEntry> entry,
                           const NotifyData& data,
                           uint64_t now,
                           ResponseCallback callback)
        {
            // Atomically check-and-update the throttle inside the shard's write
            // lock. Two concurrent notifies for the same agent hitting this node
            // won't both write to wdb.
            bool doWrite = false;
            bool doFullUpdate = false;
            auto refreshedEntry = m_registry->update(
                id,
                [&](std::shared_ptr<const AgentEntry> old)
                {
                    auto e = old ? std::make_shared<AgentEntry>(*old) : std::make_shared<AgentEntry>(*entry);
                    e->lastActivitySec = now;
                    if (e->createdAtSec == 0)
                    {
                        e->createdAtSec = now;
                    }

                    if (data.host)
                    {
                        // Always write host info if throttle has expired
                        if (now - e->lastKeepaliveUpdateSec >= m_config.keepaliveThrottleSec)
                        {
                            e->lastKeepaliveUpdateSec = now;
                            doWrite = true;
                            doFullUpdate = true;
                        }
                    }
                    else
                    {
                        // Only write lightweight keepalive if throttle has expired
                        if (now - e->lastKeepaliveUpdateSec >= m_config.keepaliveThrottleSec)
                        {
                            e->lastKeepaliveUpdateSec = now;
                            doWrite = true;
                            doFullUpdate = false;
                        }
                    }

                    return e;
                });

            if (doWrite)
            {
                if (doFullUpdate)
                {
                    LOGFN_DEBUG2(logFn(), "Agent %u: writing full agent data to wdb.", id);
                    const std::string syncStatus = m_config.isWorkerNode ? "syncreq" : "synced";
                    m_wdbClient->updateAgentData(
                        id, data.version, "active", syncStatus, &(*data.host), [](SocketError) {});
                }
                else
                {
                    LOGFN_DEBUG2(logFn(), "Agent %u: writing keepalive to wdb.", id);
                    const std::string syncStatus = m_config.isWorkerNode ? "syncreq_keepalive" : "synced";
                    m_wdbClient->updateKeepalive(id, "active", syncStatus, [](SocketError) {});
                }
            }

            m_taskClient->getPendingTasks(
                id,
                [this, refreshedEntry, callback = std::move(callback)](SocketError, std::vector<Task> tasks) mutable
                {
                    const std::string groupsCsv = toGroupsCsv(refreshedEntry->groups);
                    const std::string mergedPath = m_hashCache->getMergedMgPath(groupsCsv);
                    std::string configHash =
                        mergedPath.empty() ? std::string {} : m_hashCache->getConfigHash(mergedPath);
                    if (configHash.empty())
                    {
                        configHash = "0";
                    }

                    nlohmann::json response;
                    response["agent"]["groups"] = refreshedEntry->groups;
                    response["agent"]["config_hash"] = configHash;
                    response["settings_hash"] = m_hashCache->getSettingsHash();

                    nlohmann::json tasksJson = nlohmann::json::array();
                    for (const auto& task : tasks)
                    {
                        nlohmann::json taskJson;
                        taskJson["task_id"] = task.id;
                        taskJson["task_type"] = task.type;
                        taskJson["payload"] = task.payload;
                        tasksJson.push_back(std::move(taskJson));
                    }
                    response["tasks"] = std::move(tasksJson);
                    response["vd_feed_offset"] = this->getVdFeedOffset();

                    HttpResponse httpResp;
                    httpResp.status = 200;
                    httpResp.body = response.dump();
                    callback(httpResp);
                });
        }

        void startRegistryEvictionThread()
        {
            m_evictionThread = std::thread(
                [this]()
                {
                    std::unique_lock<std::mutex> lock(m_evictionMutex);
                    while (!m_stopping)
                    {
                        if (m_evictionCv.wait_for(lock,
                                                  std::chrono::seconds(kRegistryEvictionIntervalSec),
                                                  [this]() { return m_stopping.load(); }))
                        {
                            break;
                        }
                        if (!m_stopping)
                        {
                            lock.unlock();
                            m_registry->evictExpiredEntries(m_config.registryEvictionTtlSec);
                            lock.lock();
                        }
                    }
                });
        }

        std::shared_ptr<AgentRegistry> m_registry;
        std::shared_ptr<WazuhDBClient> m_wdbClient;
        std::shared_ptr<TaskClient> m_taskClient;
        std::shared_ptr<HashCache> m_hashCache;
        std::shared_ptr<remoted::common::VdClient> m_vdClient;
        ControlMetrics& m_metrics;
        Config m_config;
        std::atomic<bool> m_stopping;
        std::thread m_evictionThread;
        std::mutex m_evictionMutex;
        std::condition_variable m_evictionCv;
    };

    ControlHandler::ControlHandler(std::shared_ptr<AgentRegistry> registry,
                                   std::shared_ptr<WazuhDBClient> wdbClient,
                                   std::shared_ptr<TaskClient> taskClient,
                                   std::shared_ptr<HashCache> hashCache,
                                   std::shared_ptr<remoted::common::VdClient> vdClient,
                                   ControlMetrics& metrics,
                                   const Config& config)
        : m_impl(std::make_unique<Impl>(std::move(registry),
                                        std::move(wdbClient),
                                        std::move(taskClient),
                                        std::move(hashCache),
                                        std::move(vdClient),
                                        metrics,
                                        config))
    {
    }

    ControlHandler::~ControlHandler() = default;

    void ControlHandler::handleStartup(AgentId id, const StartupData& data, ResponseCallback callback)
    {
        m_impl->handleStartup(id, data, std::move(callback));
    }

    void ControlHandler::handleNotify(AgentId id, const NotifyData& data, ResponseCallback callback)
    {
        m_impl->handleNotify(id, data, std::move(callback));
    }

    void ControlHandler::handleShutdown(AgentId id, const ShutdownData& data, ResponseCallback callback)
    {
        m_impl->handleShutdown(id, data, std::move(callback));
    }

} // namespace remoted::control
