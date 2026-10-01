/*
 * Wazuh remoted module - WazuhDB client
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuhDBClient.hpp"
#include "common/logThrottle.hpp"
#include "controlConfig.hpp"
#include "epollWrapper.hpp"
#include "loggerHelper.h"
#include "socketClient.hpp"
#include "socketWrapper.hpp"
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace remoted::control
{
    namespace
    {
        constexpr auto WDB_CLIENT_LOGTAG {"wazuh-manager-remoted:wdb-client"};

        const LogFn& logFn()
        {
            static const LogFn instance {WDB_CLIENT_LOGTAG};
            return instance;
        }

        // Throttles for recurring errors
        remoted::common::LogThrottle& queueFullThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        remoted::common::LogThrottle& connectFailThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        remoted::common::LogThrottle& timeoutThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        remoted::common::LogThrottle& ioErrorThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        remoted::common::LogThrottle& nonOkResponseThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        remoted::common::LogThrottle& parseErrorThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        remoted::common::LogThrottle& expiredThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        // `global select-agent-group` answers a JSON array: [] when the local replica has no row for
        // the agent, [{"group":"a,b"}] otherwise, where a row with no groups carries "" or null.
        // Anything else is malformed and yields nullopt, which the caller reports as ProtocolError:
        // a reply that cannot be read must not become an empty membership, because /control turns
        // an empty membership into "default".
        std::optional<AgentGroupsResult> parseAgentGroups(const std::string& payload)
        {
            if (payload.empty())
            {
                return std::nullopt;
            }

            const auto json = nlohmann::json::parse(payload, nullptr, false);
            if (json.is_discarded() || !json.is_array())
            {
                return std::nullopt;
            }

            AgentGroupsResult result;
            if (json.empty())
            {
                result.noRow = true;
                return result;
            }

            const auto& row = json.front();
            if (!row.is_object())
            {
                return std::nullopt;
            }

            const auto group = row.find("group");
            if (group == row.end() || group->is_null())
            {
                return result;
            }
            if (!group->is_string())
            {
                return std::nullopt;
            }

            std::istringstream iss(group->get<std::string>());
            std::string name;
            while (std::getline(iss, name, ','))
            {
                if (!name.empty())
                {
                    result.groups.push_back(name);
                }
            }
            return result;
        }
    } // namespace
    class WazuhDBClient::Impl
    {
    public:
        Impl(const std::string& wdbSocketPath,
             uint32_t poolSize,
             uint32_t deadlineMs,
             uint32_t maxQueueSize,
             ControlMetrics& metrics,
             uint32_t requestDeadlineMs)
            : m_wdbSocketPath(wdbSocketPath)
            , m_poolSize(poolSize)
            , m_deadlineMs(deadlineMs)
            , m_requestDeadline(requestDeadlineMs == 0 ? kWdbRequestDeadlineMs : requestDeadlineMs)
            , m_maxQueueSize(maxQueueSize == 0 ? kWdbMaxQueueSize : maxQueueSize)
            , m_metrics(metrics)
        {
            for (uint32_t i = 0; i < poolSize; ++i)
            {
                m_workers.emplace_back([this, i]() { workerLoop(); });
            }
            m_reaper = std::thread([this]() { reaperLoop(); });
        }

        ~Impl()
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_stopping = true;
            }
            m_cv.notify_all();
            m_reaperCv.notify_all();
            for (auto& worker : m_workers)
            {
                if (worker.joinable())
                {
                    worker.join();
                }
            }
            if (m_reaper.joinable())
            {
                m_reaper.join();
            }

            // Fail any callbacks left in the queue instead of silently dropping
            // them. Callbacks capture upstream state; leaking them means the
            // upstream code will never learn the request completed. Stopping, not
            // Io: a clean shutdown drain is not a transport failure (same contract
            // as the task client's drain). Workers and reaper are joined, so the
            // drain is the only owner left and each request is still answered once.
            std::queue<Request> pending;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                std::swap(pending, m_queue);
            }
            while (!pending.empty())
            {
                pending.front().callback(SocketError::Stopping, "");
                pending.pop();
            }
        }

        void query(const std::string& command, std::function<void(SocketError, const std::string&)> callback)
        {
            std::function<void(SocketError, const std::string&)> reject;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (m_queue.size() >= m_maxQueueSize)
                {
                    reject = std::move(callback);
                }
                else
                {
                    // One constant deadline per client and a FIFO queue: the front is always the
                    // request that expires first, which is all the reaper has to watch.
                    const bool wasEmpty = m_queue.empty();
                    m_queue.push({command, std::move(callback), std::chrono::steady_clock::now() + m_requestDeadline});
                    m_cv.notify_one();
                    if (wasEmpty)
                    {
                        m_reaperCv.notify_one();
                    }
                }
            }
            if (reject)
            {
                incWdbError(m_metrics);
                if (const auto throttle = queueFullThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "WazuhDB queue full (max=%u): dropped %llu request(s) in the last %d s.",
                               m_maxQueueSize,
                               throttle.total,
                               remoted::common::LogThrottle::kDefaultWindowSeconds);
                }
                reject(SocketError::QueueFull, "");
            }
        }

    private:
        struct Request
        {
            std::string command;
            std::function<void(SocketError, const std::string&)> callback;
            std::chrono::steady_clock::time_point deadline;
        };

        // A request that ran out of time before wazuh-db answered it. Called by whichever owner
        // took it off the queue (the reaper or a worker), outside m_mutex.
        void expire(Request& req)
        {
            incWdbError(m_metrics);
            if (const auto throttle = expiredThrottle().record())
            {
                LOGFN_WARN(logFn(),
                           "WazuhDB request expired before wazuh-db answered (deadline=%lld ms): %llu request(s) "
                           "in the last %d s.",
                           static_cast<long long>(m_requestDeadline.count()),
                           throttle.total,
                           remoted::common::LogThrottle::kDefaultWindowSeconds);
            }
            req.callback(SocketError::Timeout, "");
        }

        // Fails every queued request whose deadline has passed. While wazuh-db is down a worker still
        // dequeues -- SocketClient keeps retrying the connect on its own thread and swallows the send
        // failure -- and then holds that request for up to the round-trip deadline, so the pool
        // drains the queue one round trip at a time. Without this thread, whatever waits behind it
        // waits without bound, long past the caller's own timeout.
        void reaperLoop()
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            while (!m_stopping)
            {
                if (m_queue.empty())
                {
                    m_reaperCv.wait(lock, [this]() { return m_stopping || !m_queue.empty(); });
                    continue;
                }

                const auto now = std::chrono::steady_clock::now();
                // A copy, never a reference into the queue: wait_until() reads its time point after
                // it has released and re-taken the lock, and a worker may pop (free) the front in
                // between.
                const auto frontDeadline = m_queue.front().deadline;
                if (now < frontDeadline)
                {
                    // Woken early by stop, or by a push that found the queue empty; either way the
                    // loop re-reads the front.
                    m_reaperCv.wait_until(lock, frontDeadline);
                    continue;
                }

                std::vector<Request> expired;
                while (!m_queue.empty() && m_queue.front().deadline <= now)
                {
                    expired.push_back(std::move(m_queue.front()));
                    m_queue.pop();
                }

                lock.unlock();
                for (auto& req : expired)
                {
                    expire(req);
                }
                lock.lock();
            }
        }

        void workerLoop()
        {
            using SocketType = Socket<OSPrimitives, SizeHeaderProtocol>;
            using ClientType = SocketClient<SocketType, EpollWrapper>;

            std::unique_ptr<ClientType> client;
            std::string response;
            std::mutex responseMutex;
            std::condition_variable responseCv;
            bool responseReady = false;
            bool needsReconnect = true;

            auto connectClient = [&]() -> bool
            {
                try
                {
                    client = std::make_unique<ClientType>(m_wdbSocketPath);
                    client->connect(
                        [&](const char* body, uint32_t bodySize, const char*, uint32_t)
                        {
                            std::lock_guard<std::mutex> lock(responseMutex);
                            response.assign(body, bodySize);
                            responseReady = true;
                            responseCv.notify_one();
                        });
                    LOGFN_DEBUG2(logFn(), "Connected to WazuhDB socket at %s.", m_wdbSocketPath.c_str());
                    return true;
                }
                catch (...)
                {
                    client.reset();
                    if (const auto throttle = connectFailThrottle().record())
                    {
                        LOGFN_ERROR(logFn(),
                                    "Failed to connect to WazuhDB socket at %s: %llu failure(s) in the last %d s.",
                                    m_wdbSocketPath.c_str(),
                                    throttle.total,
                                    remoted::common::LogThrottle::kDefaultWindowSeconds);
                    }
                    return false;
                }
            };

            while (!m_stopping.load(std::memory_order_relaxed))
            {
                if (needsReconnect || !client)
                {
                    if (!connectClient())
                    {
                        // Interruptible backoff: wake immediately on stop.
                        std::unique_lock<std::mutex> lock(m_mutex);
                        m_cv.wait_for(lock, std::chrono::seconds(1), [this] { return m_stopping.load(); });
                        continue;
                    }
                    needsReconnect = false;
                }

                std::unique_lock<std::mutex> lock(m_mutex);
                m_cv.wait(lock, [this]() { return m_stopping || !m_queue.empty(); });

                if (m_stopping && m_queue.empty())
                {
                    break;
                }

                if (m_queue.empty())
                {
                    continue;
                }

                auto req = std::move(m_queue.front());
                m_queue.pop();
                lock.unlock();

                // Expired while queued: fail it here and never send it -- a late send would do work
                // for a caller that has already been answered, or give up on it.
                const auto dequeuedAt = std::chrono::steady_clock::now();
                if (dequeuedAt >= req.deadline)
                {
                    expire(req);
                    continue;
                }

                response.clear();
                responseReady = false;

                try
                {
                    LOGFN_DEBUG2(logFn(), "Sending WazuhDB command: %s", req.command.c_str());
                    const auto sentAt = std::chrono::steady_clock::now();
                    client->send(req.command.data(), req.command.size());

                    // The round-trip deadline, capped by what is left of the request's own.
                    const auto waitUntil = std::min(sentAt + std::chrono::milliseconds(m_deadlineMs), req.deadline);
                    std::unique_lock<std::mutex> respLock(responseMutex);
                    if (responseCv.wait_until(respLock, waitUntil, [&]() { return responseReady; }))
                    {
                        // Observed only on success: wdbError already counts the failures, so the
                        // histogram means "how long a HEALTHY round trip takes" -- the number that
                        // sizes 'remoted.control_wdb_roundtrip_deadline'. Worker-thread-only,
                        // dump-independent.
                        observeWdbLatency(
                            m_metrics,
                            static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                                           std::chrono::steady_clock::now() - sentAt)
                                                           .count()));
                        LOGFN_DEBUG2(logFn(), "Received WazuhDB response.");
                        req.callback(SocketError::None, response);
                    }
                    else if (waitUntil == req.deadline)
                    {
                        // The request's own budget ran out while it was in flight -- the usual end
                        // of a request queued while wazuh-db is down, since FIFO order hands each
                        // worker the next one before it expires. Same report as the reaper's, so
                        // the operator sees one line for one cause whichever thread hit it.
                        expire(req);
                        needsReconnect = true;
                    }
                    else
                    {
                        incWdbError(m_metrics);
                        if (const auto throttle = timeoutThrottle().record())
                        {
                            LOGFN_WARN(logFn(),
                                       "WazuhDB query timeout (deadline=%u ms): %llu timeout(s) in the last %d s.",
                                       m_deadlineMs,
                                       throttle.total,
                                       remoted::common::LogThrottle::kDefaultWindowSeconds);
                        }
                        req.callback(SocketError::Timeout, "");
                        needsReconnect = true;
                    }
                }
                catch (...)
                {
                    incWdbError(m_metrics);
                    if (const auto throttle = ioErrorThrottle().record())
                    {
                        LOGFN_WARN(logFn(),
                                   "WazuhDB I/O error: %llu error(s) in the last %d s.",
                                   throttle.total,
                                   remoted::common::LogThrottle::kDefaultWindowSeconds);
                    }
                    req.callback(SocketError::Io, "");
                    needsReconnect = true;
                }
            }
        }

        std::string m_wdbSocketPath;
        uint32_t m_poolSize;
        uint32_t m_deadlineMs;
        std::chrono::milliseconds m_requestDeadline;
        uint32_t m_maxQueueSize;
        ControlMetrics& m_metrics;

        std::vector<std::thread> m_workers;
        std::queue<Request> m_queue;
        std::mutex m_mutex;
        std::condition_variable m_cv;
        std::thread m_reaper;
        std::condition_variable m_reaperCv;
        std::atomic<bool> m_stopping {false};
    };

    WazuhDBClient::WazuhDBClient(const std::string& wdbSocketPath,
                                 uint32_t poolSize,
                                 uint32_t deadlineMs,
                                 uint32_t maxQueueSize,
                                 ControlMetrics& metrics,
                                 uint32_t requestDeadlineMs)
        : m_impl(std::make_unique<Impl>(wdbSocketPath, poolSize, deadlineMs, maxQueueSize, metrics, requestDeadlineMs))
    {
    }

    WazuhDBClient::~WazuhDBClient() = default;

    void WazuhDBClient::query(const std::string& command, std::function<void(SocketError, const std::string&)> callback)
    {
        m_impl->query(command, std::move(callback));
    }

    void WazuhDBClient::globalQuery(const std::string& queryName,
                                    const nlohmann::json& params,
                                    std::function<void(SocketError)> callback)
    {
        std::string command = "global " + queryName + " " + params.dump();
        query(command,
              [callback = std::move(callback)](SocketError err, const std::string& response)
              {
                  // wazuh-db reports application failures as "err ..." over a healthy socket, so
                  // the transport status alone calls every one of them a success.
                  if (err == SocketError::None && !isOk(response))
                  {
                      err = SocketError::ProtocolError;
                  }

                  callback(err);
              });
    }

    void WazuhDBClient::getAgentGroups(AgentId id, std::function<void(SocketError, AgentGroupsResult)> callback)
    {
        std::ostringstream oss;
        oss << "global select-agent-group " << id;

        query(oss.str(),
              [callback = std::move(callback)](SocketError err, const std::string& response)
              {
                  if (err != SocketError::None)
                  {
                      callback(err, {});
                      return;
                  }

                  if (!isOk(response))
                  {
                      if (const auto throttle = nonOkResponseThrottle().record())
                      {
                          LOGFN_WARN(logFn(),
                                     "WazuhDB returned a non-ok response to getAgentGroups: %llu error(s) in the "
                                     "last %d s.",
                                     throttle.total,
                                     remoted::common::LogThrottle::kDefaultWindowSeconds);
                      }
                      callback(SocketError::ProtocolError, {});
                      return;
                  }

                  auto result = parseAgentGroups(getPayload(response));
                  if (!result)
                  {
                      if (const auto throttle = parseErrorThrottle().record())
                      {
                          LOGFN_WARN(logFn(),
                                     "WazuhDB getAgentGroups: could not parse the response: %llu error(s) in the "
                                     "last %d s.",
                                     throttle.total,
                                     remoted::common::LogThrottle::kDefaultWindowSeconds);
                      }
                      callback(SocketError::ProtocolError, {});
                      return;
                  }

                  callback(SocketError::None, std::move(*result));
              });
    }

    /**
     * @brief Parse os_major and os_minor from os_version string
     * @param osVersion The OS version string (e.g., "22.04", "20.04.5", "15-SP7")
     * @param osMajor Output string for major version
     * @param osMinor Output string for minor version
     */
    static void parseOsVersion(const std::string& osVersion, std::string& osMajor, std::string& osMinor)
    {
        if (osVersion.empty())
        {
            return;
        }

        // Find the first dot or hyphen separator
        size_t dotPos = osVersion.find('.');
        size_t hyphenPos = osVersion.find('-');
        size_t sepPos = std::min(dotPos, hyphenPos);

        if (sepPos == std::string::npos || sepPos == 0)
        {
            return;
        }

        // Extract major version
        osMajor = osVersion.substr(0, sepPos);

        // Extract minor version
        if (dotPos != std::string::npos && dotPos == sepPos)
        {
            // Standard format: "22.04" or "20.04.5"
            size_t minorStart = dotPos + 1;
            size_t minorEnd = osVersion.find('.', minorStart);
            if (minorEnd == std::string::npos)
            {
                minorEnd = osVersion.length();
            }
            if (minorEnd > minorStart)
            {
                osMinor = osVersion.substr(minorStart, minorEnd - minorStart);
            }
        }
        else if (hyphenPos != std::string::npos && hyphenPos == sepPos)
        {
            // SUSE format: "15-SP7"
            size_t spPos = osVersion.find("SP", hyphenPos);
            if (spPos == std::string::npos)
            {
                spPos = osVersion.find("sp", hyphenPos);
            }
            if (spPos != std::string::npos)
            {
                size_t minorStart = spPos + 2;
                osMinor = osVersion.substr(minorStart);
            }
        }
    }

    void WazuhDBClient::updateAgentData(AgentId id,
                                        const std::string& version,
                                        const std::string& connectionStatus,
                                        const std::string& syncStatus,
                                        const HostInfo* host,
                                        std::function<void(SocketError)> callback)
    {
        nlohmann::json params;
        params["id"] = id;
        params["version"] = version;
        params["connection_status"] = connectionStatus;
        params["sync_status"] = syncStatus;

        if (host)
        {
            params["os_name"] = host->osName;
            params["os_version"] = host->osVersion;

            // Parse os_major and os_minor from os_version
            std::string osMajor, osMinor;
            parseOsVersion(host->osVersion, osMajor, osMinor);
            params["os_major"] = osMajor;
            params["os_minor"] = osMinor;

            params["os_platform"] = host->osPlatform;
            params["os_arch"] = host->architecture;
            params["agent_ip"] = host->ip;

            if (!host->osType.empty())
            {
                params["os_type"] = host->osType;
            }
        }

        globalQuery("update-agent-data", params, std::move(callback));
    }

    void WazuhDBClient::updateKeepalive(AgentId id,
                                        const std::string& connectionStatus,
                                        const std::string& syncStatus,
                                        std::function<void(SocketError)> callback)
    {
        nlohmann::json params;
        params["id"] = id;
        params["connection_status"] = connectionStatus;
        params["sync_status"] = syncStatus;

        globalQuery("update-keepalive", params, std::move(callback));
    }

    void WazuhDBClient::updateStatusCode(AgentId id,
                                         AgentStatusCode statusCode,
                                         const std::string& version,
                                         const std::string& connectionStatus,
                                         const std::string& syncStatus,
                                         std::function<void(SocketError)> callback)
    {
        nlohmann::json params;
        params["id"] = id;
        params["status_code"] = static_cast<int>(statusCode);
        params["version"] = version;
        if (!connectionStatus.empty())
        {
            params["connection_status"] = connectionStatus;
        }
        params["sync_status"] = syncStatus;

        globalQuery("update-status-code", params, std::move(callback));
    }

    void WazuhDBClient::updateConnectionStatus(AgentId id,
                                               AgentStatusCode statusCode,
                                               const std::string& connectionStatus,
                                               const std::string& syncStatus,
                                               std::function<void(SocketError)> callback)
    {
        nlohmann::json params;
        params["id"] = id;
        params["status_code"] = static_cast<int>(statusCode);
        params["connection_status"] = connectionStatus;
        params["sync_status"] = syncStatus;

        globalQuery("update-connection-status", params, std::move(callback));
    }

    bool WazuhDBClient::isOk(const std::string& response)
    {
        return response == "ok" || response.compare(0, 3, "ok ") == 0;
    }

    std::string WazuhDBClient::getPayload(const std::string& response)
    {
        return (response.size() > 3 && response.compare(0, 3, "ok ") == 0) ? response.substr(3) : std::string {};
    }

} // namespace remoted::control
