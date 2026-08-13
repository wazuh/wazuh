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
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
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
    } // namespace
    class WazuhDBClient::Impl
    {
    public:
        Impl(const std::string& wdbSocketPath,
             uint32_t poolSize,
             uint32_t deadlineMs,
             uint32_t maxQueueSize,
             ControlMetrics& metrics)
            : m_wdbSocketPath(wdbSocketPath)
            , m_poolSize(poolSize)
            , m_deadlineMs(deadlineMs)
            , m_maxQueueSize(maxQueueSize == 0 ? kWdbMaxQueueSize : maxQueueSize)
            , m_metrics(metrics)
        {
            for (uint32_t i = 0; i < poolSize; ++i)
            {
                m_workers.emplace_back([this, i]() { workerLoop(); });
            }
        }

        ~Impl()
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_stopping = true;
            }
            m_cv.notify_all();
            for (auto& worker : m_workers)
            {
                if (worker.joinable())
                {
                    worker.join();
                }
            }

            // Fail any callbacks left in the queue instead of silently dropping
            // them. Callbacks capture upstream state; leaking them means the
            // upstream code will never learn the request completed.
            std::queue<Request> pending;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                std::swap(pending, m_queue);
            }
            while (!pending.empty())
            {
                pending.front().callback(SocketError::Io, "");
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
                    m_queue.push({command, std::move(callback)});
                    m_cv.notify_one();
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
        };

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

                response.clear();
                responseReady = false;

                try
                {
                    LOGFN_DEBUG2(logFn(), "Sending WazuhDB command: %s", req.command.c_str());
                    client->send(req.command.data(), req.command.size());

                    std::unique_lock<std::mutex> respLock(responseMutex);
                    if (responseCv.wait_for(
                            respLock, std::chrono::milliseconds(m_deadlineMs), [&]() { return responseReady; }))
                    {
                        LOGFN_DEBUG2(logFn(), "Received WazuhDB response.");
                        req.callback(SocketError::None, response);
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
        uint32_t m_maxQueueSize;
        ControlMetrics& m_metrics;

        std::vector<std::thread> m_workers;
        std::queue<Request> m_queue;
        std::mutex m_mutex;
        std::condition_variable m_cv;
        std::atomic<bool> m_stopping {false};
    };

    WazuhDBClient::WazuhDBClient(const std::string& wdbSocketPath,
                                 uint32_t poolSize,
                                 uint32_t deadlineMs,
                                 uint32_t maxQueueSize,
                                 ControlMetrics& metrics)
        : m_impl(std::make_unique<Impl>(wdbSocketPath, poolSize, deadlineMs, maxQueueSize, metrics))
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
        query(command, [callback = std::move(callback)](SocketError err, const std::string&) { callback(err); });
    }

    void WazuhDBClient::getAgentGroups(AgentId id, std::function<void(SocketError, std::vector<std::string>)> callback)
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
                      callback(SocketError::ProtocolError, {});
                      return;
                  }

                  std::string payload = getPayload(response);
                  if (payload.empty())
                  {
                      callback(SocketError::None, {});
                      return;
                  }

                  try
                  {
                      auto json = nlohmann::json::parse(payload);
                      std::string groupsCsv;

                      // Wazuh-DB returns an array: [{"group":"grp1,grp2"}]
                      if (json.is_array() && !json.empty() && json[0].is_object())
                      {
                          groupsCsv = json[0].value("group", "");
                      }

                      std::vector<std::string> groups;
                      if (!groupsCsv.empty())
                      {
                          std::istringstream iss(groupsCsv);
                          std::string group;
                          while (std::getline(iss, group, ','))
                          {
                              if (!group.empty())
                              {
                                  groups.push_back(group);
                              }
                          }
                      }

                      callback(SocketError::None, groups);
                  }
                  catch (...)
                  {
                      callback(SocketError::ProtocolError, {});
                  }
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
                                         const std::string& syncStatus,
                                         std::function<void(SocketError)> callback)
    {
        nlohmann::json params;
        params["id"] = id;
        params["status_code"] = static_cast<int>(statusCode);
        params["version"] = version;
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
