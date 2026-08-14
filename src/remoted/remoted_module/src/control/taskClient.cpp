/*
 * Wazuh remoted module - Task client
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "taskClient.hpp"
#include "common/logThrottle.hpp"
#include "controlConfig.hpp"
#include "epollWrapper.hpp"
#include "json.hpp"
#include "loggerHelper.h"
#include "socketClient.hpp"
#include "socketWrapper.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace remoted::control
{
    namespace
    {
        constexpr auto TASK_CLIENT_LOGTAG {"wazuh-manager-remoted:task-client"};

        const LogFn& logFn()
        {
            static const LogFn instance {TASK_CLIENT_LOGTAG};
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

        remoted::common::LogThrottle& protocolErrorThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }
    } // namespace
    class TaskClient::Impl
    {
    public:
        Impl(const std::string& taskSocketPath,
             uint32_t concurrency,
             uint32_t deadlineMs,
             uint32_t maxQueueSize,
             ControlMetrics& metrics)
            : m_taskSocketPath(taskSocketPath)
            , m_deadlineMs(deadlineMs == 0 ? kTmDeadlineMs : deadlineMs)
            , m_maxQueueSize(maxQueueSize == 0 ? kTaskMaxQueueSize : maxQueueSize)
            , m_metrics(metrics)
        {
            const uint32_t pool = concurrency == 0 ? 1 : concurrency;
            for (uint32_t i = 0; i < pool; ++i)
            {
                m_workers.emplace_back([this]() { workerLoop(); });
            }
        }

        ~Impl()
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_stopping = true;
            }
            m_cv.notify_all();
            for (auto& w : m_workers)
            {
                if (w.joinable())
                    w.join();
            }

            // Fail any callbacks still in the queue so upstream doesn't hang.
            std::queue<Request> pending;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                std::swap(pending, m_queue);
            }
            while (!pending.empty())
            {
                pending.front().callback(SocketError::Io, {});
                pending.pop();
            }
        }

        void getPendingTasks(AgentId id, std::function<void(SocketError, std::vector<Task>)> callback)
        {
            std::function<void(SocketError, std::vector<Task>)> reject;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (m_stopping)
                {
                    reject = std::move(callback);
                }
                else if (m_queue.size() >= m_maxQueueSize)
                {
                    reject = std::move(callback);
                }
                else
                {
                    m_queue.push({id, std::move(callback)});
                    m_cv.notify_one();
                }
            }
            if (reject)
            {
                incTaskFetchError(m_metrics);
                if (const auto throttle = queueFullThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "Task client queue full (max=%u): dropped %llu request(s) in the last %d s.",
                               m_maxQueueSize,
                               throttle.total,
                               remoted::common::LogThrottle::kDefaultWindowSeconds);
                }
                reject(SocketError::QueueFull, {});
            }
        }

    private:
        struct Request
        {
            AgentId id;
            std::function<void(SocketError, std::vector<Task>)> callback;
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
                    client = std::make_unique<ClientType>(m_taskSocketPath);
                    client->connect(
                        [&](const char* body, uint32_t bodySize, const char*, uint32_t)
                        {
                            std::lock_guard<std::mutex> lock(responseMutex);
                            response.assign(body, bodySize);
                            responseReady = true;
                            responseCv.notify_one();
                        });
                    LOGFN_DEBUG2(logFn(), "Connected to task manager socket at %s.", m_taskSocketPath.c_str());
                    return true;
                }
                catch (...)
                {
                    client.reset();
                    if (const auto throttle = connectFailThrottle().record())
                    {
                        LOGFN_ERROR(logFn(),
                                    "Failed to connect to task manager socket at %s: %llu failure(s) in the last %d s.",
                                    m_taskSocketPath.c_str(),
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

                nlohmann::json request;
                request["action"] = "get_pending_tasks";
                // Format agent_id with zero-padding to match database format (e.g., "001")
                std::ostringstream oss;
                oss << std::setfill('0') << std::setw(3) << req.id;
                request["agent_id"] = oss.str();
                std::string requestStr = request.dump();

                response.clear();
                responseReady = false;

                try
                {
                    LOGFN_DEBUG2(logFn(), "Fetching pending tasks for agent %u.", req.id);
                    client->send(requestStr.data(), requestStr.size());

                    std::unique_lock<std::mutex> respLock(responseMutex);
                    if (!responseCv.wait_for(
                            respLock, std::chrono::milliseconds(m_deadlineMs), [&]() { return responseReady; }))
                    {
                        incTaskFetchError(m_metrics);
                        if (const auto throttle = timeoutThrottle().record())
                        {
                            LOGFN_WARN(logFn(),
                                       "Task manager query timeout (deadline=%u ms): %llu timeout(s) in the last %d s.",
                                       m_deadlineMs,
                                       throttle.total,
                                       remoted::common::LogThrottle::kDefaultWindowSeconds);
                        }
                        req.callback(SocketError::Timeout, {});
                        needsReconnect = true;
                        continue;
                    }
                }
                catch (...)
                {
                    incTaskFetchError(m_metrics);
                    if (const auto throttle = ioErrorThrottle().record())
                    {
                        LOGFN_WARN(logFn(),
                                   "Task manager I/O error: %llu error(s) in the last %d s.",
                                   throttle.total,
                                   remoted::common::LogThrottle::kDefaultWindowSeconds);
                    }
                    req.callback(SocketError::Io, {});
                    needsReconnect = true;
                    continue;
                }

                deliverResponse(response, req.callback);
            }
        }

        void deliverResponse(const std::string& response,
                             const std::function<void(SocketError, std::vector<Task>)>& callback)
        {
            try
            {
                auto json = nlohmann::json::parse(response);

                if (json.contains("error"))
                {
                    incTaskFetchError(m_metrics);
                    if (const auto throttle = protocolErrorThrottle().record())
                    {
                        LOGFN_WARN(logFn(),
                                   "Task manager returned error response: %llu error(s) in the last %d s.",
                                   throttle.total,
                                   remoted::common::LogThrottle::kDefaultWindowSeconds);
                    }
                    callback(SocketError::ProtocolError, {});
                    return;
                }

                if (!json.contains("status") || json["status"] != "ok")
                {
                    incTaskFetchError(m_metrics);
                    if (const auto throttle = protocolErrorThrottle().record())
                    {
                        LOGFN_WARN(logFn(),
                                   "Task manager invalid status response: %llu error(s) in the last %d s.",
                                   throttle.total,
                                   remoted::common::LogThrottle::kDefaultWindowSeconds);
                    }
                    callback(SocketError::ProtocolError, {});
                    return;
                }

                std::vector<Task> tasks;
                if (json.contains("tasks") && json["tasks"].is_array())
                {
                    for (const auto& taskJson : json["tasks"])
                    {
                        Task task;
                        task.id = taskJson.value("task_id", "");
                        task.type = taskJson.value("task_type", "");
                        task.payload = taskJson.value("payload", nlohmann::json::object());
                        tasks.push_back(std::move(task));
                    }
                }

                incTaskFetch(m_metrics);
                if (!tasks.empty())
                {
                    LOGFN_DEBUG1(logFn(), "Retrieved %zu pending task(s) from task manager.", tasks.size());
                }
                callback(SocketError::None, std::move(tasks));
            }
            catch (...)
            {
                incTaskFetchError(m_metrics);
                if (const auto throttle = protocolErrorThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "Task manager JSON parse error: %llu error(s) in the last %d s.",
                               throttle.total,
                               remoted::common::LogThrottle::kDefaultWindowSeconds);
                }
                callback(SocketError::ProtocolError, {});
            }
        }

        std::string m_taskSocketPath;
        uint32_t m_deadlineMs;
        uint32_t m_maxQueueSize;
        ControlMetrics& m_metrics;
        std::vector<std::thread> m_workers;
        std::queue<Request> m_queue;
        std::mutex m_mutex;
        std::condition_variable m_cv;
        std::atomic<bool> m_stopping {false};
    };

    TaskClient::TaskClient(const std::string& taskSocketPath,
                           uint32_t concurrency,
                           uint32_t deadlineMs,
                           uint32_t maxQueueSize,
                           ControlMetrics& metrics)
        : m_impl(std::make_unique<Impl>(taskSocketPath, concurrency, deadlineMs, maxQueueSize, metrics))
    {
    }

    TaskClient::~TaskClient() = default;

    void TaskClient::getPendingTasks(AgentId id, std::function<void(SocketError, std::vector<Task>)> callback)
    {
        m_impl->getPendingTasks(id, std::move(callback));
    }

} // namespace remoted::control
