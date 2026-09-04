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
#include "downstream/IDownstreamClient.hpp"
#include "downstream/asioUdsHttpClient.hpp"
#include "json.hpp"
#include "loggerHelper.h"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
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

        remoted::common::LogThrottle& stoppingThrottle()
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
            bool stopping = false;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (m_stopping)
                {
                    stopping = true;
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

                if (stopping)
                {
                    // A drain is not saturation: as a full queue it would point the operator at
                    // control_tm_max_queue_size. Io is what stop()'s own drain answers.
                    if (const auto throttle = stoppingThrottle().record())
                    {
                        LOGFN_DEBUG1(logFn(),
                                     "Task client is stopping: rejected %llu request(s) in the last %d s.",
                                     throttle.total,
                                     remoted::common::LogThrottle::kDefaultWindowSeconds);
                    }
                    reject(SocketError::Io, {});
                    return;
                }

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
            /*
             * A REQUEST PER CALL, not a persistent connection.
             *
             * The task manager serves HTTP/1.1 over its socket and answers one request per
             * connection, closing it afterwards -- so the reconnect-on-failure loop this used to
             * run would have fired on every single successful poll. The client below owns its own
             * io_context and connects per request, which is what that transport actually wants.
             *
             * The queue, the worker thread and the six throttles are unchanged: what they bound is
             * this module's own concurrency and log volume, neither of which the transport change
             * affects.
             */
            remoted::downstream::DownstreamConfig clientConfig;
            clientConfig.connectTimeoutMs = kTaskConnectTimeoutMs;
            clientConfig.writeTimeoutMs = static_cast<int>(m_deadlineMs);
            clientConfig.responseTimeoutMs = static_cast<int>(m_deadlineMs);
            clientConfig.ioThreads = 1;

            auto client {std::make_unique<remoted::downstream::AsioUdsHttpClient>(clientConfig)};
            client->start();

            while (!m_stopping.load(std::memory_order_relaxed))
            {
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
                // Zero-padded to match the stored agent id format (e.g. "001").
                std::ostringstream oss;
                oss << std::setfill('0') << std::setw(3) << req.id;
                request["agent_id"] = oss.str();
                const auto requestStr {std::make_shared<const std::string>(request.dump())};

                LOGFN_DEBUG2(logFn(), "Fetching pending tasks for agent %u.", req.id);

                remoted::downstream::DownstreamRequest downstream;
                downstream.socketPath = m_taskSocketPath;
                downstream.method = remoted::http::Method::Post;
                downstream.path = kTaskPendingRoute;
                downstream.contentType = "application/json";
                downstream.body = *requestStr;
                downstream.responseTimeoutMs = static_cast<int>(m_deadlineMs);

                // The client is async; this worker is synchronous by design, because the queue is
                // what bounds concurrency. A promise per request keeps that shape without a second
                // condition variable.
                std::promise<std::pair<remoted::downstream::DownstreamError, remoted::downstream::DownstreamResponse>>
                    promise;
                auto future {promise.get_future()};

                client->sendAsync(std::move(downstream),
                                  requestStr,
                                  [&promise](remoted::downstream::DownstreamError error,
                                             remoted::downstream::DownstreamResponse response)
                                  { promise.set_value({error, std::move(response)}); });

                auto [error, response] {future.get()};

                if (error == remoted::downstream::DownstreamError::ResponseTimeout ||
                    error == remoted::downstream::DownstreamError::ConnectTimeout ||
                    error == remoted::downstream::DownstreamError::WriteTimeout)
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
                    continue;
                }

                if (error == remoted::downstream::DownstreamError::Connect)
                {
                    incTaskFetchError(m_metrics);
                    if (const auto throttle = connectFailThrottle().record())
                    {
                        LOGFN_ERROR(logFn(),
                                    "Failed to reach the task manager socket at %s: %llu failure(s) in the last %d s.",
                                    m_taskSocketPath.c_str(),
                                    throttle.total,
                                    remoted::common::LogThrottle::kDefaultWindowSeconds);
                    }
                    req.callback(SocketError::Io, {});
                    continue;
                }

                if (error != remoted::downstream::DownstreamError::None)
                {
                    incTaskFetchError(m_metrics);
                    if (const auto throttle = ioErrorThrottle().record())
                    {
                        LOGFN_WARN(logFn(),
                                   "Task manager I/O error (%s): %llu error(s) in the last %d s.",
                                   remoted::downstream::toString(error),
                                   throttle.total,
                                   remoted::common::LogThrottle::kDefaultWindowSeconds);
                    }
                    req.callback(SocketError::Io, {});
                    continue;
                }

                if (response.status < 200 || response.status > 299)
                {
                    incTaskFetchError(m_metrics);
                    if (const auto throttle = protocolErrorThrottle().record())
                    {
                        LOGFN_WARN(logFn(),
                                   "Task manager answered HTTP %d: %llu error(s) in the last %d s.",
                                   response.status,
                                   throttle.total,
                                   remoted::common::LogThrottle::kDefaultWindowSeconds);
                    }
                    req.callback(SocketError::ProtocolError, {});
                    continue;
                }

                deliverResponse(response.body, req.callback);
            }

            // Explicit rather than left to the destructor: stop() is what joins the client's own
            // io_context thread, and this worker must not return while that thread is still live.
            client->stop();
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

                // No "status" member to check: the HTTP status already carried that, and a
                // non-2xx never reaches here.

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
