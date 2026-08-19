/*
 * Wazuh remoted module - authd enrollment bridge client
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "authdClient.hpp"

#include <condition_variable>
#include <cstring>
#include <mutex>
#include <queue>
#include <string_view>
#include <thread>

#include "common/logThrottle.hpp"
#include "epollWrapper.hpp"
#include "json.hpp"
#include "loggerHelper.h"
#include "socketClient.hpp"
#include "socketWrapper.hpp"

namespace remoted::enrollment
{
    namespace
    {
        constexpr auto AUTHD_CLIENT_LOGTAG {"wazuh-manager-remoted:authd-client"};

        const LogFn& logFn()
        {
            static const LogFn instance {AUTHD_CLIENT_LOGTAG};
            return instance;
        }

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

        // authd's local-server.c strips a leading "ERROR: " off nothing -- that prefix is only
        // ever added by the CLUSTER-forwarded path (shared/src/agent_op.c's
        // w_parse_agent_add_response), never by local_add()'s own error responses. Strip it
        // defensively either way so the message is clean regardless of which path answered.
        std::string stripErrorPrefix(std::string message)
        {
            constexpr std::string_view kPrefix {"ERROR: "};
            if (message.rfind(kPrefix, 0) == 0)
            {
                message.erase(0, kPrefix.size());
            }
            return message;
        }
    } // namespace

    class AuthdClient::Impl
    {
    public:
        Impl(std::string socketPath,
             bool isWorkerNode,
             std::uint32_t connectTimeoutMs,
             std::uint32_t responseTimeoutMs,
             std::uint32_t maxQueueSize)
            : m_socketPath(std::move(socketPath))
            , m_connectTimeoutMs(connectTimeoutMs != 0 ? connectTimeoutMs : AuthdClient::kDefaultConnectTimeoutMs)
            , m_responseTimeoutMs(AuthdClient::resolveResponseTimeoutMs(responseTimeoutMs, isWorkerNode))
            , m_maxQueueSize(maxQueueSize != 0 ? maxQueueSize : AuthdClient::kDefaultMaxQueueSize)
        {
            m_worker = std::thread([this] { workerLoop(); });
        }

        ~Impl()
        {
            stop();
        }

        void stop()
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (m_stopping)
                {
                    return;
                }
                m_stopping = true;
            }
            m_cv.notify_all();
            if (m_worker.joinable())
            {
                m_worker.join();
            }

            std::queue<Request> pending;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                std::swap(pending, m_queue);
            }
            while (!pending.empty())
            {
                AuthdResult result;
                result.errorCode = -1;
                result.message = "AuthdClient is stopping";
                pending.front().callback(std::move(result));
                pending.pop();
            }
        }

        void addAgent(AuthdAddRequest request, std::function<void(AuthdResult)> callback)
        {
            std::function<void(AuthdResult)> reject;
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
                    m_queue.push({std::move(request), std::move(callback)});
                    m_cv.notify_one();
                }
            }
            if (reject)
            {
                if (const auto throttle = queueFullThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "AuthdClient queue full (max=%u): dropped %llu request(s) in the last %d s.",
                               m_maxQueueSize,
                               throttle.total,
                               remoted::common::LogThrottle::kDefaultWindowSeconds);
                }
                AuthdResult result;
                result.errorCode = -1;
                result.message = "Enrollment request queue is full";
                reject(std::move(result));
            }
        }

    private:
        struct Request
        {
            AuthdAddRequest request;
            std::function<void(AuthdResult)> callback;
        };

        void workerLoop()
        {
            while (true)
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_cv.wait(lock, [this]() { return m_stopping || !m_queue.empty(); });

                // Unlike TaskClient's equivalent loop, stopping here does NOT drain the rest of
                // the queue first: any request not already in flight is abandoned immediately
                // and left for stop()'s own cleanup to reject with "stopping" (see stop()). A
                // slow or hung authd could otherwise make stop() take arbitrarily long --
                // proportional to queue depth times the response timeout -- which risks
                // delaying RemotedModuleFacade's own bounded teardown sequence. Only the request
                // already popped and in flight (if any) is allowed to finish naturally.
                if (m_stopping)
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

                req.callback(performRequest(req.request));
            }
        }

        AuthdResult performRequest(const AuthdAddRequest& request)
        {
            using SocketType = Socket<OSPrimitives, SizeHeaderProtocol>;
            using ClientType = SocketClient<SocketType, EpollWrapper>;

            AuthdResult result;
            result.errorCode = -1;

            nlohmann::json arguments;
            arguments["name"] = request.name;
            arguments["ip"] = request.ip;
            if (request.groups)
            {
                arguments["groups"] = *request.groups;
            }
            if (request.keyHash)
            {
                arguments["key_hash"] = *request.keyHash;
            }

            nlohmann::json payload;
            payload["function"] = "add";
            payload["arguments"] = std::move(arguments);
            const std::string requestStr = payload.dump();

            std::string response;
            std::mutex responseMutex;
            std::condition_variable responseCv;
            bool responseReady = false;

            std::unique_ptr<ClientType> client;
            try
            {
                // Connect-per-request by construction: a fresh ClientType every call, dropped at
                // the end of this function -- there is no persistent connection to reconnect.
                client = std::make_unique<ClientType>(m_socketPath);
                client->connect(
                    [&](const char* body, uint32_t bodySize, const char*, uint32_t)
                    {
                        std::lock_guard<std::mutex> lock(responseMutex);
                        response.assign(body, bodySize);
                        responseReady = true;
                        responseCv.notify_one();
                    });
                LOGFN_DEBUG2(logFn(), "Connected to authd socket at %s.", m_socketPath.c_str());
            }
            catch (const std::exception& e)
            {
                result.message = std::string("Could not connect to authd: ") + e.what();
                if (const auto throttle = connectFailThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "Failed to connect to authd socket at %s: %llu failure(s) in the last %d s.",
                               m_socketPath.c_str(),
                               throttle.total,
                               remoted::common::LogThrottle::kDefaultWindowSeconds);
                }
                return result;
            }

            try
            {
                client->send(requestStr.data(), requestStr.size());

                std::unique_lock<std::mutex> respLock(responseMutex);
                if (!responseCv.wait_for(
                        respLock, std::chrono::milliseconds(m_responseTimeoutMs), [&]() { return responseReady; }))
                {
                    result.message = "Timed out waiting for authd's reply";
                    if (const auto throttle = timeoutThrottle().record())
                    {
                        LOGFN_WARN(logFn(),
                                   "authd response timeout (deadline=%u ms): %llu timeout(s) in the last %d s.",
                                   m_responseTimeoutMs,
                                   throttle.total,
                                   remoted::common::LogThrottle::kDefaultWindowSeconds);
                    }
                    return result;
                }
            }
            catch (const std::exception& e)
            {
                result.message = std::string("I/O error talking to authd: ") + e.what();
                if (const auto throttle = ioErrorThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "authd socket I/O error: %llu error(s) in the last %d s.",
                               throttle.total,
                               remoted::common::LogThrottle::kDefaultWindowSeconds);
                }
                return result;
            }

            return parseResponse(response);
        }

        AuthdResult parseResponse(const std::string& response)
        {
            AuthdResult result;
            result.errorCode = -1;

            try
            {
                const auto json = nlohmann::json::parse(response);
                const int errorCode = json.value("error", -1);

                if (errorCode == 0)
                {
                    const auto& data = json.at("data");
                    result.errorCode = 0;
                    result.id = data.value("id", "");
                    result.name = data.value("name", "");
                    result.ip = data.value("ip", "");
                    result.key = data.value("key", "");
                }
                else
                {
                    // A well-formed business rejection from authd (e.g. 9008 Duplicate name):
                    // surface its exact code so the endpoint can map it precisely.
                    result.errorCode = errorCode;
                    result.message = stripErrorPrefix(json.value("message", ""));
                }
            }
            catch (const std::exception& e)
            {
                result.errorCode = -1;
                result.message = std::string("Malformed response from authd: ") + e.what();
                if (const auto throttle = protocolErrorThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "authd returned an unparseable response: %llu error(s) in the last %d s.",
                               throttle.total,
                               remoted::common::LogThrottle::kDefaultWindowSeconds);
                }
            }

            return result;
        }

        std::string m_socketPath;
        // Currently unenforced -- see the constructor's doc comment in authdClient.hpp.
        [[maybe_unused]] std::uint32_t m_connectTimeoutMs;
        std::uint32_t m_responseTimeoutMs;
        std::uint32_t m_maxQueueSize;

        std::thread m_worker;
        std::queue<Request> m_queue;
        std::mutex m_mutex;
        std::condition_variable m_cv;
        bool m_stopping {false};
    };

    AuthdClient::AuthdClient(std::string socketPath,
                             bool isWorkerNode,
                             std::uint32_t connectTimeoutMs,
                             std::uint32_t responseTimeoutMs,
                             std::uint32_t maxQueueSize)
        : m_impl(std::make_unique<Impl>(
              std::move(socketPath), isWorkerNode, connectTimeoutMs, responseTimeoutMs, maxQueueSize))
    {
    }

    AuthdClient::~AuthdClient() = default;

    void AuthdClient::addAgent(AuthdAddRequest request, std::function<void(AuthdResult)> callback)
    {
        m_impl->addAgent(std::move(request), std::move(callback));
    }

    std::uint32_t AuthdClient::resolveResponseTimeoutMs(std::uint32_t configuredMs, bool isWorkerNode) noexcept
    {
        if (configuredMs != 0)
        {
            return configuredMs;
        }
        return isWorkerNode ? kWorkerDefaultResponseTimeoutMs : kMasterDefaultResponseTimeoutMs;
    }

    void AuthdClient::stop()
    {
        m_impl->stop();
    }

} // namespace remoted::enrollment
