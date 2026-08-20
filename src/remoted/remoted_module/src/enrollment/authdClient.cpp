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

#include <sys/socket.h>
#include <sys/time.h>

#include <condition_variable>
#include <cstring>
#include <mutex>
#include <queue>
#include <string_view>
#include <thread>
#include <vector>

#include "common/logThrottle.hpp"
#include "json.hpp"
#include "loggerHelper.h"
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
             std::uint32_t maxQueueSize,
             std::uint32_t workerThreads)
            : m_socketPath(std::move(socketPath))
            , m_connectTimeoutMs(connectTimeoutMs != 0 ? connectTimeoutMs : AuthdClient::kDefaultConnectTimeoutMs)
            , m_responseTimeoutMs(AuthdClient::resolveResponseTimeoutMs(responseTimeoutMs, isWorkerNode))
            , m_maxQueueSize(maxQueueSize != 0 ? maxQueueSize : AuthdClient::kDefaultMaxQueueSize)
        {
            const auto poolSize = workerThreads != 0 ? workerThreads : AuthdClient::kDefaultWorkerThreads;
            m_workers.reserve(poolSize);
            for (std::uint32_t i = 0; i < poolSize; ++i)
            {
                m_workers.emplace_back([this] { workerLoop(); });
            }
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
            for (auto& worker : m_workers)
            {
                if (worker.joinable())
                {
                    worker.join();
                }
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

            // Deliberately the bare Socket, not shared_modules/utils's SocketClient: SocketClient's
            // connect() only starts a background thread that connects asynchronously and returns
            // immediately, with no hook to learn when (or whether) it actually succeeded. An
            // earlier version of this method called SocketClient::connect() and then send() on the
            // very next line with no synchronization between them -- almost always losing the race
            // against that background thread, which queued the request until a later, unrelated
            // event flushed it (or didn't). Since this method already runs on this class's own
            // dedicated worker thread (never an I/O thread), a plain BLOCKING connect() is both
            // simpler and correct: it returns only once truly connected, or throws immediately on a
            // real failure -- no race, no background thread, no epoll needed.
            SocketType socket;
            try
            {
                // Deliberately inlined into one expression, not split into a named UnixAddress
                // local first: UnixAddress::builder()/.address()/.build() build up and hand back a
                // reference into a temporary object whose SocketAddress::addr member self-points at
                // its OWN sun_path buffer. Binding that through a `const auto` copy first would
                // copy the SocketAddress struct's pointer value byte-for-byte -- still pointing at
                // the ORIGINAL (about-to-be-destroyed) temporary's buffer, not the copy's own --
                // turning connect()'s later dereference into a read of freed stack memory. Kept as
                // one expression, the temporary stays alive for its whole evaluation, including
                // this connect() call.
                socket.connect(UnixAddress::builder().address(m_socketPath).build().data(), SOCK_STREAM);
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

            // Bounds both the send and the reply wait. Socket/OSPrimitives don't expose
            // setsockopt() publicly (it's used internally for the send/receive buffer sizes only),
            // so this is set directly on the raw fd via the standard POSIX call.
            const struct timeval timeout
            {
                static_cast<time_t>(m_responseTimeoutMs / 1000),
                    static_cast<suseconds_t>((m_responseTimeoutMs % 1000) * 1000)
            };
            ::setsockopt(socket.fileDescriptor(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            ::setsockopt(socket.fileDescriptor(), SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

            try
            {
                socket.send(requestStr.data(), requestStr.size());
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

            std::string response;
            bool responseReceived = false;
            try
            {
                // One call, blocking (bounded by SO_RCVTIMEO above) between the header and body
                // reads. authd closes its end of the socket right after this one reply (see
                // run_local_server's accept loop, os_auth/src/local-server.c), so the loop inside
                // read() continuing on to look for a NEXT frame hits EOF and throws -- expected,
                // not an error, once the callback below has already fired (see the catch below).
                socket.read(
                    [&](int, const char* body, uint32_t bodySize, const char*, uint32_t)
                    {
                        response.assign(body, bodySize);
                        responseReceived = true;
                    });
            }
            catch (const std::exception& e)
            {
                if (!responseReceived)
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
                // else: the reply was already captured above; this is just authd closing the
                // connection right afterward, surfacing as EOF on the next (never-coming) frame.
            }

            if (!responseReceived)
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

        std::vector<std::thread> m_workers;
        std::queue<Request> m_queue;
        std::mutex m_mutex;
        std::condition_variable m_cv;
        bool m_stopping {false};
    };

    AuthdClient::AuthdClient(std::string socketPath,
                             bool isWorkerNode,
                             std::uint32_t connectTimeoutMs,
                             std::uint32_t responseTimeoutMs,
                             std::uint32_t maxQueueSize,
                             std::uint32_t workerThreads)
        : m_impl(std::make_unique<Impl>(
              std::move(socketPath), isWorkerNode, connectTimeoutMs, responseTimeoutMs, maxQueueSize, workerThreads))
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
