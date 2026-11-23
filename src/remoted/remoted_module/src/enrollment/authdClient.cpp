/*
 * Wazuh remoted module - authd enrollment bridge client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "authdClient.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <queue>
#include <string_view>
#include <system_error>
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

        remoted::common::LogThrottle& expiredThrottle()
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

        /// The `add` wire request. Built on the WORKER thread, once the connection to authd is up
        /// (see performRequest() and deadlineFor()), not on the caller's: the deadline below is
        /// measured from that instant, so the bounded queue carries the structured request rather
        /// than bytes.
        /// @param deadlineMs Absolute instant (ms since the Unix epoch) after which the answer can
        ///                    no longer be delivered; 0 means "no deadline" and the field is omitted.
        std::string buildAddPayload(const AuthdAddRequest& request, std::int64_t deadlineMs)
        {
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
            if (request.tokenId)
            {
                arguments["token_id"] = *request.tokenId;
            }
            if (request.reenroll)
            {
                arguments["reenroll"] = {{"kid", request.reenroll->kid}, {"bearer", request.reenroll->bearer}};
            }
            if (request.source)
            {
                arguments["source"] = *request.source;
            }
            // authd on the master refuses a re-enrollment that arrives past it,
            // without rotating anything. Omitted when unknown, which authd reads as "no deadline".
            if (deadlineMs > 0)
            {
                arguments["deadline_ms"] = deadlineMs;
            }

            nlohmann::json payload;
            payload["function"] = "add";
            payload["arguments"] = std::move(arguments);
            return payload.dump();
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
             std::uint32_t workerThreads,
             std::uint32_t httpRequestTimeoutMs)
            : m_socketPath(std::move(socketPath))
            , m_connectTimeoutMs(connectTimeoutMs != 0 ? connectTimeoutMs : AuthdClient::kDefaultConnectTimeoutMs)
            , m_responseTimeoutMs(AuthdClient::resolveResponseTimeoutMs(responseTimeoutMs, isWorkerNode))
            , m_maxQueueSize(maxQueueSize != 0 ? maxQueueSize : AuthdClient::kDefaultMaxQueueSize)
            , m_httpRequestTimeoutMs(httpRequestTimeoutMs != 0 ? httpRequestTimeoutMs
                                                               : AuthdClient::kDefaultHttpRequestTimeoutMs)
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
                result.errorCode = kAuthdRequestNotSentErrorCode;
                result.message = "AuthdClient is stopping";
                pending.front().callback(std::move(result));
                pending.pop();
            }
        }

        /// The request travels UNSERIALIZED from here on: the payload is built by the worker once
        /// it is connected to authd, not by the caller's thread, because the deadline it carries is
        /// the instant the reply wait that starts there gives up. Queue wait and connect time
        /// therefore do not eat into the reply budget; they do eat into the request's HTTP budget,
        /// and a request that has spent all of it before it can be sent is answered
        /// kAuthdRequestNotSentErrorCode without reaching authd (see performRequest()).
        void enqueue(AuthdAddRequest request, std::function<void(AuthdResult)> callback)
        {
            std::function<void(AuthdResult)> reject;
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
                    // Counted here and only here: shutdown rejections share the branch below but
                    // are NOT saturation, and conflating them would make the metric lie every
                    // time the module stops.
                    m_queueRejectedTotal.fetch_add(1, std::memory_order_relaxed);
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
                if (stopping)
                {
                    if (const auto throttle = stoppingThrottle().record())
                    {
                        LOGFN_DEBUG1(logFn(),
                                     "AuthdClient is stopping: rejected %llu request(s) %s.",
                                     throttle.total,
                                     throttle.period().c_str());
                    }
                    AuthdResult result;
                    result.errorCode = kAuthdRequestNotSentErrorCode;
                    result.message = "AuthdClient is stopping";
                    reject(std::move(result));
                    return;
                }

                if (const auto throttle = queueFullThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "AuthdClient queue full (max=%u): dropped %llu request(s) %s.",
                               m_maxQueueSize,
                               throttle.total,
                               throttle.period().c_str());
                }
                AuthdResult result;
                result.errorCode = kAuthdRequestNotSentErrorCode;
                result.message = "Enrollment request queue is full";
                reject(std::move(result));
            }
        }

    private:
        struct Request
        {
            AuthdAddRequest request; ///< Serialized by the worker, not by the caller (see enqueue()).
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

                // This runs on a bare std::thread (m_workers), not on the HTTP transport's own
                // worker pool -- RestinioHttpServer's own try/catch around a route handler's
                // SYNCHRONOUS call (see its comment about asio::thread_pool terminating on any
                // escaping exception) does NOT cover this: addAgent() already returned by the
                // time this runs, later, on a different thread entirely. An uncaught exception
                // here -- from performRequest() itself, or from req.callback() (e.g.
                // mapAuthdResult()'s JSON building, or IHttpResponder::send() racing an
                // already-torn-down connection) -- would escape this thread's entry function and
                // std::terminate the entire remoted daemon, taking down every other agent's
                // connection along with the one enrollment request that triggered it.
                try
                {
                    req.callback(performRequest(req.request));
                }
                catch (const std::exception& e)
                {
                    LOGFN_ERROR(logFn(), "AuthdClient worker thread caught an exception: %s", e.what());
                }
                catch (...)
                {
                    LOGFN_ERROR(logFn(), "AuthdClient worker thread caught a non-standard exception.");
                }
            }
        }

        /// The instant after which THIS client stops waiting for authd's answer, as an absolute
        /// wall-clock epoch in milliseconds -- what authd compares against its own clock to refuse
        /// an enrollment nobody is waiting for any more.
        ///
        /// Called once the connection to authd is up, with that instant as `connectedMs`, and not
        /// when the request was dequeued: the connect budget is either already spent or not spent
        /// at all by then, and only the reply wait is left. Adding the connect budget would let
        /// authd apply a request for up to that long after this client gave up -- the failure the
        /// deadline exists to prevent. performRequest() sets the receive timeout to exactly the
        /// time between `connectedMs` and the value returned here, so the two cannot disagree.
        ///
        /// Capped by the request's own HTTP budget: remoted only WARNS at start-up when authd's
        /// budget exceeds http_request_timeout, so that cap is the only hard bound there is.
        /// Returns 0 ("no deadline", the behaviour that predates this) when the arrival instant is
        /// unknown, which keeps every path that does not set it working exactly as before.
        std::int64_t deadlineFor(const AuthdAddRequest& request, std::int64_t connectedMs) const
        {
            if (!request.arrivalMs)
            {
                return 0;
            }

            const std::int64_t replyBudget = connectedMs + m_responseTimeoutMs;
            const std::int64_t httpBudget = *request.arrivalMs + m_httpRequestTimeoutMs;
            return std::min(replyBudget, httpBudget);
        }

        static std::int64_t epochMs()
        {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                .count();
        }

        AuthdResult performRequest(const AuthdAddRequest& request)
        {
            using SocketType = Socket<OSPrimitives, SizeHeaderProtocol>;

            AuthdResult result;
            result.errorCode = kAuthdRequestNotSentErrorCode;

            // Deliberately the bare Socket, not shared_modules/utils's SocketClient: SocketClient's
            // connect() only starts a background thread that connects asynchronously and returns
            // immediately, with no hook to learn when (or whether) it actually succeeded. An
            // earlier version of this method called SocketClient::connect() and then send() on the
            // very next line with no synchronization between them -- almost always losing the race
            // against that background thread, which queued the request until a later, unrelated
            // event flushed it (or didn't). Since this method already runs on this class's own
            // dedicated worker thread (never an I/O thread), a deterministic, bounded connect is
            // both simpler and correct: it returns only once truly connected, or throws on a real
            // failure or timeout -- no race, no background thread, no epoll needed.
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
                //
                // SOCK_NONBLOCK so a saturated authd accept() backlog can't block this worker
                // thread indefinitely (the one scenario a plain blocking connect() can't bound):
                // Socket::connect() already tolerates EINPROGRESS/EAGAIN and returns immediately in
                // that case instead of throwing.
                socket.connect(UnixAddress::builder().address(m_socketPath).build().data(),
                               SOCK_STREAM | SOCK_NONBLOCK);

                // Wait for the connect to complete (or fail) within m_connectTimeoutMs. For a
                // Unix-domain socket this resolves near-instantly in practice -- this bound only
                // matters when authd's own accept() backlog is full.
                struct pollfd pfd {socket.fileDescriptor(), POLLOUT, 0};
                const int ready = ::poll(&pfd, 1, static_cast<int>(m_connectTimeoutMs));
                if (ready == 0)
                {
                    throw std::system_error(ETIMEDOUT, std::generic_category(), "Timed out connecting to authd");
                }
                if (ready < 0)
                {
                    throw std::system_error(errno, std::generic_category(), "poll() failed while connecting to authd");
                }

                // AF_UNIX quirk verified against the real kernel behavior: when the peer's listen()
                // backlog is full, a non-blocking connect() fails synchronously with EAGAIN -- there
                // is no async "still connecting" state the way there is for TCP, so poll() comes
                // back ready almost immediately with POLLHUP set, and SO_ERROR below misleadingly
                // reports 0 ("success") even though the socket was never actually connected (a
                // subsequent send()/read() would fail with ENOTCONN). POLLHUP/POLLERR must be
                // checked directly -- SO_ERROR alone cannot distinguish this from a real success.
                if (pfd.revents & (POLLHUP | POLLERR))
                {
                    throw std::system_error(
                        EAGAIN, std::generic_category(), "authd's accept backlog is full (connect rejected)");
                }

                int connectErr = 0;
                socklen_t connectErrLen = sizeof(connectErr);
                if (::getsockopt(socket.fileDescriptor(), SOL_SOCKET, SO_ERROR, &connectErr, &connectErrLen) < 0)
                {
                    throw std::system_error(errno, std::generic_category(), "getsockopt(SO_ERROR) failed");
                }
                if (connectErr != 0)
                {
                    throw std::system_error(connectErr, std::generic_category(), "Error connecting to socket");
                }

                // Back to blocking mode: SO_RCVTIMEO/SO_SNDTIMEO (set below) only bound a blocking
                // call -- on a non-blocking fd, send()/read() would instead fail immediately with
                // EAGAIN rather than waiting up to m_responseTimeoutMs.
                const int flags = ::fcntl(socket.fileDescriptor(), F_GETFL, 0);
                if (flags < 0 || ::fcntl(socket.fileDescriptor(), F_SETFL, flags & ~O_NONBLOCK) < 0)
                {
                    throw std::system_error(
                        errno, std::generic_category(), "Could not restore blocking mode on authd socket");
                }

                LOGFN_DEBUG2(logFn(), "Connected to authd socket at %s.", m_socketPath.c_str());
            }
            catch (const std::exception& e)
            {
                result.message = std::string("Could not connect to authd: ") + e.what();
                if (const auto throttle = connectFailThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "Failed to connect to authd socket at %s: %llu failure(s) %s.",
                               m_socketPath.c_str(),
                               throttle.total,
                               throttle.period().c_str());
                }
                return result;
            }

            // The deadline is stamped here, with the connection up, from the budget that is
            // actually left; the reply wait below is bounded by that same budget, so the instant
            // authd is told is the instant this client stops waiting.
            const std::int64_t connectedMs = epochMs();
            std::int64_t deadlineMs = 0;
            std::string requestStr;
            try
            {
                deadlineMs = deadlineFor(request, connectedMs);
                requestStr = buildAddPayload(request, deadlineMs);
            }
            catch (const std::exception& e)
            {
                // Answered explicitly rather than thrown: the worker loop's catch would only log
                // it, leaving this request's responder unanswered and the agent waiting out its
                // whole HTTP budget. Nothing was sent, so authd cannot have acted on it.
                LOGFN_ERROR(logFn(), "AuthdClient could not serialize an enrollment request: %s", e.what());
                result.message = "Enrollment request could not be serialized";
                return result;
            }

            // A request whose HTTP budget ran out in the queue or the connect is not sent: nobody is
            // waiting for its answer, and authd would still pay for it -- a re-enrollment reserves
            // the agent and queries wazuh-db before it reaches its own deadline check -- while this
            // worker, giving up at once, moves on to the next one. Not sending it is also the only
            // way its outcome stays known (-1, nothing was done) instead of unknown (-2). `<=`, not
            // `<`: at the deadline itself there is no time left to wait, while authd, which refuses
            // only past it, could still apply the request.
            if (deadlineMs > 0 && deadlineMs <= connectedMs)
            {
                result.message = "Enrollment request expired before it could be sent to authd";
                if (const auto throttle = expiredThrottle().record())
                {
                    // WARN, like the timeouts: authd is answering more slowly than requests arrive.
                    LOGFN_WARN(logFn(),
                               "%llu enrollment request(s) not sent to authd %s: their HTTP budget ran out "
                               "before an authd worker reached them. Is authd keeping up?",
                               throttle.total,
                               throttle.period().c_str());
                }
                return result;
            }

            // Without a deadline the wait is the full response budget, as before deadlines existed.
            // With one, it is what is left of it, which the check above leaves at 1 ms or more; the
            // max() only keeps a zero timeval ("wait forever") impossible should that check change.
            const std::int64_t waitMs =
                deadlineMs > 0 ? std::max<std::int64_t>(1, deadlineMs - connectedMs) : m_responseTimeoutMs;

            // Bounds both the send and the reply wait. Socket/OSPrimitives don't expose
            // setsockopt() publicly (it's used internally for the send/receive buffer sizes only),
            // so this is set directly on the raw fd via the standard POSIX call.
            const struct timeval timeout {static_cast<time_t>(waitMs / 1000),
                                          static_cast<suseconds_t>((waitMs % 1000) * 1000)};
            ::setsockopt(socket.fileDescriptor(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            ::setsockopt(socket.fileDescriptor(), SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

            try
            {
                socket.send(requestStr.data(), requestStr.size());
            }
            catch (const std::exception& e)
            {
                // Socket::send() only throws before completing the frame (see its while loop),
                // and authd can't act on a frame it never fully received.
                result.message = std::string("I/O error talking to authd: ") + e.what();
                if (const auto throttle = ioErrorThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "authd socket I/O error: %llu error(s) %s.",
                               throttle.total,
                               throttle.period().c_str());
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
                    // The send already completed: authd may have acted on it.
                    result.errorCode = kAuthdOutcomeUnknownErrorCode;
                    result.message = std::string("I/O error talking to authd: ") + e.what();
                    if (const auto throttle = ioErrorThrottle().record())
                    {
                        LOGFN_WARN(logFn(),
                                   "authd socket I/O error: %llu error(s) %s.",
                                   throttle.total,
                                   throttle.period().c_str());
                    }
                    return result;
                }
                // else: the reply was already captured above; this is just authd closing the
                // connection right afterward, surfacing as EOF on the next (never-coming) frame.
            }

            if (!responseReceived)
            {
                // The send completed, so authd may have processed it before this timeout.
                result.errorCode = kAuthdOutcomeUnknownErrorCode;
                result.message = "Timed out waiting for authd's reply";
                if (const auto throttle = timeoutThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "authd response timeout (deadline=%u ms): %llu timeout(s) %s.",
                               m_responseTimeoutMs,
                               throttle.total,
                               throttle.period().c_str());
                }
                return result;
            }

            return parseResponse(response);
        }

        AuthdResult parseResponse(const std::string& response)
        {
            // Only reached once a response was received: never "not sent" past this point.
            AuthdResult result;
            result.errorCode = kAuthdOutcomeUnknownErrorCode;

            try
            {
                const auto json = nlohmann::json::parse(response);
                // Default matches this function's own invariant: a well-formed reply missing
                // "error" is still an answer, not a send failure.
                const int errorCode = json.value("error", kAuthdOutcomeUnknownErrorCode);

                if (errorCode == 0)
                {
                    const auto& data = json.at("data");
                    result.errorCode = 0;
                    result.id = data.value("id", "");
                    result.name = data.value("name", "");
                    result.ip = data.value("ip", "");
                    result.key = data.value("key", "");
                    result.reenrollSecret = data.value("reenroll_secret", "");
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
                result.errorCode = kAuthdOutcomeUnknownErrorCode;
                result.message = std::string("Malformed response from authd: ") + e.what();
                if (const auto throttle = protocolErrorThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "authd returned an unparseable response: %llu error(s) %s.",
                               throttle.total,
                               throttle.period().c_str());
                }
            }

            return result;
        }

        std::string m_socketPath;
        std::uint32_t m_connectTimeoutMs;
        std::uint32_t m_responseTimeoutMs;
        std::uint32_t m_maxQueueSize;
        std::uint32_t m_httpRequestTimeoutMs;

        std::vector<std::thread> m_workers;
        std::queue<Request> m_queue;
        mutable std::mutex m_mutex;
        std::condition_variable m_cv;
        bool m_stopping {false};
        std::atomic<std::uint64_t> m_queueRejectedTotal {0}; ///< Refused because the queue was full.

    public:
        AuthdClient::QueueDiagnostics queueDiagnostics() const
        {
            AuthdClient::QueueDiagnostics d;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                d.depth = m_queue.size();
            }
            d.capacity = m_maxQueueSize;
            d.rejectedTotal = m_queueRejectedTotal.load(std::memory_order_relaxed);
            return d;
        }
    };

    AuthdClient::AuthdClient(std::string socketPath,
                             bool isWorkerNode,
                             std::uint32_t connectTimeoutMs,
                             std::uint32_t responseTimeoutMs,
                             std::uint32_t maxQueueSize,
                             std::uint32_t workerThreads,
                             std::uint32_t httpRequestTimeoutMs)
        : m_impl(std::make_unique<Impl>(std::move(socketPath),
                                        isWorkerNode,
                                        connectTimeoutMs,
                                        responseTimeoutMs,
                                        maxQueueSize,
                                        workerThreads,
                                        httpRequestTimeoutMs))
    {
    }

    AuthdClient::~AuthdClient() = default;

    void AuthdClient::addAgent(AuthdAddRequest request, std::function<void(AuthdResult)> callback)
    {
        m_impl->enqueue(std::move(request), std::move(callback));
    }

    std::uint32_t AuthdClient::resolveResponseTimeoutMs(std::uint32_t configuredMs, bool isWorkerNode) noexcept
    {
        if (configuredMs != 0)
        {
            return configuredMs;
        }
        return isWorkerNode ? kWorkerDefaultResponseTimeoutMs : kMasterDefaultResponseTimeoutMs;
    }

    AuthdClient::QueueDiagnostics AuthdClient::queueDiagnostics() const
    {
        return m_impl->queueDiagnostics();
    }

    void AuthdClient::stop()
    {
        m_impl->stop();
    }

} // namespace remoted::enrollment
