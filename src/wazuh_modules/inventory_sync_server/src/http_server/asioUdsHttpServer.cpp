/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "asioUdsHttpServer.hpp"

#include "common/logThrottle.hpp"
#include "inFlightBudget.hpp"
#include "loggerHelper.h"
#include "proc.hpp"
#include "requestParser.hpp"
#include "udsHttpServerFactory.hpp"

#include <asio.hpp>

#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <future>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace
{
    constexpr auto SERVER_LOGTAG {"wazuh-manager-modulesd:inventory-sync-server:server"};

    // File-local rather than a member: LogFn has hidden ELF visibility (loggerHelper.h wraps
    // everything in a visibility pragma), so holding one as a field of a default-visibility class
    // trips -Wattributes. Also avoids a heap allocation per log call.
    const LogFn& logFn()
    {
        static const LogFn instance {SERVER_LOGTAG};
        return instance;
    }

    using stream_protocol = asio::local::stream_protocol;

    /**
     * @brief Fixed part of the per-request memory charge: llhttp state, timer, socket, strand, the
     *        Session object and the response buffers.
     *
     * The VARIABLE part -- the header map and the read buffer -- is derived from the configured limits
     * instead, by perRequestOverhead() below.
     */
    constexpr std::size_t SESSION_FIXED_OVERHEAD {4U * 1024U};

    /**
     * @brief Bytes charged to a request on top of its declared payload.
     *
     * Derived from the limits rather than a constant: per-connection state stays resident for the
     * WHOLE deferral, so the budget has to charge for it to be an honest proxy for memory when
     * hundreds of replies are outstanding -- and the dominant term, the header map, is bounded by
     * three CONFIGURABLE limits, so a constant would drift the moment an operator raised one.
     */
    std::size_t perRequestOverhead(const invsync::http::UdsHttpServerConfig& config)
    {
        const auto headBound = config.maxHeaderCount * (config.maxHeaderNameSize + config.maxHeaderValueSize);
        return headBound + config.bufferSize + SESSION_FIXED_OVERHEAD;
    }

    /*
     * The shutdown budget, split into named pieces.
     *
     * modulesd runs every module's stop() sequentially and the init script gives the WHOLE daemon
     * 30 s before SIGKILL (init/wazuh-server.sh, MAX_KILL_TRIES), so these have to add up to
     * comfortably less than that on their own: 2 + 10 + drainTimeoutSec (2 by default) + 5 + 2 = 21 s
     * worst case.
     */

    /// Waiting for closeAcceptor() to have run on the acceptor strand. Bounded because the strand is
    /// drained by the I/O threads, and a handler that never returns would otherwise hang stop()
    /// forever -- with the facade's lifecycle mutex held, inside modulesd's signal handler.
    constexpr auto ACCEPTOR_CLOSE_TIMEOUT = std::chrono::seconds {2};

    /// Waiting for in-flight dispatches to finish and pre-handler connections to clear.
    constexpr auto DISPATCH_DRAIN_TIMEOUT = std::chrono::seconds {10};

    /// Waiting for force-closed sessions to leave the registry.
    constexpr auto FORCE_CLOSE_TIMEOUT = std::chrono::seconds {5};

    /// How long stop() waits for the I/O threads to drain naturally before forcing the issue.
    constexpr auto THREAD_EXIT_GRACE = std::chrono::seconds {2};

    const char* reasonPhrase(int status)
    {
        switch (status)
        {
            case 200: return "OK";
            case 202: return "Accepted";
            case 400: return "Bad Request";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 409: return "Conflict";
            case 411: return "Length Required";
            case 413: return "Content Too Large";
            case 414: return "URI Too Long";
            case 431: return "Request Header Fields Too Large";
            case 500: return "Internal Server Error";
            case 503: return "Service Unavailable";
            case 504: return "Gateway Timeout";
            default: return "OK";
        }
    }

    const char* methodToString(invsync::http::Method method)
    {
        switch (method)
        {
            case invsync::http::Method::Get: return "GET";
            case invsync::http::Method::Post: return "POST";
            case invsync::http::Method::Put: return "PUT";
            case invsync::http::Method::Delete: return "DELETE";
            case invsync::http::Method::Patch: return "PATCH";
        }
        return "POST";
    }

    /// IMF-fixdate, cached per whole second so a burst of responses does not re-run strftime.
    std::string httpDate()
    {
        thread_local std::time_t cachedSecond {0};
        thread_local std::string cachedValue;

        const auto now = std::time(nullptr);
        if (now != cachedSecond || cachedValue.empty())
        {
            std::tm tm {};
            ::gmtime_r(&now, &tm);
            std::array<char, 40> buffer {};
            const auto written = std::strftime(buffer.data(), buffer.size(), "%a, %d %b %Y %H:%M:%S GMT", &tm);
            cachedValue.assign(buffer.data(), written);
            cachedSecond = now;
        }
        return cachedValue;
    }

    /// The exact inverse of the peer's buildRequestHead(): Content-Length delimited, Connection: close.
    std::string serializeHead(const invsync::http::HttpResponse& response)
    {
        std::string head {"HTTP/1.1 "};
        head += std::to_string(response.status);
        head += ' ';
        head += reasonPhrase(response.status);
        head += "\r\nServer: wazuh-manager-modulesd\r\nDate: ";
        head += httpDate();
        head += "\r\nContent-Length: ";
        head += std::to_string(response.body.size());
        head += "\r\n";
        for (const auto& [name, value] : response.headers)
        {
            head += name;
            head += ": ";
            head += value;
            head += "\r\n";
        }
        head += "Connection: close\r\n\r\n";
        return head;
    }

    invsync::http::HttpResponse errorResponse(int status, const char* message)
    {
        std::string body {R"({"error":")"};
        body += message;
        body += R"(","code":)";
        body += std::to_string(status);
        body += "}";
        return invsync::http::HttpResponse::json(status, std::move(body));
    }
} // namespace

namespace invsync::http
{
    namespace
    {
        /**
         * @brief The I/O runtime, co-owned by the server, every Session AND every responder.
         *
         * This shared ownership is the mechanism behind the post-stop guarantee (S3): when the
         * server is gone but a responder is still held by some handler, the io_context object stays
         * ALLOCATED -- by then holding zero I/O objects and zero pending handlers -- so a late
         * send() finds a dead weak_ptr and returns having touched only live memory.
         */
        struct Runtime
        {
            asio::io_context ioc;
        };

        struct Route
        {
            Method method;
            std::string path;
            RouteHandler handler;
            bool countAgainstBudget;
        };

        struct ServerState;

        /**
         * @brief Payload plus its byte reservation, owned together.
         *
         * The handler receives a shared_ptr<const HttpRequest> ALIASED into this object, so dropping
         * the request releases the payload and its reservation in one step -- typically minutes
         * before the reply is sent, since the responder deliberately does not co-own it.
         */
        struct RequestContext
        {
            /*
             * Co-owns the ServerState, and MUST stay the first member so it is destroyed LAST.
             *
             * `reservation` holds a raw InFlightBudget* into ServerState::budget, and the contract
             * explicitly lets a handler keep the request "so it can travel across deferred queues" --
             * outliving the responder, and therefore able to outlive the server itself. Without this
             * reference ~Reservation would call release() on a destroyed budget. It bites even when the
             * budget is disabled: tryReserve() still hands back a Reservation whose owner is non-null.
             */
            std::shared_ptr<ServerState> state;
            HttpRequest request;
            InFlightBudget::Reservation reservation;
        };

        class Session;

        /**
         * @brief State shared between the server and its Sessions.
         *
         * Held by shared_ptr rather than reached through a back-pointer to the server so that no
         * Session can ever observe a half-destroyed server, whatever the teardown order turns out
         * to be.
         */
        struct ServerState
        {
            UdsHttpServerConfig config;
            std::vector<Route> routes;
            std::unique_ptr<InFlightBudget> budget;

            std::mutex registryMutex;
            std::map<std::uint64_t, std::shared_ptr<Session>> sessions;
            std::uint64_t nextSessionId {1};

            /// Counters that make the shutdown guarantees checkable rather than hoped for.
            std::atomic<std::size_t> liveSessions {0};
            std::atomic<std::size_t> undispatched {0};
            std::atomic<std::size_t> dispatchesRunning {0};

            std::mutex progressMutex;
            std::condition_variable progressCv;

            /// Separate per condition: a storm of one kind must not suppress another kind's first line.
            common::LogThrottle budgetThrottle;
            common::LogThrottle connectionCapThrottle;
            common::LogThrottle malformedThrottle;
            common::LogThrottle abandonedThrottle;
            common::LogThrottle responseTimeoutThrottle;
            common::LogThrottle acceptErrorThrottle;
            common::LogThrottle handlerThrewThrottle;
            common::LogThrottle sessionBringupThrottle;
            common::LogThrottle limitRejectThrottle;
            common::LogThrottle noRouteThrottle;
            common::LogThrottle writeErrorThrottle;
            common::LogThrottle phaseTimeoutThrottle;
            common::LogThrottle peerGoneThrottle;

            /// Connections answered 503 because stopAccepting() found them pre-handler; reported in
            /// the shutdown INFO so the third source of 503 (besides budget and cap) is accounted for.
            std::atomic<std::size_t> shutdownRejected {0};

            std::atomic_bool accepting {false};

            /// Resolved once in start() from the configured limits; see perRequestOverhead().
            std::size_t perRequestOverhead {0};

            void noteProgress()
            {
                {
                    std::lock_guard<std::mutex> lock {progressMutex};
                }
                progressCv.notify_all();
            }
        };

        /**
         * @brief One accepted connection. Kept alive by the shared_ptr captured in every async
         *        handler plus the registry entry.
         *
         * Every handler runs on m_strand, so the members need no locking -- but that is only true
         * because each completion handler is explicitly bound to it with asio::bind_executor().
         * An accepted socket inherits the executor of the acceptor that produced it, and this
         * server's acceptor lives on ONE shared strand, so without those binds the socket handlers
         * of every connection would run serialized on that shared strand while the timer ran on
         * m_strand: two executors touching the same members (a real race on m_finished, which is the
         * only guard against answering twice), and io_threads > 1 buying no parallelism at all
         * because all request handling is invoked from the read handler.
         *
         * If you add an async operation on m_socket, bind its handler to m_strand too.
         */
        class Session final : public std::enable_shared_from_this<Session>
        {
        public:
            Session(std::shared_ptr<Runtime> runtime,
                    std::shared_ptr<ServerState> state,
                    stream_protocol::socket socket)
                // m_runtime is declared FIRST in the member list below, so it is destroyed LAST:
                // ~socket and ~steady_timer always run while the io_context is still alive (I1).
                : m_runtime {std::move(runtime)}
                , m_state {std::move(state)}
                , m_strand {asio::make_strand(m_runtime->ioc)}
                , m_socket {std::move(socket)}
                , m_timer {m_strand}
                , m_parser {parserLimits(m_state->config)}
                , m_readBuffer(m_state->config.bufferSize, '\0')
            {
            }

            asio::strand<asio::io_context::executor_type>& strand() noexcept
            {
                return m_strand;
            }

            void setId(std::uint64_t id) noexcept
            {
                m_id = id;
            }

            void start()
            {
                armTimer(Phase::Header, std::chrono::seconds {m_state->config.headerTimeoutSec});
                doRead();
            }

            /// Answer 503 and close, for a connection that never reached a handler. Used by
            /// stopAccepting()'s phase 1.
            void rejectForShutdown()
            {
                if (m_finished || m_dispatched)
                {
                    return;
                }
                m_state->shutdownRejected.fetch_add(1, std::memory_order_relaxed);
                deliver(errorResponse(503, "Server is shutting down"));
            }

            /// Force this session closed without answering. Used by stop()'s phase 2 so the peer sees
            /// EOF promptly instead of waiting out its own response deadline.
            void forceClose()
            {
                if (m_finished)
                {
                    return;
                }
                m_finished = true;
                // Cancelling the timer is REQUIRED, not tidiness: a pending async_wait holds a
                // shared_ptr to this Session, and the Session holds the Runtime that owns the
                // io_context the wait is queued on -- a reference cycle neither side can break.
                // Cancelling runs the handler now (operation_aborted) and releases its reference.
                m_timer.cancel();
                closeSocket();
                unregisterSelf();
            }

            bool dispatched() const noexcept
            {
                return m_dispatched;
            }

            /// Called by the responder. Always marshals onto the strand, so Session members stay
            /// single-threaded no matter which thread produced the response. May run on any caller
            /// thread, so a failed post must not throw out of it: the session is then reaped by the
            /// response timer or the peer watch.
            void submitResponse(HttpResponse response)
            {
                auto self = shared_from_this();
                try
                {
                    asio::post(m_strand,
                               [self, response = std::move(response)]() mutable
                               { self->deliver(std::move(response)); });
                }
                // LCOV_EXCL_START -- only a failed handler allocation inside asio::post throws here
                catch (...)
                {
                }
                // LCOV_EXCL_STOP
            }

            /// Called when a responder is destroyed without ever having sent: a handler bug, answered
            /// 503 so the peer is never left hanging. Runs from a destructor, so it must not throw.
            void submitAbandoned()
            {
                auto self = shared_from_this();
                try
                {
                    asio::post(m_strand,
                               [self]()
                               {
                                   if (self->m_finished)
                                   {
                                       return;
                                   }
                                   if (const auto decision = self->m_state->abandonedThrottle.record())
                                   {
                                       LOGFN_WARN(logFn(),
                                                  "%llu request(s) in the last %d s were dropped by their handler "
                                                  "without a response and were answered 503. This is a handler bug.",
                                                  static_cast<unsigned long long>(decision.total),
                                                  common::LogThrottle::kDefaultWindowSeconds);
                                   }
                                   self->deliver(errorResponse(503, "Handler produced no response"));
                               });
                }
                // LCOV_EXCL_START -- only a failed handler allocation inside asio::post throws here
                catch (...)
                {
                }
                // LCOV_EXCL_STOP
            }

        private:
            class SessionResponder;

            enum class Phase
            {
                Header,
                Body,
                Response,
                Write
            };

            static RequestParser::Limits parserLimits(const UdsHttpServerConfig& config)
            {
                RequestParser::Limits limits;
                limits.maxBodySize = config.maxBodySize;
                limits.maxUrlSize = config.maxUrlSize;
                limits.maxHeaderNameSize = config.maxHeaderNameSize;
                limits.maxHeaderValueSize = config.maxHeaderValueSize;
                limits.maxHeaderCount = config.maxHeaderCount;
                return limits;
            }

            void armTimer(Phase phase, std::chrono::seconds timeout)
            {
                m_phase = phase;
                auto self = shared_from_this();
                m_timer.expires_after(timeout);
                m_timer.async_wait(
                    [self](const std::error_code& ec)
                    {
                        if (ec)
                        {
                            return; // cancelled
                        }
                        self->onTimeout();
                    });
            }

            void onTimeout()
            {
                if (m_finished)
                {
                    return;
                }

                if (m_phase == Phase::Response)
                {
                    // Synthesize a status rather than just dropping the connection: the peer gets a
                    // 504 it can classify instead of a bare reset. This is the leak backstop for a
                    // handler that kept a responder and never used it.
                    if (const auto decision = m_state->responseTimeoutThrottle.record())
                    {
                        LOGFN_WARN(logFn(),
                                   "%llu request(s) in the last %d s were not answered within %zu s and were closed "
                                   "with 504. Their handler is stuck or lost the responder.",
                                   static_cast<unsigned long long>(decision.total),
                                   common::LogThrottle::kDefaultWindowSeconds,
                                   m_state->config.responseTimeoutSec);
                    }
                    deliver(errorResponse(504, "Handler did not respond in time"));
                    return;
                }

                // Header/Body/Write: the peer is slow or gone. Nothing useful to say to it, but the
                // operator needs the trace -- these closes consume the connections that
                // max_parallel_connections bounds, and without a line a slow-loris or a degraded
                // network is invisible.
                if (const auto decision = m_state->phaseTimeoutThrottle.record())
                {
                    LOGFN_DEBUG1(logFn(),
                                 "Closed %llu connection(s) in the last %d s that timed out before a response was "
                                 "due (last phase: %s).",
                                 static_cast<unsigned long long>(decision.total),
                                 common::LogThrottle::kDefaultWindowSeconds,
                                 phaseName(m_phase));
                }
                m_finished = true;
                closeSocket();
                unregisterSelf();
            }

            static const char* phaseName(Phase phase)
            {
                switch (phase)
                {
                    case Phase::Header: return "reading the request head";
                    case Phase::Body: return "reading the request body";
                    case Phase::Response: return "awaiting the handler's response";
                    case Phase::Write: return "writing the response";
                }
                return "unknown";
            }

            void doRead()
            {
                auto self = shared_from_this();
                // bind_executor, not a bare lambda: see the class comment. The socket carries the
                // acceptor's shared strand, so an unbound handler would run there instead of here.
                m_socket.async_read_some(asio::buffer(m_readBuffer.data(), m_readBuffer.size()),
                                         asio::bind_executor(m_strand,
                                                             [self](const std::error_code& ec, std::size_t n)
                                                             { self->onRead(ec, n); }));
            }

            void onRead(const std::error_code& ec, std::size_t bytes)
            {
                if (m_finished)
                {
                    return;
                }

                if (ec)
                {
                    // EOF while awaiting a deferred response means the peer gave up first; there is
                    // no one left to answer.
                    m_finished = true;
                    m_timer.cancel();
                    closeSocket();
                    unregisterSelf();
                    return;
                }

                auto verdict = m_parser.feed(m_readBuffer.data(), bytes);

                if (verdict == RequestParser::Feed::HeadersReady)
                {
                    verdict = admitAndResume();
                }

                switch (verdict)
                {
                    case RequestParser::Feed::Incomplete: doRead(); return;
                    case RequestParser::Feed::Complete: dispatch(); return;
                    case RequestParser::Feed::Reject:
                        // These four statuses are decided by limits an operator can tune, and the
                        // peer's write-then-read pattern often means it never reads the status either
                        // (see the interop note below deliver()) -- so this line is the only record
                        // that a 413/414/431 happened at all.
                        if (const auto decision = m_state->limitRejectThrottle.record())
                        {
                            LOGFN_WARN(logFn(),
                                       "Rejected %llu request(s) in the last %d s for exceeding a configured limit "
                                       "(last: %d on '%.128s').",
                                       static_cast<unsigned long long>(decision.total),
                                       common::LogThrottle::kDefaultWindowSeconds,
                                       m_parser.rejectStatus(),
                                       requestPath().c_str());
                        }
                        deliver(errorResponse(m_parser.rejectStatus(), rejectMessage(m_parser.rejectStatus())));
                        return;
                    case RequestParser::Feed::ProtocolError:
                        if (const auto decision = m_state->malformedThrottle.record())
                        {
                            LOGFN_DEBUG1(logFn(),
                                         "Rejected %llu malformed HTTP request(s) in the last %d s with 400.",
                                         static_cast<unsigned long long>(decision.total),
                                         common::LogThrottle::kDefaultWindowSeconds);
                        }
                        deliver(errorResponse(400, "Malformed HTTP request"));
                        return;
                    case RequestParser::Feed::HeadersReady:
                        // admitAndResume() never returns this.
                        return;
                }
            }

            static const char* rejectMessage(int status)
            {
                switch (status)
                {
                    case 411: return "Content-Length is required; chunked transfer encoding is not supported";
                    case 413: return "Request body is too large";
                    case 414: return "Request target is too long";
                    case 431: return "Request headers are too large";
                    case 500: return "Internal error";
                    default: return "Request rejected";
                }
            }

            /**
             * @brief Admission control, run while parsing is paused at the end of the head.
             *
             * Ordering matters and is stricter than the peer's, which reserves only once the whole
             * body is already in memory: routing is resolved and the declared length is checked
             * BEFORE a body we would discard is read at all.
             */
            RequestParser::Feed admitAndResume()
            {
                const auto* route = matchRoute();
                if (route == nullptr)
                {
                    respondNoRoute();
                    return RequestParser::Feed::Incomplete; // deliver() already ran; nothing more to parse
                }

                if (route->countAgainstBudget && m_state->budget)
                {
                    const auto declared = static_cast<std::size_t>(m_parser.declaredContentLength());
                    auto reserved = m_state->budget->tryReserve(declared + m_state->perRequestOverhead);
                    if (!reserved)
                    {
                        if (const auto decision = m_state->budgetThrottle.record())
                        {
                            LOGFN_WARN(logFn(),
                                       "Rejected %llu request(s) with 503 in the last %d s: the in-flight payload "
                                       "budget is exhausted (%zu request(s) resident, %zu byte(s) free). Consider "
                                       "raising 'inventory_sync_server_max_inflight_bytes'.",
                                       static_cast<unsigned long long>(decision.total),
                                       common::LogThrottle::kDefaultWindowSeconds,
                                       m_state->budget->inFlightCount(),
                                       m_state->budget->availableBytes());
                        }
                        deliver(errorResponse(503, "Server is out of capacity"));
                        return RequestParser::Feed::Incomplete;
                    }
                    m_reservation = std::move(*reserved);
                }

                m_route = route;
                armTimer(Phase::Body, std::chrono::seconds {m_state->config.bodyTimeoutSec});
                return m_parser.resume();
            }

            const Route* matchRoute()
            {
                const auto target = requestPath();
                const Route* pathMatch {nullptr};

                for (const auto& route : m_state->routes)
                {
                    if (route.path != target)
                    {
                        continue;
                    }
                    pathMatch = &route;
                    if (route.method == m_parser.request().method)
                    {
                        return &route;
                    }
                }
                // A path match with the wrong verb is remembered so respondNoRoute() can answer 405
                // with an Allow header instead of a misleading 404.
                m_pathMatchedOtherMethod = pathMatch != nullptr;
                return nullptr;
            }

            /// The routable part of the target: everything before the query string. The target itself
            /// is kept raw (query included) because that is what the peer signs and logs.
            std::string requestPath()
            {
                const auto& target = m_parser.request().target;
                const auto query = target.find('?');
                return query == std::string::npos ? target : target.substr(0, query);
            }

            void respondNoRoute()
            {
                // The peer maps 404/405 to a retryable 503 towards the agent and its forwarder logs
                // them selectively, so a route mismatch between remoted and this module -- the
                // expected integration failure while the sync path is provisional -- would otherwise
                // leave no trace in either daemon.
                if (const auto decision = m_state->noRouteThrottle.record())
                {
                    LOGFN_WARN(logFn(),
                               "Answered %llu request(s) in the last %d s with %d: no route for %s '%.128s'.",
                               static_cast<unsigned long long>(decision.total),
                               common::LogThrottle::kDefaultWindowSeconds,
                               m_pathMatchedOtherMethod ? 405 : 404,
                               methodToString(m_parser.request().method),
                               requestPath().c_str());
                }

                if (!m_pathMatchedOtherMethod)
                {
                    deliver(errorResponse(404, "Unknown endpoint"));
                    return;
                }

                const auto path = requestPath();
                std::string allow;
                for (const auto& route : m_state->routes)
                {
                    if (route.path != path)
                    {
                        continue;
                    }
                    if (!allow.empty())
                    {
                        allow += ", ";
                    }
                    allow += methodToString(route.method);
                }

                auto response = errorResponse(405, "Method not allowed for this endpoint");
                response.headers.emplace_back("Allow", allow);
                deliver(std::move(response));
            }

            void dispatch()
            {
                m_dispatched = true;
                m_state->undispatched.fetch_sub(1, std::memory_order_relaxed);
                m_state->dispatchesRunning.fetch_add(1, std::memory_order_relaxed);

                // RAII rather than a trailing decrement: a throw below would otherwise leak the
                // count, and a leaked count makes EVERY later shutdown wait out its full
                // dispatch-drain window inside modulesd's signal handler.
                struct RunningGuard
                {
                    ServerState& state;
                    ~RunningGuard()
                    {
                        state.dispatchesRunning.fetch_sub(1, std::memory_order_relaxed);
                        state.noteProgress();
                    }
                } runningGuard {*m_state};

                std::shared_ptr<SessionResponder> responder;

                // Exception barrier for the WHOLE dispatch, allocations included, not just the
                // handler call: a throw anywhere here must produce a 500 rather than take the I/O
                // thread -- and therefore the whole daemon -- down with it.
                try
                {
                    // The payload and its reservation move into a jointly-owned context; the handler
                    // gets a view aliased into it, so dropping that view frees both at once.
                    auto context = std::make_shared<RequestContext>();
                    context->state = m_state; // keeps the budget alive if the handler outlives us
                    context->request = std::move(m_parser.request());
                    context->reservation = std::move(m_reservation);
                    std::shared_ptr<const HttpRequest> request {context, &context->request};

                    // The read buffer is dead weight from here on, and it would otherwise stay resident
                    // for the whole deferral: 8 KiB x hundreds of pending replies.
                    m_readBuffer.clear();
                    m_readBuffer.shrink_to_fit();

                    armTimer(Phase::Response, std::chrono::seconds {m_state->config.responseTimeoutSec});
                    watchPeerDuringDeferral();

                    responder = std::make_shared<SessionResponder>(m_runtime, weak_from_this(), m_state);
                    m_route->handler(std::move(request), responder);
                }
                catch (const std::exception& e)
                {
                    answerFailedDispatch(responder, e.what());
                }
                // LCOV_EXCL_START -- nothing reachable from here throws a non-std type
                catch (...)
                {
                    answerFailedDispatch(responder, "non-standard exception");
                }
                // LCOV_EXCL_STOP
            }

            /// Answers 500 for a throw while dispatching -- from the handler or from the allocations
            /// leading up to it. Throttled: a deterministic handler bug fires once per request on the
            /// ingest path.
            void answerFailedDispatch(const std::shared_ptr<SessionResponder>& responder, const char* reason)
            {
                if (const auto decision = m_state->handlerThrewThrottle.record())
                {
                    LOGFN_ERROR(logFn(),
                                "%llu request(s) failed while being dispatched in the last %d s and were answered "
                                "500 (last: %s).",
                                static_cast<unsigned long long>(decision.total),
                                common::LogThrottle::kDefaultWindowSeconds,
                                reason);
                }
                if (responder)
                {
                    responder->send(errorResponse(500, "Internal error"));
                }
                // LCOV_EXCL_START -- responder is null only when an allocation before the handler
                // call failed, which a test cannot stage without breaking the allocator
                else
                {
                    deliver(errorResponse(500, "Internal error"));
                }
                // LCOV_EXCL_STOP
            }

            /**
             * @brief Notices a peer that gives up while its response is deferred.
             *
             * After dispatch() there is no read pending, so without this an EOF sits unseen and the
             * fd, the registry entry and the connection slot are held until the response timeout --
             * hundreds of seconds after the peer's own deadline expired. The protocol is one request
             * per connection with no pipelining, so any byte arriving during a deferral is a peer
             * violating the contract, and EOF is the peer giving up; either way the session is done.
             *
             * A one-byte async_read_some, deliberately NOT async_wait(wait_read): asio may complete
             * a readiness wait from the reactor's cached (speculative, edge-triggered) state left
             * behind by the request's own reads -- readable-per-cache while a recv() would say
             * EAGAIN -- which falsely condemned ~1% of group-committed responses whose request
             * arrived in more than one segment. A real read only completes on actual data or EOF.
             */
            void watchPeerDuringDeferral()
            {
                auto self = shared_from_this();
                m_socket.async_read_some(
                    asio::buffer(&m_peerProbe, 1),
                    asio::bind_executor(m_strand,
                                        [self](const std::error_code& ec, std::size_t)
                                        {
                                            if (self->m_finished || ec == asio::error::operation_aborted)
                                            {
                                                return; // already answered, or torn down
                                            }
                                            if (const auto decision = self->m_state->peerGoneThrottle.record())
                                            {
                                                LOGFN_DEBUG1(logFn(),
                                                             "Closed %llu connection(s) in the last %d s whose "
                                                             "peer went away while the response was still "
                                                             "pending.",
                                                             static_cast<unsigned long long>(decision.total),
                                                             common::LogThrottle::kDefaultWindowSeconds);
                                            }
                                            self->m_finished = true;
                                            self->m_timer.cancel();
                                            self->closeSocket();
                                            self->unregisterSelf();
                                        }));
            }

            /// Exactly-once. Every path that ends a request funnels through here.
            void deliver(HttpResponse response)
            {
                if (m_finished)
                {
                    return;
                }
                m_finished = true;
                m_timer.cancel();

                // Past this point m_finished is set, so no other path will ever close this session:
                // a throw below (serializeHead and the async initiations allocate) must still
                // release the fd and the registry entry, or they leak until stop().
                try
                {
                    m_writeHead = serializeHead(response);
                    m_writeBody = std::move(response.body);
                    m_writeBuffers = {asio::buffer(m_writeHead), asio::buffer(m_writeBody)};

                    armWriteTimer();

                    auto self = shared_from_this();
                    asio::async_write(m_socket,
                                      m_writeBuffers,
                                      asio::bind_executor(
                                          m_strand,
                                          [self](const std::error_code& ec, std::size_t)
                                          {
                                              // A response that could not be written must be
                                              // distinguishable from a delivered one.
                                              if (ec && ec != asio::error::operation_aborted)
                                              {
                                                  if (const auto decision = self->m_state->writeErrorThrottle.record())
                                                  {
                                                      LOGFN_DEBUG1(logFn(),
                                                                   "Failed to write %llu response(s) in the "
                                                                   "last %d s (last: %s).",
                                                                   static_cast<unsigned long long>(decision.total),
                                                                   common::LogThrottle::kDefaultWindowSeconds,
                                                                   ec.message().c_str());
                                                  }
                                              }
                                              self->m_timer.cancel();
                                              self->closeSocket();
                                              self->unregisterSelf();
                                          }));
                }
                // LCOV_EXCL_START -- only serializeHead/async-initiation allocation failures land here
                catch (...)
                {
                    m_timer.cancel();
                    closeSocket();
                    unregisterSelf();
                }
                // LCOV_EXCL_STOP
            }

            /*
             * INTEROP NOTE, for the rejections decided at headers-complete (404, 405, 411, 413, 503).
             *
             * The peer writes an entire request before reading any of the response, so rejecting at
             * the head and closing makes a peer mid-way through a large body see a transport error
             * instead of the status. Accepted deliberately: draining the refused body would hand the
             * client control over how long we spend on it, and remoted caps the body on its own
             * inbound side first. A small rejected body fits in the socket buffer and the peer reads
             * the status normally -- which is why the server-side throttled logs above are the only
             * reliable record of a large-body rejection.
             */

            /// The write deadline is armed after m_finished is already set, so it must close the
            /// socket directly rather than route through deliver().
            void armWriteTimer()
            {
                m_phase = Phase::Write;
                auto self = shared_from_this();
                m_timer.expires_after(std::chrono::seconds {m_state->config.writeTimeoutSec});
                m_timer.async_wait(
                    [self](const std::error_code& ec)
                    {
                        if (ec)
                        {
                            return;
                        }
                        self->closeSocket();
                        self->unregisterSelf();
                    });
            }

            void closeSocket()
            {
                std::error_code ignore;
                m_socket.shutdown(stream_protocol::socket::shutdown_both, ignore);
                m_socket.close(ignore);
            }

            void unregisterSelf()
            {
                if (m_unregistered)
                {
                    return;
                }
                m_unregistered = true;

                if (!m_dispatched)
                {
                    m_state->undispatched.fetch_sub(1, std::memory_order_relaxed);
                }
                m_state->liveSessions.fetch_sub(1, std::memory_order_relaxed);

                {
                    std::lock_guard<std::mutex> lock {m_state->registryMutex};
                    m_state->sessions.erase(m_id);
                }
                m_state->noteProgress();
            }

            /**
             * @brief The responder handed to a handler.
             *
             * Holds the Runtime strongly (so a late send() is safe even after the server is gone) but
             * the Session only WEAKLY -- a responder a handler forgets about must not keep a file
             * descriptor open. There is deliberately no reference in the other direction, which is
             * what lets the destructor detect the never-sent case at all.
             */
            class SessionResponder final : public IHttpResponder
            {
            public:
                SessionResponder(std::shared_ptr<Runtime> runtime,
                                 std::weak_ptr<Session> session,
                                 std::shared_ptr<ServerState> state)
                    : m_runtime {std::move(runtime)}
                    , m_session {std::move(session)}
                    , m_state {std::move(state)}
                {
                }

                ~SessionResponder() override
                {
                    if (m_answered.load(std::memory_order_acquire))
                    {
                        return;
                    }
                    if (auto session = m_session.lock())
                    {
                        session->submitAbandoned();
                    }
                }

                void send(HttpResponse response) override
                {
                    // Exactly once, whichever thread gets here first.
                    if (m_answered.exchange(true, std::memory_order_acq_rel))
                    {
                        return;
                    }
                    if (auto session = m_session.lock())
                    {
                        session->submitResponse(std::move(response));
                    }
                    // Otherwise the session is already gone (timed out, peer closed, or the server
                    // was stopped). A no-op, by contract -- never undefined behaviour.
                }

            private:
                std::shared_ptr<Runtime> m_runtime; ///< Declared first => destroyed last.
                std::weak_ptr<Session> m_session;
                std::shared_ptr<ServerState> m_state;
                std::atomic<bool> m_answered {false};
            };

            std::shared_ptr<Runtime> m_runtime; ///< MUST stay the first member (see the constructor).
            std::shared_ptr<ServerState> m_state;
            asio::strand<asio::io_context::executor_type> m_strand;
            stream_protocol::socket m_socket;
            asio::steady_timer m_timer;
            RequestParser m_parser;
            std::vector<char> m_readBuffer;
            char m_peerProbe {0}; ///< 1-byte sink for watchPeerDuringDeferral()'s EOF-detecting read.

            InFlightBudget::Reservation m_reservation;
            const Route* m_route {nullptr};
            bool m_pathMatchedOtherMethod {false};

            std::uint64_t m_id {0};
            Phase m_phase {Phase::Header};
            bool m_finished {false};
            bool m_dispatched {false};
            bool m_unregistered {false};

            std::string m_writeHead;
            std::string m_writeBody;
            std::array<asio::const_buffer, 2> m_writeBuffers {};
        };

        /// Writes a canned response on a socket we are refusing to turn into a Session.
        ///
        /// Deliberately NOT bound to a per-connection strand, unlike Session's handlers: this socket
        /// belongs to no Session, nothing else ever touches it, and the one-shot write-then-close is
        /// already serialized by the acceptor strand it was accepted on.
        void writeAndClose(std::shared_ptr<ServerState> state,
                           std::shared_ptr<stream_protocol::socket> socket,
                           const HttpResponse& response)
        {
            auto payload = std::make_shared<std::string>(serializeHead(response) + response.body);
            asio::async_write(*socket,
                              asio::buffer(*payload),
                              [state = std::move(state), socket, payload](const std::error_code& ec, std::size_t)
                              {
                                  if (ec && ec != asio::error::operation_aborted)
                                  {
                                      if (const auto decision = state->writeErrorThrottle.record())
                                      {
                                          LOGFN_DEBUG1(logFn(),
                                                       "Failed to write %llu response(s) in the last %d s (last: %s).",
                                                       static_cast<unsigned long long>(decision.total),
                                                       common::LogThrottle::kDefaultWindowSeconds,
                                                       ec.message().c_str());
                                      }
                                  }
                                  std::error_code ignore;
                                  socket->shutdown(stream_protocol::socket::shutdown_both, ignore);
                                  socket->close(ignore);
                              });
        }
    } // namespace

    struct AsioUdsHttpServer::Impl
    {
        enum class State
        {
            Idle,
            Running,
            Draining,
            Stopped
        };

        std::shared_ptr<Runtime> runtime {std::make_shared<Runtime>()};
        std::shared_ptr<ServerState> state {std::make_shared<ServerState>()};

        std::optional<asio::executor_work_guard<asio::io_context::executor_type>> work;
        std::vector<std::thread> threads;
        std::atomic<std::size_t> threadsExited {0};
        std::mutex threadMutex;
        std::condition_variable threadCv;

        std::optional<asio::strand<asio::io_context::executor_type>> acceptorStrand;
        std::optional<stream_protocol::acceptor> acceptor;

        std::atomic<State> lifecycle {State::Idle};
        std::string socketPath;
        /// Inode of the socket this server bound, so teardown never unlinks someone else's.
        ::ino_t boundInode {0};

        /**
         * @brief Serialises the shutdown phases against each other.
         *
         * The lifecycle CAS alone is not enough: the loser of the CAS in doStop() goes straight to
         * joinThreads() while the winner is still reading threads.size() and joinThreads() is
         * clear()ing the vector. The facade's stop() and this class's destructor can genuinely both
         * run -- stop() then ~AsioUdsHttpServer -- so that race is reachable, not theoretical.
         */
        std::mutex shutdownMutex;

        /// For the I/O-thread resume loop: a persistent throwing condition would otherwise emit one
        /// ERROR per queued handler, at CPU speed, multiplied by ioThreads. Lives here rather than in
        /// ServerState because the thread lambda captures the Impl.
        common::LogThrottle ioThreadResumeThrottle;

        /// Bind, permission and listen, in an order where any failure leaves nothing running.
        void bindAcceptor()
        {
            // sockaddr_un::sun_path is famously short and asio's own failure here is opaque, so the
            // limit is checked up front with a message that names both the path and the cap.
            constexpr std::size_t SUN_PATH_MAX {sizeof(::sockaddr_un::sun_path)};
            if (socketPath.size() >= SUN_PATH_MAX)
            {
                throw std::runtime_error {"the socket path '" + socketPath + "' is " +
                                          std::to_string(socketPath.size()) + " characters, which does not fit the " +
                                          std::to_string(SUN_PATH_MAX - 1) +
                                          "-character limit for Unix domain sockets"};
            }

            struct stat existing {};
            if (::stat(socketPath.c_str(), &existing) == 0)
            {
                if (!S_ISSOCK(existing.st_mode))
                {
                    // Deliberately stricter than cpp-httplib, which unlinks whatever is in the way: a
                    // typo in the configured path must not delete an operator's file.
                    throw std::runtime_error {"'" + socketPath +
                                              "' already exists and is not a socket; refusing to remove it"};
                }
                // A stale socket from an unclean shutdown. Without this, bind() would fail with
                // EADDRINUSE forever and the module would never come back. Logged: if the socket was
                // NOT stale (a second manager still serving on it), this line is the only trace of
                // the takeover on this side.
                LOGFN_INFO(logFn(),
                           "Removing the existing socket at '%s' (a leftover from an unclean shutdown) before "
                           "binding.",
                           socketPath.c_str());
                ::unlink(socketPath.c_str());
            }

            // The parent directory is deliberately NOT created: the installer owns it, so a missing
            // one is an installation problem and must be loud rather than papered over.
            const stream_protocol::endpoint endpoint {socketPath};
            acceptor->open(endpoint.protocol());
            acceptor->bind(endpoint);
            acceptor->listen(asio::socket_base::max_listen_connections);

            // Mandatory, not belt-and-braces: bind() applies the umask, so the mode it leaves behind
            // is whatever the daemon's umask allows. Without this, remoted (a different user, same
            // group) can get EACCES on a socket that looks fine.
            if (::chmod(socketPath.c_str(), static_cast<::mode_t>(state->config.socketMode)) != 0)
            {
                LOGFN_WARN(logFn(),
                           "Could not set mode %04o on '%s': %s. The peer may not be able to connect.",
                           state->config.socketMode,
                           socketPath.c_str(),
                           std::strerror(errno));
            }

            // Remembered so closeAcceptor() can tell OUR socket from one another process rebound at
            // the same path in the meantime, and unlink only its own.
            struct stat bound {};
            boundInode = (::stat(socketPath.c_str(), &bound) == 0) ? bound.st_ino : 0;
        }

        /**
         * @brief Arms one accept chain.
         *
         * There are `concurrentAccepts` of these outstanding at once, all on the acceptor strand.
         * Every one of them must keep re-arming itself for as long as the server is accepting: the
         * count of live chains is the server's capacity to notice new connections at all, and a chain
         * that returns without re-arming is gone until the module restarts.
         */
        void doAccept()
        {
            // Initiation and completion are both guarded: a throw anywhere in the chain would
            // otherwise escape to the I/O thread barrier and this chain would never re-arm --
            // with the default of 2 chains, two such events leave the socket bound, the process
            // healthy and the listener permanently deaf.
            try
            {
                acceptor->async_accept([this](const std::error_code& ec, stream_protocol::socket socket)
                                       { onAcceptCompleted(ec, std::move(socket)); });
            }
            // LCOV_EXCL_START -- initiating an accept throws only on allocation failure
            catch (const std::exception& e)
            {
                reportAcceptFailure(e.what());
                rearmAccept();
            }
            // LCOV_EXCL_STOP
        }

        void onAcceptCompleted(const std::error_code& ec, stream_protocol::socket socket)
        {
            try
            {
                if (ec)
                {
                    // operation_aborted is the normal path: stopAccepting() closed the acceptor.
                    // Checking `accepting` too covers the close racing ahead of the cancel.
                    if (ec == asio::error::operation_aborted || !state->accepting.load(std::memory_order_acquire))
                    {
                        return;
                    }

                    // Any OTHER error (EMFILE above all -- the descriptor budget is shared by all of
                    // modulesd) is transient and MUST NOT end the chain.
                    reportAcceptFailure(ec.message().c_str());
                    rearmAccept();
                    return;
                }

                onAccepted(std::move(socket));
                doAccept();
            }
            // LCOV_EXCL_START -- onAccepted() has its own barrier, so only its rollback path or the
            // re-arm itself can throw here, both allocation failures
            catch (const std::exception& e)
            {
                reportAcceptFailure(e.what());
                rearmAccept();
            }
            catch (...)
            {
                reportAcceptFailure("non-standard exception");
                rearmAccept();
            }
            // LCOV_EXCL_STOP
        }

        void reportAcceptFailure(const char* reason)
        {
            if (const auto decision = state->acceptErrorThrottle.record())
            {
                LOGFN_WARN(logFn(),
                           "Failed to accept %llu inventory sync connection(s) in the last %d s: %s. The "
                           "listener is still accepting; peers will retry.",
                           static_cast<unsigned long long>(decision.total),
                           common::LogThrottle::kDefaultWindowSeconds,
                           reason);
            }
        }

        /// Re-arms through the strand instead of recursing: on a persistent condition async_accept
        /// can complete immediately, and recursion would grow the stack. If even the post fails the
        /// chain is gone -- the throttled accept-failure line is the only trace.
        void rearmAccept() noexcept
        {
            try
            {
                asio::post(*acceptorStrand, [this]() { doAccept(); });
            }
            // LCOV_EXCL_START -- only a failed handler allocation inside asio::post throws here
            catch (...)
            {
            }
            // LCOV_EXCL_STOP
        }

        void onAccepted(stream_protocol::socket socket)
        {
            if (!state->accepting.load(std::memory_order_acquire))
            {
                std::error_code ignore;
                socket.close(ignore);
                return;
            }

            const auto live = state->liveSessions.fetch_add(1, std::memory_order_relaxed) + 1;
            if (live > state->config.maxConnections)
            {
                state->liveSessions.fetch_sub(1, std::memory_order_relaxed);
                // A rollback is progress too: stop() waits on this counter, and without the wake it
                // sits out its whole window whenever the cap was hit as the server was going down.
                state->noteProgress();
                if (const auto decision = state->connectionCapThrottle.record())
                {
                    LOGFN_WARN(logFn(),
                               "Refused %llu connection(s) with 503 in the last %d s: the %zu-connection limit is "
                               "reached. Each deferred response holds one connection; consider raising "
                               "'inventory_sync_server_max_parallel_connections'.",
                               static_cast<unsigned long long>(decision.total),
                               common::LogThrottle::kDefaultWindowSeconds,
                               state->config.maxConnections);
                }
                // An explicit status rather than a silent close, so the peer classifies this as
                // "server out of capacity" instead of a transport failure.
                writeAndClose(state,
                              std::make_shared<stream_protocol::socket>(std::move(socket)),
                              errorResponse(503, "Too many concurrent connections"));
                return;
            }

            // From here both counters are bumped, so every failure path has to put them back:
            // everything below can throw std::bad_alloc, and a leaked counter is permanent -- it
            // makes every later shutdown sit out its drain window.
            bool bumpedUndispatched {false};
            bool registered {false};
            std::uint64_t id {0};

            try
            {
                auto session = std::make_shared<Session>(runtime, state, std::move(socket));

                state->undispatched.fetch_add(1, std::memory_order_relaxed);
                bumpedUndispatched = true;

                {
                    std::lock_guard<std::mutex> lock {state->registryMutex};
                    id = state->nextSessionId++;
                    session->setId(id);
                    state->sessions.emplace(id, session);
                }
                registered = true;

                // The posted body runs later, on the session's strand, outside this try: it needs its
                // own barrier, or a throw in armTimer/doRead leaves a registered session with no
                // timer and no read pending -- a permanent fd leak.
                asio::post(session->strand(),
                           [session, state = this->state]()
                           {
                               try
                               {
                                   session->start();
                               }
                               // LCOV_EXCL_START -- armTimer/doRead throw only on allocation failure
                               catch (...)
                               {
                                   if (const auto decision = state->sessionBringupThrottle.record())
                                   {
                                       LOGFN_ERROR(logFn(),
                                                   "Could not bring up %llu accepted inventory sync connection(s) in "
                                                   "the last %d s.",
                                                   static_cast<unsigned long long>(decision.total),
                                                   common::LogThrottle::kDefaultWindowSeconds);
                                   }
                                   try
                                   {
                                       session->forceClose();
                                   }
                                   catch (...)
                                   {
                                   }
                               }
                               // LCOV_EXCL_STOP
                           });
            }
            catch (const std::exception& e)
            {
                reportBringupFailure(e.what());
                rollbackFailedAccept(bumpedUndispatched, registered, id);
            }
            catch (...)
            {
                reportBringupFailure("non-standard exception");
                rollbackFailedAccept(bumpedUndispatched, registered, id);
            }
        }

        // LCOV_EXCL_START -- both callees of the bad_alloc-only bring-up catches above
        /// Bring-up failures are resource exhaustion (bad_alloc), i.e. the same incident on every
        /// connection attempt while it lasts -- so they aggregate like accept failures do.
        void reportBringupFailure(const char* reason)
        {
            if (const auto decision = state->sessionBringupThrottle.record())
            {
                LOGFN_ERROR(logFn(),
                            "Could not bring up %llu accepted inventory sync connection(s) in the last %d s "
                            "(last: %s).",
                            static_cast<unsigned long long>(decision.total),
                            common::LogThrottle::kDefaultWindowSeconds,
                            reason);
            }
        }

        /// Undoes onAccepted()'s bookkeeping when bringing a connection up threw part-way, so the
        /// shutdown counters stay exact. Never throws: it runs from a catch block.
        void rollbackFailedAccept(bool bumpedUndispatched, bool registered, std::uint64_t id) noexcept
        {
            try
            {
                if (registered)
                {
                    std::lock_guard<std::mutex> lock {state->registryMutex};
                    state->sessions.erase(id);
                }
                if (bumpedUndispatched)
                {
                    state->undispatched.fetch_sub(1, std::memory_order_relaxed);
                }
                state->liveSessions.fetch_sub(1, std::memory_order_relaxed);
                state->noteProgress();
            }
            catch (...) // NOLINT(bugprone-empty-catch) -- nothing useful left to do on this path
            {
            }
        }
        // LCOV_EXCL_STOP

        /// Phase 1. See IUdsHttpServer::stopAccepting() for the guarantees this establishes.
        void doStopAccepting() noexcept
        {
            // The lock acquisition sits inside the barrier too: this is noexcept, so anything
            // escaping here -- however unlikely -- would be an instant terminate for all of modulesd.
            try
            {
                std::lock_guard<std::mutex> lock {shutdownMutex};
                doStopAcceptingLocked();
            }
            // LCOV_EXCL_START -- mutex::lock() failure is not stageable from a test
            catch (...)
            {
            }
            // LCOV_EXCL_STOP
        }

        /// Body of phase 1. Callers must hold shutdownMutex.
        void doStopAcceptingLocked() noexcept
        {
            auto expected = State::Running;
            if (!lifecycle.compare_exchange_strong(expected, State::Draining))
            {
                return; // Idle, already draining, or stopped.
            }

            try
            {
                state->accepting.store(false, std::memory_order_release);

                // P1.1: close the acceptor ON its strand, and WAIT for that to have happened.
                // Merely posting would leave "no new connection will be accepted" scheduled rather
                // than true, which a test can observe by connecting successfully afterwards.
                if (acceptorStrand && !threads.empty())
                {
                    // Bounded wait: this runs with the facade's lifecycle mutex held, inside
                    // modulesd's signal handler. The promise is a shared_ptr, not a local, so giving
                    // up on the wait cannot leave the queued lambda holding a dangling address.
                    auto closed = std::make_shared<std::promise<void>>();
                    auto done = closed->get_future();
                    asio::post(*acceptorStrand,
                               [this, closed]()
                               {
                                   closeAcceptor();
                                   closed->set_value();
                               });

                    if (done.wait_for(ACCEPTOR_CLOSE_TIMEOUT) != std::future_status::ready)
                    {
                        // Deliberately does NOT close the acceptor from this thread: it belongs to the
                        // strand, and racing the queued handler for it is worse than a socket that
                        // stays bound a moment longer. Phase 2 force-closes everything regardless.
                        LOGFN_ERROR(logFn(),
                                    "The inventory sync server's acceptor did not close within %lld s; a request "
                                    "handler is not returning. Continuing to shut down.",
                                    static_cast<long long>(ACCEPTOR_CLOSE_TIMEOUT.count()));
                    }
                }
                else
                {
                    closeAcceptor();
                }

                // P1.2: connections that had not reached a handler get 503; those already dispatched
                // are left alone, because their response is still coming.
                std::vector<std::shared_ptr<Session>> snapshot;
                {
                    std::lock_guard<std::mutex> lock {state->registryMutex};
                    snapshot.reserve(state->sessions.size());
                    for (auto& [id, session] : state->sessions)
                    {
                        snapshot.push_back(session);
                    }
                }
                for (auto& session : snapshot)
                {
                    asio::post(session->strand(), [session]() { session->rejectForShutdown(); });
                }

                // P1.3: wait until nothing is mid-dispatch and nothing is still pre-handler. Both
                // counters are bounded by the file-descriptor limit and every path decrements them,
                // so this cannot hang -- but only while the I/O threads are running to drive it.
                if (!threads.empty())
                {
                    std::unique_lock<std::mutex> lock {state->progressMutex};
                    state->progressCv.wait_for(lock,
                                               DISPATCH_DRAIN_TIMEOUT,
                                               [this]
                                               {
                                                   return state->undispatched.load(std::memory_order_relaxed) == 0 &&
                                                          state->dispatchesRunning.load(std::memory_order_relaxed) == 0;
                                               });
                }

                const auto outstanding = state->liveSessions.load(std::memory_order_relaxed);
                const auto rejected = state->shutdownRejected.load(std::memory_order_relaxed);
                LOGFN_INFO(logFn(),
                           "inventory sync server is no longer accepting on '%s'; %zu deferred repl%s still "
                           "outstanding, %zu pre-handler connection(s) answered 503.",
                           socketPath.c_str(),
                           outstanding,
                           outstanding == 1 ? "y" : "ies",
                           rejected);
            }
            // LCOV_EXCL_START -- nothing in the body throws outside allocation failure
            catch (const std::exception& e)
            {
                // noexcept by contract. A swallowed exception here makes the "no handler will run
                // again" guarantee best-effort rather than unconditional, so the cause must be named.
                LOGFN_ERROR(
                    logFn(), "An error occurred while the inventory sync server stopped accepting: %s.", e.what());
            }
            catch (...)
            {
                LOGFN_ERROR(logFn(), "An error occurred while the inventory sync server stopped accepting.");
            }
            // LCOV_EXCL_STOP
        }

        void closeAcceptor() noexcept
        {
            if (!acceptor)
            {
                return;
            }
            std::error_code ignore;
            acceptor->cancel(ignore);
            acceptor->close(ignore);

            // Only unlink the socket if the path still refers to the inode we bound. Between our bind
            // and this teardown another process can have unlinked ours and bound its own at the same
            // path (bindAcceptor() unlinks any stale socket it finds, so the reverse is possible too);
            // unlinking unconditionally would silently take down that server's listener.
            if (socketPath.empty() || boundInode == 0)
            {
                return;
            }
            struct stat current {};
            const auto statResult = ::stat(socketPath.c_str(), &current);
            if (statResult == 0 && current.st_ino == boundInode)
            {
                ::unlink(socketPath.c_str());
            }
            else
            {
                // Two managers fighting over the socket (double start, unclean upgrade) is a real
                // production incident and this is its only trace on this side.
                try
                {
                    LOGFN_WARN(logFn(),
                               "Not unlinking '%s': %s since this server started.",
                               socketPath.c_str(),
                               statResult == 0 ? "another process has re-bound it" : "something removed it");
                }
                catch (...) // LCOV_EXCL_LINE -- this function is noexcept and log formatting allocates
                {
                }
            }
        }

        /// Phase 2. See IUdsHttpServer::stop() for the guarantees this establishes.
        void doStop() noexcept
        {
            try
            {
                doStopBody();
            }
            // LCOV_EXCL_START -- doStopBody() carries its own catches; only mutex::lock() is left
            catch (...)
            {
                // noexcept backstop: nothing may escape into the destructor / the signal handler.
            }
            // LCOV_EXCL_STOP
        }

        void doStopBody()
        {
            std::lock_guard<std::mutex> lock {shutdownMutex};

            doStopAcceptingLocked();

            auto expected = State::Draining;
            if (!lifecycle.compare_exchange_strong(expected, State::Stopped))
            {
                // Idle (never started) or already stopped.
                lifecycle.store(State::Stopped);
                joinThreads();
                return;
            }

            try
            {
                // P2.1: give the deferred replies their bounded window to land.
                if (!threads.empty())
                {
                    std::unique_lock<std::mutex> lock {state->progressMutex};
                    state->progressCv.wait_for(lock,
                                               std::chrono::seconds {state->config.drainTimeoutSec},
                                               [this]
                                               { return state->liveSessions.load(std::memory_order_relaxed) == 0; });
                }

                const auto stranded = state->liveSessions.load(std::memory_order_relaxed);
                if (stranded > 0)
                {
                    LOGFN_WARN(logFn(),
                               "%zu inventory sync request(s) had not been answered after %zu s; closing their "
                               "connections. The peer will see them fail rather than time out.",
                               stranded,
                               state->config.drainTimeoutSec);
                }

                // P2.2: force-close the remainder. Destroying every Session HERE, with the reactor
                // still alive, is invariant I2: it keeps ~socket/~steady_timer out of
                // ~io_context(), which would otherwise run them while the reactor's own services
                // are being torn down around them.
                forceCloseAll();

                // P2.3: release the work guard but do NOT stop the io_context. Every socket is
                // closed, so the pending completions fire with operation_aborted, the Sessions
                // release, the context runs dry and run() returns on its own -- which is what makes
                // the "no I/O object outlives the reactor" ordering hold.
                work.reset();

                if (!threads.empty())
                {
                    std::unique_lock<std::mutex> lock {threadMutex};
                    const auto drained = threadCv.wait_for(
                        lock, THREAD_EXIT_GRACE, [this] { return threadsExited.load() >= threads.size(); });

                    if (!drained)
                    {
                        // The fragile path, logged as such so it is never taken silently.
                        LOGFN_ERROR(logFn(),
                                    "The inventory sync server's I/O threads did not drain within %lld s; forcing the "
                                    "I/O context to stop.",
                                    static_cast<long long>(THREAD_EXIT_GRACE.count()));
                        runtime->ioc.stop();
                    }
                }
            }
            // LCOV_EXCL_START -- nothing in the body throws outside allocation failure
            catch (const std::exception& e)
            {
                LOGFN_ERROR(logFn(), "An error occurred while the inventory sync server stopped: %s.", e.what());
                runtime->ioc.stop();
            }
            catch (...)
            {
                LOGFN_ERROR(logFn(), "An error occurred while the inventory sync server stopped.");
                runtime->ioc.stop();
            }
            // LCOV_EXCL_STOP

            joinThreads();
            LOGFN_INFO(logFn(), "inventory sync server fully stopped.");
        }

        void forceCloseAll() noexcept
        {
            // Marked noexcept but it allocates and locks; a throw would bypass doStop()'s own catch
            // (the callee's noexcept wins) and terminate the daemon, so it carries its own barrier.
            try
            {
                std::vector<std::shared_ptr<Session>> snapshot;
                {
                    std::lock_guard<std::mutex> lock {state->registryMutex};
                    snapshot.reserve(state->sessions.size());
                    for (auto& [id, session] : state->sessions)
                    {
                        snapshot.push_back(session);
                    }
                }

                for (auto& session : snapshot)
                {
                    asio::post(session->strand(), [session]() { session->forceClose(); });
                }

                if (!threads.empty())
                {
                    std::unique_lock<std::mutex> lock {state->progressMutex};
                    state->progressCv.wait_for(lock,
                                               FORCE_CLOSE_TIMEOUT,
                                               [this]
                                               {
                                                   std::lock_guard<std::mutex> registryLock {state->registryMutex};
                                                   return state->sessions.empty();
                                               });
                }

                std::lock_guard<std::mutex> lock {state->registryMutex};
                state->sessions.clear();
            }
            // LCOV_EXCL_START -- only allocation/lock failure reaches this backstop
            catch (...)
            {
            }
            // LCOV_EXCL_STOP
        }

        void joinThreads() noexcept
        {
            for (auto& thread : threads)
            {
                try
                {
                    if (thread.joinable())
                    {
                        thread.join();
                    }
                }
                // LCOV_EXCL_START -- join() throws only for deadlock/invalid-handle programming
                // errors; there is no way to stage one without corrupting the thread object
                catch (...)
                {
                    // join() throwing (system_error) with the thread still joinable would terminate
                    // on ~thread; detaching is the only remaining way to make the handle droppable.
                    try
                    {
                        thread.detach();
                    }
                    catch (...)
                    {
                    }
                }
                // LCOV_EXCL_STOP
            }
            threads.clear();
        }
    };

    AsioUdsHttpServer::AsioUdsHttpServer()
        : m_impl {std::make_unique<Impl>()}
    {
    }

    AsioUdsHttpServer::~AsioUdsHttpServer()
    {
        m_impl->doStop();
    }

    void
    AsioUdsHttpServer::addRoute(Method method, const std::string& path, RouteHandler handler, bool countAgainstBudget)
    {
        if (m_impl->lifecycle.load() != Impl::State::Idle)
        {
            throw std::logic_error {"routes must be registered before the inventory sync server is started"};
        }
        m_impl->state->routes.push_back(Route {method, path, std::move(handler), countAgainstBudget});
    }

    void AsioUdsHttpServer::start(const UdsHttpServerConfig& config)
    {
        if (m_impl->lifecycle.load() != Impl::State::Idle)
        {
            throw std::logic_error {"the inventory sync server is already started"};
        }

        m_impl->state->config = config;
        m_impl->socketPath = config.socketPath;

        m_impl->state->perRequestOverhead = perRequestOverhead(m_impl->state->config);

        if (m_impl->state->config.maxInFlightBytes > 0)
        {
            if (m_impl->state->config.maxBodySize != UdsHttpServerConfig::UNLIMITED_BODY_SIZE)
            {
                // Explicit body cap: a budget below one maximum-size body would reject every
                // request, so clamp it up and say so rather than silently serving nothing.
                const auto floorBytes = m_impl->state->config.maxBodySize + m_impl->state->perRequestOverhead;
                if (m_impl->state->config.maxInFlightBytes < floorBytes)
                {
                    LOGFN_WARN(logFn(),
                               "The in-flight byte budget (%zu) is below one maximum-size request (%zu); raising it, "
                               "otherwise every request would be rejected.",
                               m_impl->state->config.maxInFlightBytes,
                               floorBytes);
                    m_impl->state->config.maxInFlightBytes = floorBytes;
                }
            }
            else
            {
                // No body cap of its own (the default): the in-flight budget IS the effective
                // session limit. Feeding it to the parser turns "declares more than could EVER be
                // admitted" into a 413 at headers-complete -- a contract error the peer must fix by
                // splitting the session -- instead of an eternal 503 the peer would retry forever.
                constexpr std::size_t MIN_UNCAPPED_BODY {1024U * 1024U};
                if (m_impl->state->config.maxInFlightBytes < m_impl->state->perRequestOverhead + MIN_UNCAPPED_BODY)
                {
                    LOGFN_WARN(logFn(),
                               "The in-flight byte budget (%zu) cannot fit one request's fixed overhead (%zu) plus a "
                               "minimal body; raising it, otherwise every request would be rejected.",
                               m_impl->state->config.maxInFlightBytes,
                               m_impl->state->perRequestOverhead);
                    m_impl->state->config.maxInFlightBytes = m_impl->state->perRequestOverhead + MIN_UNCAPPED_BODY;
                }
                m_impl->state->config.maxBodySize =
                    m_impl->state->config.maxInFlightBytes - m_impl->state->perRequestOverhead;
            }
        }
        m_impl->state->budget = std::make_unique<InFlightBudget>(m_impl->state->config.maxInFlightBytes);

        m_impl->acceptorStrand.emplace(asio::make_strand(m_impl->runtime->ioc));
        m_impl->acceptor.emplace(*m_impl->acceptorStrand);

        // Throws on failure, before any thread exists, so a failed start leaves nothing running and
        // the caller's retry loop can simply try again.
        m_impl->bindAcceptor();

        m_impl->work.emplace(asio::make_work_guard(m_impl->runtime->ioc));
        m_impl->state->accepting.store(true, std::memory_order_release);
        m_impl->lifecycle.store(Impl::State::Running);

        const auto threadCount = m_impl->state->config.ioThreads > 0 ? m_impl->state->config.ioThreads
                                                                     : static_cast<std::size_t>(cpp_get_nproc());
        m_impl->threads.reserve(threadCount);
        for (std::size_t i = 0; i < threadCount; ++i)
        {
            m_impl->threads.emplace_back(
                [impl = m_impl.get()]
                {
                    // First use allocates LogFn's static; doing it here keeps the catch blocks below
                    // allocation-free.
                    logFn();

                    // Re-enter run() after an exception instead of letting the thread die. Letting it
                    // die would silently shrink the reactor -- the server would keep answering, just
                    // more slowly, with nothing in the log tying the two together. Throttled: a
                    // condition that repeats fires once per queued handler, at CPU speed.
                    for (;;)
                    {
                        try
                        {
                            impl->runtime->ioc.run();
                            break;
                        }
                        // LCOV_EXCL_START -- every handler posted to the reactor carries its own
                        // barrier, so only an allocation failure inside asio itself lands here
                        catch (const std::exception& e)
                        {
                            if (const auto decision = impl->ioThreadResumeThrottle.record())
                            {
                                LOGFN_ERROR(logFn(),
                                            "The inventory sync server's I/O threads caught %llu exception(s) in the "
                                            "last %d s and resumed (last: %s).",
                                            static_cast<unsigned long long>(decision.total),
                                            common::LogThrottle::kDefaultWindowSeconds,
                                            e.what());
                            }
                        }
                        catch (...)
                        {
                            if (const auto decision = impl->ioThreadResumeThrottle.record())
                            {
                                LOGFN_ERROR(logFn(),
                                            "The inventory sync server's I/O threads caught %llu exception(s) in the "
                                            "last %d s and resumed (last: non-standard exception).",
                                            static_cast<unsigned long long>(decision.total),
                                            common::LogThrottle::kDefaultWindowSeconds);
                            }
                        }
                        // LCOV_EXCL_STOP
                    }

                    impl->threadsExited.fetch_add(1);
                    try
                    {
                        std::lock_guard<std::mutex> lock {impl->threadMutex};
                    }
                    catch (...) // LCOV_EXCL_LINE -- mutex::lock() failure is not stageable from a test
                    {
                    }
                    impl->threadCv.notify_all();
                });
        }

        for (std::size_t i = 0; i < m_impl->state->config.concurrentAccepts; ++i)
        {
            asio::post(*m_impl->acceptorStrand, [impl = m_impl.get()]() { impl->doAccept(); });
        }

        // The one always-visible record of the effective transport configuration; the C shim only
        // reports it at debug level.
        LOGFN_INFO(logFn(),
                   "inventory sync server bound to '%s' (mode %04o, %zu I/O thread(s), %zu concurrent accept(s), "
                   "max %zu connection(s), %zu byte in-flight budget, %zu byte body cap, %zu byte per-request "
                   "overhead; timeouts s: header=%zu body=%zu response=%zu write=%zu drain=%zu).",
                   m_impl->socketPath.c_str(),
                   m_impl->state->config.socketMode,
                   threadCount,
                   m_impl->state->config.concurrentAccepts,
                   m_impl->state->config.maxConnections,
                   m_impl->state->config.maxInFlightBytes,
                   m_impl->state->config.maxBodySize,
                   m_impl->state->perRequestOverhead,
                   m_impl->state->config.headerTimeoutSec,
                   m_impl->state->config.bodyTimeoutSec,
                   m_impl->state->config.responseTimeoutSec,
                   m_impl->state->config.writeTimeoutSec,
                   m_impl->state->config.drainTimeoutSec);
    }

    void AsioUdsHttpServer::stopAccepting() noexcept
    {
        m_impl->doStopAccepting();
    }

    void AsioUdsHttpServer::stop() noexcept
    {
        m_impl->doStop();
    }

    std::unique_ptr<IUdsHttpServer> makeUdsHttpServer()
    {
        return std::make_unique<AsioUdsHttpServer>();
    }

} // namespace invsync::http
