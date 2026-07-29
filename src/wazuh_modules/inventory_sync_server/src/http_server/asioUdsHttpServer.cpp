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

#include <grp.h>
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
     * @brief Bytes charged to a request on top of its payload.
     *
     * Larger than remoted's equivalent (4 KiB) on purpose: our per-connection state -- read buffer,
     * llhttp state, timer, socket, header map -- stays resident for the WHOLE deferral, whereas
     * RESTinio frees its per-connection state as soon as the handler is posted. Charging for it keeps
     * the byte budget an honest proxy for real memory when hundreds of replies are outstanding.
     */
    constexpr std::size_t PER_REQUEST_OVERHEAD {16U * 1024U};

    /// How long stop() waits for the I/O threads to drain naturally before forcing the issue.
    constexpr auto THREAD_EXIT_GRACE = std::chrono::seconds {2};

    const char* reasonPhrase(int status)
    {
        switch (status)
        {
            case 200: return "OK";
            case 202: return "Accepted";
            case 400: return "Bad Request";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
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

        /**
         * @brief Payload plus its byte reservation, owned together.
         *
         * The handler receives a shared_ptr<const HttpRequest> ALIASED into this object, so dropping
         * the request releases the payload and its reservation in one step -- typically minutes
         * before the reply is sent, since the responder deliberately does not co-own it.
         */
        struct RequestContext
        {
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

            std::atomic_bool accepting {false};

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
         *        handler plus the registry entry; every handler runs on its strand, so its members
         *        need no locking.
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
                // Cancelling the timer is REQUIRED, not tidiness. A pending async_wait holds a
                // shared_ptr to this Session, and the Session holds a shared_ptr to the Runtime that
                // owns the io_context the operation is queued on -- so leaving the wait armed is a
                // reference cycle that neither side can break: the io_context cannot be destroyed
                // because the Session keeps it alive, and the Session cannot be destroyed because the
                // io_context's queue keeps it alive. Cancelling makes the handler run now (with
                // operation_aborted), while the reactor is still alive, and release its reference.
                //
                // Only reachable for a session that is force-closed without ever being answered, which
                // is why udsShutdown_test.cpp's never-answered cases are the ones that caught it -- and
                // only under LeakSanitizer.
                m_timer.cancel();
                closeSocket();
                unregisterSelf();
            }

            bool dispatched() const noexcept
            {
                return m_dispatched;
            }

            /// Called by the responder. Always marshals onto the strand, so Session members stay
            /// single-threaded no matter which thread produced the response.
            void submitResponse(HttpResponse response)
            {
                auto self = shared_from_this();
                asio::post(m_strand,
                           [self, response = std::move(response)]() mutable { self->deliver(std::move(response)); });
            }

            /// Called when a responder is destroyed without ever having sent: a handler bug, answered
            /// 503 so the peer is never left hanging.
            void submitAbandoned()
            {
                auto self = shared_from_this();
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
                                              "%llu request(s) in the last %d s were dropped by their handler without "
                                              "a response and were answered 503. This is a handler bug.",
                                              static_cast<unsigned long long>(decision.total),
                                              common::LogThrottle::kDefaultWindowSeconds);
                               }
                               self->deliver(errorResponse(503, "Handler produced no response"));
                           });
            }

        private:
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

                m_timedOut = true;

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

                // Header/Body/Write: the peer is slow or gone. Nothing useful to say to it.
                m_finished = true;
                closeSocket();
                unregisterSelf();
            }

            void doRead()
            {
                auto self = shared_from_this();
                m_socket.async_read_some(asio::buffer(m_readBuffer.data(), m_readBuffer.size()),
                                         [self](const std::error_code& ec, std::size_t n) { self->onRead(ec, n); });
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
                    auto reserved = m_state->budget->tryReserve(declared + PER_REQUEST_OVERHEAD);
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

                // The payload and its reservation move into a jointly-owned context; the handler
                // gets a view aliased into it, so dropping that view frees both at once.
                auto context = std::make_shared<RequestContext>();
                context->request = std::move(m_parser.request());
                context->reservation = std::move(m_reservation);
                std::shared_ptr<const HttpRequest> request {context, &context->request};

                // The read buffer is dead weight from here on, and it would otherwise stay resident
                // for the whole deferral: 8 KiB x hundreds of pending replies.
                m_readBuffer.clear();
                m_readBuffer.shrink_to_fit();

                armTimer(Phase::Response, std::chrono::seconds {m_state->config.responseTimeoutSec});

                auto responder = std::make_shared<SessionResponder>(m_runtime, weak_from_this(), m_state);

                // Exception barrier. A handler that throws must produce a 500 rather than take the
                // I/O thread -- and therefore the whole daemon -- down with it.
                try
                {
                    m_route->handler(std::move(request), responder);
                }
                catch (const std::exception& e)
                {
                    LOGFN_ERROR(logFn(), "An inventory sync request handler threw: %s. Answering 500.", e.what());
                    responder->send(errorResponse(500, "Internal error"));
                }
                catch (...)
                {
                    LOGFN_ERROR(logFn(),
                                "An inventory sync request handler threw a non-standard exception. "
                                "Answering 500.");
                    responder->send(errorResponse(500, "Internal error"));
                }

                m_state->dispatchesRunning.fetch_sub(1, std::memory_order_relaxed);
                m_state->noteProgress();
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

                m_writeHead = serializeHead(response);
                m_writeBody = std::move(response.body);
                m_writeBuffers = {asio::buffer(m_writeHead), asio::buffer(m_writeBody)};

                armWriteTimer();

                auto self = shared_from_this();
                asio::async_write(m_socket,
                                  m_writeBuffers,
                                  [self](const std::error_code&, std::size_t)
                                  {
                                      self->m_timer.cancel();
                                      self->closeSocket();
                                      self->unregisterSelf();
                                      return;
                                  });
            }

            /*
             * INTEROP NOTE, for the rejections decided at headers-complete (404, 405, 411, 413, 503).
             *
             * The peer writes an entire request before reading any of the response. When we reject at
             * the head and close, a peer that is still sending a large body sees its write fail rather
             * than reading our status -- so it reports a transport error instead of, say, 413.
             *
             * That is accepted deliberately rather than worked around:
             *   - Draining the rest of the body so the peer can read the status means reading, and
             *       discarding, everything it declared. There is no bound on that except the write
             *       deadline, which turns a cheap rejection into an expensive one and hands a client
             *       control over how long we spend on a request we already refused.
             *   - remoted, the only production peer, caps the body on its OWN inbound side and answers
             *       the agent 413 there (see its auth_max_body_size), so an oversized batch never
             *       reaches this socket in a correctly configured manager. It can only happen when
             *       this module's body cap is set BELOW remoted's, which is a misconfiguration worth
             *       fixing rather than absorbing.
             *   - It matches what the rest of the product does: remoted's own inbound server aborts the
             *       parse and closes on an over-cap body too.
             *
             * A small rejected body -- the realistic 404/405 case -- fits in the socket buffer, so the
             * peer reads the status normally. Only a large one is truncated.
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
                        self->m_timedOut = true;
                        self->closeSocket();
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

            InFlightBudget::Reservation m_reservation;
            const Route* m_route {nullptr};
            bool m_pathMatchedOtherMethod {false};

            std::uint64_t m_id {0};
            Phase m_phase {Phase::Header};
            bool m_timedOut {false};
            bool m_finished {false};
            bool m_dispatched {false};
            bool m_unregistered {false};

            std::string m_writeHead;
            std::string m_writeBody;
            std::array<asio::const_buffer, 2> m_writeBuffers {};
        };

        /// Writes a canned response on a socket we are refusing to turn into a Session.
        void writeAndClose(std::shared_ptr<stream_protocol::socket> socket, const HttpResponse& response)
        {
            auto payload = std::make_shared<std::string>(serializeHead(response) + response.body);
            asio::async_write(*socket,
                              asio::buffer(*payload),
                              [socket, payload](const std::error_code&, std::size_t)
                              {
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

            struct stat existing
            {
            };
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
                // EADDRINUSE forever and the module would never come back.
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

            if (!state->config.socketGroup.empty())
            {
                applySocketGroup();
            }
        }

        void applySocketGroup()
        {
            std::array<char, 4096> buffer {};
            ::group groupEntry {};
            ::group* result {nullptr};

            if (::getgrnam_r(state->config.socketGroup.c_str(), &groupEntry, buffer.data(), buffer.size(), &result) !=
                    0 ||
                result == nullptr)
            {
                LOGFN_WARN(logFn(),
                           "Could not resolve group '%s' for '%s'; leaving the socket's group unchanged.",
                           state->config.socketGroup.c_str(),
                           socketPath.c_str());
                return;
            }

            if (::chown(socketPath.c_str(), static_cast<::uid_t>(-1), result->gr_gid) != 0)
            {
                LOGFN_WARN(logFn(),
                           "Could not set group '%s' on '%s': %s.",
                           state->config.socketGroup.c_str(),
                           socketPath.c_str(),
                           std::strerror(errno));
            }
        }

        void doAccept()
        {
            acceptor->async_accept(
                [this](const std::error_code& ec, stream_protocol::socket socket)
                {
                    if (ec)
                    {
                        // operation_aborted is the normal path: stopAccepting() closed the acceptor.
                        return;
                    }

                    onAccepted(std::move(socket));
                    doAccept();
                });
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
                writeAndClose(std::make_shared<stream_protocol::socket>(std::move(socket)),
                              errorResponse(503, "Too many concurrent connections"));
                return;
            }

            auto session = std::make_shared<Session>(runtime, state, std::move(socket));
            state->undispatched.fetch_add(1, std::memory_order_relaxed);

            {
                std::lock_guard<std::mutex> lock {state->registryMutex};
                const auto id = state->nextSessionId++;
                session->setId(id);
                state->sessions.emplace(id, session);
            }

            asio::post(session->strand(), [session]() { session->start(); });
        }

        /// Phase 1. See IUdsHttpServer::stopAccepting() for the guarantees this establishes.
        void doStopAccepting() noexcept
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
                    std::promise<void> closed;
                    auto done = closed.get_future();
                    asio::post(*acceptorStrand,
                               [this, &closed]()
                               {
                                   closeAcceptor();
                                   closed.set_value();
                               });
                    done.wait();
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
                                               std::chrono::seconds {30},
                                               [this]
                                               {
                                                   return state->undispatched.load(std::memory_order_relaxed) == 0 &&
                                                          state->dispatchesRunning.load(std::memory_order_relaxed) == 0;
                                               });
                }

                const auto outstanding = state->liveSessions.load(std::memory_order_relaxed);
                LOGFN_INFO(logFn(),
                           "inventory sync server is no longer accepting on '%s'; %zu deferred repl%s still "
                           "outstanding.",
                           socketPath.c_str(),
                           outstanding,
                           outstanding == 1 ? "y" : "ies");
            }
            catch (...)
            {
                // noexcept by contract. A swallowed exception here makes the "no handler will run
                // again" guarantee best-effort rather than unconditional -- worth stating plainly,
                // though unlike remoted's version it rests on two counters we own rather than on a
                // third-party wait() plus a thread-pool join.
                LOGFN_ERROR(logFn(), "An error occurred while the inventory sync server stopped accepting.");
            }
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
            if (!socketPath.empty())
            {
                ::unlink(socketPath.c_str());
            }
        }

        /// Phase 2. See IUdsHttpServer::stop() for the guarantees this establishes.
        void doStop() noexcept
        {
            doStopAccepting();

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
            catch (...)
            {
                LOGFN_ERROR(logFn(), "An error occurred while the inventory sync server stopped.");
                runtime->ioc.stop();
            }

            joinThreads();
            LOGFN_INFO(logFn(), "inventory sync server fully stopped.");
        }

        void forceCloseAll() noexcept
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
                                           std::chrono::seconds {5},
                                           [this]
                                           {
                                               std::lock_guard<std::mutex> registryLock {state->registryMutex};
                                               return state->sessions.empty();
                                           });
            }

            std::lock_guard<std::mutex> lock {state->registryMutex};
            state->sessions.clear();
        }

        void joinThreads() noexcept
        {
            for (auto& thread : threads)
            {
                if (thread.joinable())
                {
                    thread.join();
                }
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

        // A budget below one maximum-size body would reject every request, so clamp it up and say so
        // rather than silently serving nothing.
        if (m_impl->state->config.maxInFlightBytes > 0)
        {
            const auto floorBytes = m_impl->state->config.maxBodySize + PER_REQUEST_OVERHEAD;
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
                    // Re-enter run() after an exception instead of letting the thread die. Letting it
                    // die would silently shrink the reactor -- the server would keep answering, just
                    // more slowly, with nothing in the log tying the two together.
                    for (;;)
                    {
                        try
                        {
                            impl->runtime->ioc.run();
                            break;
                        }
                        catch (const std::exception& e)
                        {
                            LOGFN_ERROR(logFn(), "An inventory sync server I/O thread caught: %s. Resuming.", e.what());
                        }
                        catch (...)
                        {
                            LOGFN_ERROR(logFn(),
                                        "An inventory sync server I/O thread caught a non-standard exception. "
                                        "Resuming.");
                        }
                    }

                    impl->threadsExited.fetch_add(1);
                    {
                        std::lock_guard<std::mutex> lock {impl->threadMutex};
                    }
                    impl->threadCv.notify_all();
                });
        }

        for (std::size_t i = 0; i < m_impl->state->config.concurrentAccepts; ++i)
        {
            asio::post(*m_impl->acceptorStrand, [impl = m_impl.get()]() { impl->doAccept(); });
        }

        LOGFN_INFO(logFn(),
                   "inventory sync server bound to '%s' (mode %04o, %zu I/O thread(s), max %zu connection(s), "
                   "%zu byte in-flight budget, %zu byte body cap).",
                   m_impl->socketPath.c_str(),
                   m_impl->state->config.socketMode,
                   threadCount,
                   m_impl->state->config.maxConnections,
                   m_impl->state->config.maxInFlightBytes,
                   m_impl->state->config.maxBodySize);
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
