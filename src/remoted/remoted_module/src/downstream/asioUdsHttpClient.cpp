/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 25, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "asioUdsHttpClient.hpp"

#include "loggerHelper.h"

#include <asio/buffer.hpp>
#include <asio/connect.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>
#include <asio/local/stream_protocol.hpp>
#include <asio/post.hpp>
#include <asio/read.hpp>
#include <asio/steady_timer.hpp>
#include <asio/strand.hpp>
#include <asio/write.hpp>

#include <llhttp.h>

#include <array>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <memory>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace
{
    constexpr auto DOWNSTREAM_LOGTAG {"wazuh-manager-remoted:downstream"};

    // File-local rather than an Impl member: LogFn has hidden ELF visibility (loggerHelper.h wraps
    // everything in a visibility pragma), so holding one as a field of a default-visibility class
    // trips -Wattributes. Also avoids a heap allocation per log call.
    const LogFn& logFn()
    {
        static const LogFn instance {DOWNSTREAM_LOGTAG};
        return instance;
    }

    using stream_protocol = asio::local::stream_protocol;

    const char* methodToString(remoted::http::Method method)
    {
        switch (method)
        {
            case remoted::http::Method::Get: return "GET";
            case remoted::http::Method::Post: return "POST";
            case remoted::http::Method::Put: return "PUT";
            case remoted::http::Method::Delete: return "DELETE";
            case remoted::http::Method::Patch: return "PATCH";
        }
        return "POST";
    }

    std::string buildRequestHead(const remoted::downstream::DownstreamRequest& req, std::size_t bodyLen)
    {
        std::string head {methodToString(req.method)};
        head += ' ';
        head += req.path;
        head += " HTTP/1.1\r\nHost: localhost\r\n";
        if (!req.contentType.empty())
        {
            head += "Content-Type: ";
            head += req.contentType;
            head += "\r\n";
        }
        // Caller-supplied headers, verbatim and in order. Names/values are produced by our own
        // endpoint code (never by the agent), so there is nothing to sanitize here -- but that is
        // exactly why nothing else may be routed through: a CRLF in either half would let the caller
        // inject arbitrary headers into this request.
        for (const auto& [name, value] : req.headers)
        {
            head += name;
            head += ": ";
            head += value;
            head += "\r\n";
        }
        head += "Content-Length: ";
        head += std::to_string(bodyLen);
        head += "\r\nConnection: close\r\n\r\n";
        return head;
    }

    // Cumulative cap on the response's header bytes (names + values). Same rationale as
    // maxResponseBodySize, but headers are protocol plumbing rather than payload, so a fixed
    // constant well above anything a Wazuh service legitimately sends beats another tunable.
    constexpr std::size_t kMaxResponseHeaderBytes {16U * 1024U};

    // Shared, stateless response-parser settings (must outlive every parser -> static). Each parser
    // reaches its owning Session through llhttp_t::data.
    struct SessionParseState
    {
        std::string* body {nullptr};
        bool* messageComplete {nullptr};
        std::size_t* maxBodySize {nullptr};

        // Header capture. llhttp streams names/values in fragments (a header may be split across
        // reads), so both halves accumulate here and the pair is committed on the value->field
        // transition and at on_headers_complete.
        std::vector<std::pair<std::string, std::string>>* headers {nullptr};
        std::string headerName;
        std::string headerValue;
        bool headerValueSeen {false}; ///< The fragment stream is currently inside a value.
        std::size_t headerBytes {0};  ///< Cumulative name+value bytes, checked against the cap.
    };

    void commitHeader(SessionParseState& state)
    {
        if (state.headerValueSeen)
        {
            // Lower-cased like HttpRequest::headers, so consumers do one exact lookup instead of a
            // case-insensitive scan (header names are case-insensitive per RFC 9110).
            for (auto& c : state.headerName)
            {
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }
            state.headers->emplace_back(std::move(state.headerName), std::move(state.headerValue));
            state.headerName.clear();
            state.headerValue.clear();
            state.headerValueSeen = false;
        }
    }

    const llhttp_settings_t* responseSettings()
    {
        static const llhttp_settings_t settings = []
        {
            llhttp_settings_t s;
            llhttp_settings_init(&s);
            s.on_header_field = [](llhttp_t* parser, const char* at, std::size_t len) -> int
            {
                auto* state = static_cast<SessionParseState*>(parser->data);
                commitHeader(*state); // a new field fragment after a value closes the previous pair
                state->headerBytes += len;
                if (state->headerBytes > kMaxResponseHeaderBytes)
                {
                    return HPE_USER;
                }
                state->headerName.append(at, len);
                return 0;
            };
            s.on_header_value = [](llhttp_t* parser, const char* at, std::size_t len) -> int
            {
                auto* state = static_cast<SessionParseState*>(parser->data);
                state->headerValueSeen = true;
                state->headerBytes += len;
                if (state->headerBytes > kMaxResponseHeaderBytes)
                {
                    return HPE_USER;
                }
                state->headerValue.append(at, len);
                return 0;
            };
            s.on_headers_complete = [](llhttp_t* parser) -> int
            {
                commitHeader(*static_cast<SessionParseState*>(parser->data));
                return 0;
            };
            s.on_body = [](llhttp_t* parser, const char* at, std::size_t len) -> int
            {
                auto* state = static_cast<SessionParseState*>(parser->data);
                *state->body += std::string_view {at, len};
                // HPE_USER: llhttp's documented sentinel for a callback-signaled abort (distinct
                // from a genuine protocol error) -- caps a misbehaving/compromised local downstream
                // service's response, symmetric with the byte budget on the inbound agent path.
                return state->body->size() > *state->maxBodySize ? HPE_USER : 0;
            };
            s.on_message_complete = [](llhttp_t* parser) -> int
            {
                *static_cast<SessionParseState*>(parser->data)->messageComplete = true;
                return 0;
            };
            return s;
        }();
        return &settings;
    }
} // namespace

namespace remoted::downstream
{
    namespace
    {
        using Millis = std::chrono::milliseconds;

        /**
         * @brief One in-flight downstream call. Kept alive by the shared_ptr captured in every async
         *        handler; all handlers run on the Session's strand, so its members need no locking.
         */
        class Session final : public std::enable_shared_from_this<Session>
        {
        public:
            Session(asio::io_context& ioc,
                    DownstreamRequest request,
                    std::shared_ptr<const void> bodyKeepAlive,
                    DownstreamCallback onComplete,
                    Millis connectTimeout,
                    Millis writeTimeout,
                    Millis responseTimeout,
                    std::size_t maxResponseBodySize)
                : m_strand {asio::make_strand(ioc)}
                , m_socket {m_strand}
                , m_timer {m_strand}
                , m_request {std::move(request)}
                , m_bodyKeepAlive {std::move(bodyKeepAlive)}
                , m_onComplete {std::move(onComplete)}
                , m_connectTimeout {connectTimeout}
                , m_writeTimeout {writeTimeout}
                , m_responseTimeout {responseTimeout}
                , m_maxResponseBodySize {maxResponseBodySize}
                , m_head {buildRequestHead(m_request, m_request.body.size())}
            {
                m_parseState.body = &m_respBody;
                m_parseState.messageComplete = &m_messageComplete;
                m_parseState.maxBodySize = &m_maxResponseBodySize;
                m_parseState.headers = &m_respHeaders;
                llhttp_init(&m_parser, HTTP_RESPONSE, responseSettings());
                m_parser.data = &m_parseState;
            }

            asio::strand<asio::io_context::executor_type>& strand() noexcept
            {
                return m_strand;
            }

            void start()
            {
                auto self = shared_from_this();
                armTimer(Phase::Connect, m_connectTimeout);
                m_socket.async_connect(stream_protocol::endpoint {m_request.socketPath},
                                       [self](const std::error_code& ec) { self->onConnect(ec); });
            }

        private:
            // Which deadline the timer is currently enforcing. Tracked explicitly rather than
            // inferred from which handler observed operation_aborted: that inference happens to be
            // correct today (onRead is only reachable after the response timer is armed), but it is
            // exactly the kind of implicit invariant a later refactor breaks silently.
            enum class Phase
            {
                Connect,
                Write,
                Response
            };

            static DownstreamError timeoutErrorFor(Phase phase)
            {
                switch (phase)
                {
                    case Phase::Connect: return DownstreamError::ConnectTimeout;
                    case Phase::Write: return DownstreamError::WriteTimeout;
                    case Phase::Response: return DownstreamError::ResponseTimeout;
                }
                return DownstreamError::ResponseTimeout;
            }

            void armTimer(Phase phase, Millis timeout)
            {
                m_phase = phase;
                auto self = shared_from_this();
                m_timer.expires_after(timeout);
                m_timer.async_wait(
                    [self](const std::error_code& ec)
                    {
                        if (ec)
                        {
                            return; // timer cancelled
                        }
                        self->m_timedOut = true;
                        std::error_code ignore;
                        self->m_socket.close(ignore); // aborts pending I/O -> handlers see operation_aborted
                    });
            }

            void onConnect(const std::error_code& ec)
            {
                if (m_finished)
                {
                    return;
                }
                m_timer.cancel();
                if (ec)
                {
                    finish(m_timedOut ? timeoutErrorFor(m_phase) : DownstreamError::Connect, {});
                    return;
                }
                // Cover the write phase too: without an active timer here, a downstream peer that
                // accepts the connection but never drains its socket (kernel send buffer full) can
                // hang async_write indefinitely, pinning this request's deferred-work slot and byte
                // reservation forever. doWrite()'s completion re-arms the timer for the response
                // phase, so this timer stays live end-to-end across every phase.
                armTimer(Phase::Write, m_writeTimeout);
                doWrite();
            }

            void doWrite()
            {
                auto self = shared_from_this();
                m_writeBuffers = {asio::buffer(m_head), asio::buffer(m_request.body.data(), m_request.body.size())};
                asio::async_write(m_socket,
                                  m_writeBuffers,
                                  [self](const std::error_code& ec, std::size_t)
                                  {
                                      // Send complete (or failed): the body has left our hands, so
                                      // release the payload keep-alive NOW (frees buffer + budget).
                                      self->m_bodyKeepAlive.reset();
                                      if (self->m_finished)
                                      {
                                          return;
                                      }
                                      if (ec)
                                      {
                                          self->finish(self->m_timedOut ? timeoutErrorFor(self->m_phase)
                                                                        : DownstreamError::Transport,
                                                       {});
                                          return;
                                      }
                                      self->armTimer(Phase::Response, self->m_responseTimeout);
                                      self->doRead();
                                  });
            }

            void doRead()
            {
                auto self = shared_from_this();
                m_socket.async_read_some(asio::buffer(m_readBuffer),
                                         [self](const std::error_code& ec, std::size_t n) { self->onRead(ec, n); });
            }

            void onRead(const std::error_code& ec, std::size_t n)
            {
                if (m_finished)
                {
                    return;
                }

                if (!ec)
                {
                    const auto parseResult = llhttp_execute(&m_parser, m_readBuffer.data(), n);
                    if (parseResult != HPE_OK)
                    {
                        finish(parseResult == HPE_USER ? DownstreamError::ResponseTooLarge : DownstreamError::Protocol,
                               {});
                        return;
                    }
                    if (m_messageComplete)
                    {
                        complete();
                        return;
                    }
                    doRead();
                }
                else if (ec == asio::error::eof)
                {
                    llhttp_finish(&m_parser);
                    if (m_messageComplete)
                    {
                        complete();
                    }
                    else
                    {
                        finish(DownstreamError::Protocol, {});
                    }
                }
                else if (ec == asio::error::operation_aborted)
                {
                    if (m_timedOut)
                    {
                        finish(timeoutErrorFor(m_phase), {});
                    }
                    // otherwise aborted by finish()/close -> nothing to do
                }
                else
                {
                    finish(DownstreamError::Transport, {});
                }
            }

            void complete()
            {
                DownstreamResponse response;
                response.status = static_cast<int>(m_parser.status_code);
                response.body = std::move(m_respBody);
                response.headers = std::move(m_respHeaders);
                finish(DownstreamError::None, std::move(response));
            }

            void finish(DownstreamError error, DownstreamResponse response)
            {
                if (m_finished)
                {
                    return; // exactly-once (handlers are serialized by the strand)
                }
                m_finished = true;

                std::error_code ignore;
                m_timer.cancel();
                m_socket.close(ignore);
                m_bodyKeepAlive.reset();

                auto callback = std::move(m_onComplete);
                if (callback)
                {
                    callback(error, std::move(response));
                }
            }

            asio::strand<asio::io_context::executor_type> m_strand;
            stream_protocol::socket m_socket;
            asio::steady_timer m_timer;
            DownstreamRequest m_request;
            std::shared_ptr<const void> m_bodyKeepAlive;
            DownstreamCallback m_onComplete;
            Millis m_connectTimeout;
            Millis m_writeTimeout;
            Millis m_responseTimeout;
            std::size_t m_maxResponseBodySize;
            std::string m_head;
            std::array<asio::const_buffer, 2> m_writeBuffers {};
            std::array<char, 8192> m_readBuffer {};
            std::string m_respBody;
            std::vector<std::pair<std::string, std::string>> m_respHeaders;
            llhttp_t m_parser {};
            SessionParseState m_parseState {};
            bool m_messageComplete {false};
            Phase m_phase {Phase::Connect}; ///< Which deadline armTimer() last armed.
            bool m_timedOut {false};
            bool m_finished {false};
        };
    } // namespace

    struct AsioUdsHttpClient::Impl
    {
        explicit Impl(DownstreamConfig cfg)
            : config {std::move(cfg)}
            , work {asio::make_work_guard(ioc)}
        {
        }

        DownstreamConfig config;
        asio::io_context ioc;
        asio::executor_work_guard<asio::io_context::executor_type> work;
        std::vector<std::thread> threads;
    };

    AsioUdsHttpClient::AsioUdsHttpClient(DownstreamConfig config)
        : m_impl {std::make_unique<Impl>(std::move(config))}
    {
    }

    AsioUdsHttpClient::~AsioUdsHttpClient()
    {
        stop();
    }

    void AsioUdsHttpClient::start()
    {
        if (!m_impl->threads.empty())
        {
            return; // already started
        }

        const auto count = m_impl->config.ioThreads == 0 ? std::size_t {1} : m_impl->config.ioThreads;
        m_impl->threads.reserve(count);
        for (std::size_t i = 0; i < count; ++i)
        {
            // Defense in depth: nothing in Session is expected to throw, but a bare std::thread
            // (unlike asio::thread_pool, which terminates with a clear message) would otherwise
            // fall back to the standard "uncaught exception escaping a thread" rule on any throw.
            m_impl->threads.emplace_back(
                [this]
                {
                    try
                    {
                        m_impl->ioc.run();
                    }
                    catch (const std::exception& e)
                    {
                        LOGFN_ERROR(
                            logFn(), "Downstream UDS client I/O thread ended on an unexpected exception: %s", e.what());
                    }
                    catch (...)
                    {
                        LOGFN_ERROR(logFn(), "Downstream UDS client I/O thread ended on a non-standard exception.");
                    }
                });
        }

        LOGFN_INFO(logFn(), "Downstream UDS client started (%zu I/O thread(s)).", count);
    }

    void AsioUdsHttpClient::stop() noexcept
    {
        if (m_impl->threads.empty())
        {
            return;
        }

        // noexcept, and reached from ~AsioUdsHttpClient() as well as the facade's teardown:
        // thread::join() can throw std::system_error, which would terminate the daemon mid-shutdown.
        try
        {
            m_impl->work.reset();
            m_impl->ioc.stop();
            for (auto& thread : m_impl->threads)
            {
                if (thread.joinable())
                {
                    thread.join();
                }
            }
        }
        catch (const std::exception& e)
        {
            LOGFN_ERROR(logFn(), "Failure while stopping the downstream UDS client: %s.", e.what());
        }
        catch (...)
        {
            LOGFN_ERROR(logFn(), "Non-standard exception while stopping the downstream UDS client.");
        }

        m_impl->threads.clear();
    }

    void AsioUdsHttpClient::sendAsync(DownstreamRequest req,
                                      std::shared_ptr<const void> bodyKeepAlive,
                                      DownstreamCallback onComplete)
    {
        // Resolve every per-request override BEFORE `req` is moved into the Session. Reading
        // req.responseTimeoutMs inside the same argument list as std::move(req) would be a
        // sequencing bug: function arguments are only indeterminately sequenced (C++17
        // [expr.call]/8), so the read may be ordered after the move. It would appear to work today
        // purely because moving a DownstreamRequest leaves its int members intact -- which is
        // exactly what would make it break silently if this field ever became a non-trivial type.
        const int responseTimeoutMs =
            req.responseTimeoutMs > 0 ? req.responseTimeoutMs : m_impl->config.responseTimeoutMs;

        auto session = std::make_shared<Session>(m_impl->ioc,
                                                 std::move(req),
                                                 std::move(bodyKeepAlive),
                                                 std::move(onComplete),
                                                 Millis {m_impl->config.connectTimeoutMs},
                                                 Millis {m_impl->config.writeTimeoutMs},
                                                 Millis {responseTimeoutMs},
                                                 m_impl->config.maxResponseBodySize);

        // Run the whole state machine on the session's strand.
        asio::post(session->strand(), [session] { session->start(); });
    }

} // namespace remoted::downstream
