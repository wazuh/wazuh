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

#include "deferredForwarder.hpp"

#include "common/logThrottle.hpp"
#include "loggerHelper.h"

#include <asio/post.hpp>
#include <asio/thread_pool.hpp>

#include <array>
#include <cstddef>
#include <string_view>
#include <utility>

namespace remoted::downstream
{
    namespace
    {
        constexpr auto DEFERRED_FORWARDER_LOGTAG {"wazuh-manager-remoted:forwarder"};

        // One shared instance instead of a `LogFn {TAG}` temporary per log call, which would
        // heap-allocate every time (LogFn holds a std::string and this tag is past the SSO
        // threshold). loggerHelper.h still stays out of deferredForwarder.hpp, which the tests
        // include -- see auth/keystore.cpp for why that matters.
        const LogFn& logFn()
        {
            static const LogFn instance {DEFERRED_FORWARDER_LOGTAG};
            return instance;
        }

        remoted::http::HttpResponse serviceUnavailable()
        {
            remoted::http::HttpResponse response {503, R"({"error":"Service unavailable","code":503})", {}};
            response.headers.emplace_back("Content-Type", "application/json");
            return response;
        }

        remoted::http::HttpResponse internalError()
        {
            remoted::http::HttpResponse response {500, R"({"error":"Internal server error","code":500})", {}};
            response.headers.emplace_back("Content-Type", "application/json");
            return response;
        }

        // Number of throttle slots: one per DownstreamError value, so a permanently-failing
        // condition (e.g. the engine socket is absent) can never mask a newly-appearing, different
        // one (e.g. responses suddenly getting truncated).
        constexpr std::size_t kDownstreamErrorCount {static_cast<std::size_t>(DownstreamError::ResponseTooLarge) + 1};

        // The operator-facing half of each downstream failure: what to check, and which tunable
        // governs it. Kept next to the error taxonomy so adding an enumerator forces a decision
        // about what to tell the operator.
        const char* remediationFor(DownstreamError error)
        {
            switch (error)
            {
                case DownstreamError::Connect:
                    return "Check that the downstream service is running and listening on that socket.";
                case DownstreamError::ConnectTimeout:
                    return "Consider increasing the value of 'downstream_connect_timeout'.";
                case DownstreamError::WriteTimeout:
                    return "The downstream service is not draining its socket. Consider increasing the value of "
                           "'downstream_write_timeout'.";
                case DownstreamError::ResponseTimeout:
                    return "Consider increasing the value of 'downstream_response_timeout'.";
                case DownstreamError::Transport: return "The connection broke mid-exchange.";
                case DownstreamError::Protocol:
                    return "The downstream service answered something that is not valid HTTP.";
                case DownstreamError::ResponseTooLarge:
                    return "Consider increasing the value of 'downstream_max_response_body_size'.";
                case DownstreamError::None: break;
            }
            return "";
        }
    } // namespace

    struct DeferredForwarder::Impl
    {
        Impl(std::shared_ptr<IDownstreamClient> downstreamClient,
             std::shared_ptr<DeferredWorkLimiter> workLimiter,
             std::size_t postProcessThreads)
            : client {std::move(downstreamClient)}
            , limiter {std::move(workLimiter)}
            , postPool {postProcessThreads == 0 ? std::size_t {1} : postProcessThreads}
        {
        }

        std::shared_ptr<IDownstreamClient> client;
        std::shared_ptr<DeferredWorkLimiter> limiter;
        asio::thread_pool postPool;

        /// Both of these fire once per affected request, so under a real outage or burst they would
        /// otherwise write one identical line per event. Throttled, with the count in the message.
        remoted::common::LogThrottle slotExhaustedThrottle;
        std::array<remoted::common::LogThrottle, kDownstreamErrorCount> downstreamErrorThrottles;
        /// 404/405 from a downstream service: a route contract mismatch between remoted and that
        /// service. The endpoints collapse it into the same 503 the agent retries forever, so this
        /// line is the only trace of it anywhere.
        remoted::common::LogThrottle routeMismatchThrottle;
    };

    DeferredForwarder::DeferredForwarder(std::shared_ptr<IDownstreamClient> client,
                                         std::shared_ptr<DeferredWorkLimiter> limiter,
                                         std::size_t postProcessThreads)
        : m_impl {std::make_unique<Impl>(std::move(client), std::move(limiter), postProcessThreads)}
    {
    }

    DeferredForwarder::~DeferredForwarder()
    {
        // A destructor is implicitly noexcept and this one runs during the facade's teardown while
        // the lifecycle mutex is held: a std::system_error out of join() would terminate the daemon
        // mid-shutdown instead of stopping it.
        try
        {
            m_impl->postPool.join(); // drain in-flight post-processing (the client must already be stopped)
        }
        catch (const std::exception& e)
        {
            LOGFN_ERROR(logFn(), "Failure while draining the post-processing pool: %s.", e.what());
        }
        catch (...)
        {
            LOGFN_ERROR(logFn(), "Non-standard exception while draining the post-processing pool.");
        }
    }

    void DeferredForwarder::forward(std::shared_ptr<const remoted::auth::AuthenticatedRequest> req,
                                    std::shared_ptr<remoted::http::IHttpResponder> responder,
                                    DownstreamTarget target,
                                    PostProcessor postProcess)
    {
        auto slot = m_impl->limiter->tryAcquire();
        if (!slot)
        {
            // Too many requests already awaiting downstream: shed with a plain 503 (the agent retries).
            if (const auto shed = m_impl->slotExhaustedThrottle.record())
            {
                LOGFN_WARN(logFn(),
                           "Deferred-work slots exhausted (capacity %zu): shed %llu request(s) with 503 in the last "
                           "%d s. Consider increasing the value of 'max_deferred_requests', or investigate why the "
                           "downstream service is not keeping up.",
                           m_impl->limiter->capacity(),
                           static_cast<unsigned long long>(shed.total),
                           remoted::common::LogThrottle::kDefaultWindowSeconds);
            }
            responder->send(serviceUnavailable());
            return;
        }

        // Capture the body view BEFORE moving `req` into the client's keep-alive.
        const std::string_view body = req->payload.bytes();

        // The slot is move-only; wrap it so the (copyable) std::function callback can carry it. It is
        // released when the post-processing task that finally answers is destroyed.
        auto slotPtr = std::make_shared<DeferredWorkLimiter::Slot>(std::move(*slot));

        DownstreamRequest downstreamRequest;
        downstreamRequest.socketPath = std::move(target.socketPath);
        downstreamRequest.method = target.method;
        downstreamRequest.path = std::move(target.path);
        downstreamRequest.contentType = std::move(target.contentType);
        downstreamRequest.headers = std::move(target.headers);
        downstreamRequest.body = body;
        downstreamRequest.responseTimeoutMs = target.responseTimeoutMs;

        auto* postPool = &m_impl->postPool;
        auto* errorThrottles = &m_impl->downstreamErrorThrottles;
        auto* routeMismatchThrottle = &m_impl->routeMismatchThrottle;
        // A string LITERAL, so capturing it below stays allocation-free (see DownstreamTarget).
        const char* const serviceName = target.serviceName;
        m_impl->client->sendAsync(
            std::move(downstreamRequest),
            /*bodyKeepAlive=*/std::move(req),
            [responder, slotPtr, postProcess, postPool, errorThrottles, routeMismatchThrottle, serviceName](
                DownstreamError error, DownstreamResponse response)
            {
                // Diagnose the failure HERE, where the raw DownstreamError is still available: the
                // endpoint's PostProcessor collapses all of them into one 503, so by the time the
                // agent gets an answer the cause is gone. Logged per error kind (each has its own
                // throttle slot and its own remediation) so a permanent failure cannot mask a new,
                // different one.
                //
                // Deliberately allocation-free: every argument is a literal or an integer. The
                // socket path is not included because it lives in the DownstreamRequest that was
                // just moved into the client, and capturing a copy would cost an allocation on
                // every request just to serve a rare log line. `serviceName` identifies WHICH
                // downstream failed without that cost -- it is a string literal, so capturing it is
                // free. Note the throttle slots are still shared across services (one per error
                // kind, not per service x error), so with several services failing at once only the
                // first one to hit a slot names itself until the window rolls over.
                if (error != DownstreamError::None)
                {
                    auto& throttle = (*errorThrottles)[static_cast<std::size_t>(error)];
                    if (const auto failed = throttle.record())
                    {
                        LOGFN_WARN(logFn(),
                                   "Downstream call to the %s failed (%s) for %llu request(s) in the last %d s; "
                                   "answering 503. %s",
                                   serviceName,
                                   toString(error),
                                   static_cast<unsigned long long>(failed.total),
                                   remoted::common::LogThrottle::kDefaultWindowSeconds,
                                   remediationFor(error));
                    }
                }
                else if (response.status >= 500)
                {
                    // The service answered, but with a server error. Distinct from a transport
                    // failure and worth surfacing, since the endpoint also turns it into a 503.
                    auto& throttle = (*errorThrottles)[static_cast<std::size_t>(DownstreamError::None)];
                    if (const auto failed = throttle.record())
                    {
                        LOGFN_WARN(logFn(),
                                   "The %s answered HTTP %d for %llu request(s) in the last %d s; answering 503.",
                                   serviceName,
                                   response.status,
                                   static_cast<unsigned long long>(failed.total),
                                   remoted::common::LogThrottle::kDefaultWindowSeconds);
                    }
                }
                else if (response.status == 404 || response.status == 405)
                {
                    // A route contract mismatch between remoted and the service: the agent will get
                    // a 503 and retry something that can never succeed, so without this line the
                    // mismatch is invisible in both daemons.
                    if (const auto failed = routeMismatchThrottle->record())
                    {
                        LOGFN_WARN(logFn(),
                                   "The %s answered HTTP %d for %llu request(s) in the last %d s: the request path "
                                   "does not match a route on that service. The two sides are running mismatched "
                                   "versions or configurations; answering 503.",
                                   serviceName,
                                   response.status,
                                   static_cast<unsigned long long>(failed.total),
                                   remoted::common::LogThrottle::kDefaultWindowSeconds);
                    }
                }

                // Offload the (possibly heavy) post-processing off the client's I/O thread. This
                // task runs on DeferredForwarder's own asio::thread_pool, which -- like every
                // asio::thread_pool -- terminates the whole process if an exception escapes a
                // posted handler. postProcess() is endpoint-supplied and may be non-trivial (the
                // README documents it may "inspect the downstream body, apply business logic"),
                // so a throw there (or a bad_alloc from send() under the exact memory pressure
                // this pipeline is designed to survive) must not be allowed to escape.
                asio::post(*postPool,
                           [responder, slotPtr, postProcess, error, response = std::move(response)]
                           {
                               remoted::http::HttpResponse toSend;
                               try
                               {
                                   toSend = postProcess(error, response);
                               }
                               catch (const std::exception& e)
                               {
                                   LOGFN_WARN(logFn(), "PostProcessor threw, answering 500: %s", e.what());
                                   toSend = internalError();
                               }
                               catch (...)
                               {
                                   LOGFN_WARN(logFn(), "PostProcessor threw a non-standard exception, answering 500.");
                                   toSend = internalError();
                               }

                               try
                               {
                                   responder->send(std::move(toSend));
                               }
                               catch (const std::exception& e)
                               {
                                   // send() is send-once; if this itself throws, retrying isn't
                                   // safe (the answered-flag may already be set). Log and stop --
                                   // one dropped response, not a terminated process.
                                   LOGFN_WARN(logFn(), "responder->send() threw: %s", e.what());
                               }
                               catch (...)
                               {
                                   LOGFN_WARN(logFn(), "responder->send() threw a non-standard exception.");
                               }
                           });
            });
    }

} // namespace remoted::downstream
