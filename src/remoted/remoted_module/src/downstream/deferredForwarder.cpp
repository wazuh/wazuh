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

#include "loggerHelper.h"

#include <asio/post.hpp>
#include <asio/thread_pool.hpp>

#include <string_view>
#include <utility>

namespace remoted::downstream
{
    namespace
    {
        constexpr auto DEFERRED_FORWARDER_LOGTAG {"wazuh-manager-remoted:forwarder"};

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
    };

    DeferredForwarder::DeferredForwarder(std::shared_ptr<IDownstreamClient> client,
                                         std::shared_ptr<DeferredWorkLimiter> limiter,
                                         std::size_t postProcessThreads)
        : m_impl {std::make_unique<Impl>(std::move(client), std::move(limiter), postProcessThreads)}
    {
    }

    DeferredForwarder::~DeferredForwarder()
    {
        m_impl->postPool.join(); // drain in-flight post-processing (the client must already be stopped)
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
        downstreamRequest.body = body;

        auto* postPool = &m_impl->postPool;
        m_impl->client->sendAsync(
            std::move(downstreamRequest),
            /*bodyKeepAlive=*/std::move(req),
            [responder, slotPtr, postProcess, postPool](DownstreamError error, DownstreamResponse response)
            {
                // Offload the (possibly heavy) post-processing off the client's I/O thread. This
                // task runs on DeferredForwarder's own asio::thread_pool, which -- like every
                // asio::thread_pool -- terminates the whole process if an exception escapes a
                // posted handler. postProcess() is endpoint-supplied and may be non-trivial (the
                // README documents it may "inspect the downstream body, apply business logic"),
                // so a throw there (or a bad_alloc from send() under the exact memory pressure
                // this pipeline is designed to survive) must not be allowed to escape.
                asio::post(
                    *postPool,
                    [responder, slotPtr, postProcess, error, response = std::move(response)]
                    {
                        remoted::http::HttpResponse toSend;
                        try
                        {
                            toSend = postProcess(error, response);
                        }
                        catch (const std::exception& e)
                        {
                            LOGFN_WARN(
                                LogFn {DEFERRED_FORWARDER_LOGTAG}, "PostProcessor threw, answering 500: %s", e.what());
                            toSend = internalError();
                        }
                        catch (...)
                        {
                            LOGFN_WARN(LogFn {DEFERRED_FORWARDER_LOGTAG},
                                       "PostProcessor threw a non-standard exception, answering 500.");
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
                            LOGFN_WARN(LogFn {DEFERRED_FORWARDER_LOGTAG}, "responder->send() threw: %s", e.what());
                        }
                        catch (...)
                        {
                            LOGFN_WARN(LogFn {DEFERRED_FORWARDER_LOGTAG},
                                       "responder->send() threw a non-standard exception.");
                        }
                    });
            });
    }

} // namespace remoted::downstream
