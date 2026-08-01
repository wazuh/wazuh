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

#ifndef _REMOTED_DOWNSTREAM_DEFERRED_FORWARDER_HPP
#define _REMOTED_DOWNSTREAM_DEFERRED_FORWARDER_HPP

#include "IDownstreamClient.hpp"
#include "auth/authTypes.hpp"          // remoted::auth::AuthenticatedRequest
#include "deferredWorkLimiter.hpp"     // remoted::downstream::DeferredWorkLimiter
#include "http_server/IHttpServer.hpp" // remoted::http::{HttpResponse,IHttpResponder,Method}

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace remoted::downstream
{

    /// @brief Where to forward: a per-endpoint UDS socket + HTTP method/path/content-type.
    struct DownstreamTarget
    {
        std::string socketPath;
        remoted::http::Method method {remoted::http::Method::Post};
        std::string path;
        std::string contentType;
        /// Extra request headers, forwarded verbatim. See DownstreamRequest::headers.
        std::vector<std::pair<std::string, std::string>> headers;
        /**
         * @brief Short, stable name of the downstream service, used ONLY in failure logs.
         *
         * Deliberately a `const char*` pointing at a string literal rather than a std::string: the
         * failure-log lambda captures it by value on EVERY request, and this pipeline's logging is
         * documented as allocation-free on the hot path
         */
        const char* serviceName {"downstream service"};
        /// How long this endpoint is willing to wait for the downstream answer, ms. <=0 -> the
        /// client's configured default (remoted.downstream_response_timeout). This is where an
        /// endpoint whose handler legitimately takes minutes declares that, without relaxing the
        /// deadline for fast endpoints like /stateless.
        ///
        /// @warning A value above `http_request_timeout` cannot take effect: the HTTP server caps
        /// the whole request and will cut it off first. RemotedModuleFacade warns at startup when
        /// the downstream deadlines add up past that cap.
        int responseTimeoutMs {0};
    };

    /**
     * @brief Per-endpoint post-processing of a downstream result.
     *
     * Receives the raw outcome (error + status + body) and produces the response to the agent. May be
     * non-trivial (parse the body, apply business logic, handle errors). Runs on the forwarder's
     * post-processing pool, off the client's I/O threads.
     */
    using PostProcessor = std::function<remoted::http::HttpResponse(DownstreamError, const DownstreamResponse&)>;

    /**
     * @brief Forwards authenticated requests to a downstream UDS service and replies asynchronously.
     *
     * Acquires a DeferredWorkLimiter slot (503 when full), hands the request to the async client
     * (which frees the payload + byte budget once the send completes), and on the response offloads a
     * per-endpoint PostProcessor onto its own thread pool to build and deliver the client reply. One
     * forwarder serves many endpoints and many sockets (each forward() call carries its own target).
     *
     * Teardown: the owning code must stop the client BEFORE destroying the forwarder, so no in-flight
     * completion posts to the (destroyed) post-processing pool.
     */
    class DeferredForwarder final
    {
    public:
        DeferredForwarder(std::shared_ptr<IDownstreamClient> client,
                          std::shared_ptr<DeferredWorkLimiter> limiter,
                          std::size_t postProcessThreads);
        ~DeferredForwarder();

        DeferredForwarder(const DeferredForwarder&) = delete;
        DeferredForwarder& operator=(const DeferredForwarder&) = delete;

        void forward(std::shared_ptr<const remoted::auth::AuthenticatedRequest> req,
                     std::shared_ptr<remoted::http::IHttpResponder> responder,
                     DownstreamTarget target,
                     PostProcessor postProcess);

    private:
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace remoted::downstream

#endif // _REMOTED_DOWNSTREAM_DEFERRED_FORWARDER_HPP
