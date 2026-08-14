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

#ifndef _REMOTED_DOWNSTREAM_I_CLIENT_HPP
#define _REMOTED_DOWNSTREAM_I_CLIENT_HPP

#include "http_server/IHttpServer.hpp" // remoted::http::Method

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace remoted::downstream
{

    /**
     * @brief Why a downstream call did not yield a response (None == got an HTTP response).
     *
     * The three timeouts are distinct on purpose: they map to three different tunables
     * (downstream_connect_timeout / _write_timeout / _response_timeout) and to three genuinely
     * different diagnoses -- "the service isn't listening", "the service isn't draining its
     * socket", "the service is too slow to answer". Collapsing them into one value made a log line
     * unable to tell the operator which knob to touch. This is manager-internal detail: the status
     * an agent sees stays the same for all of them (see endpoints::stateless::postProcess).
     */
    enum class DownstreamError
    {
        None,
        Connect,          ///< Could not connect to the socket (nothing listening / refused).
        ConnectTimeout,   ///< The connect deadline elapsed.
        WriteTimeout,     ///< The request-body send deadline elapsed (peer not reading).
        ResponseTimeout,  ///< The post-send response deadline elapsed.
        Transport,        ///< Socket read/write error or unexpected close.
        Protocol,         ///< The response was not valid HTTP.
        ResponseTooLarge, ///< The response body exceeded DownstreamConfig::maxResponseBodySize.
    };

    /// @brief Stable lowercase tag for logging. Never null; "unknown" for an out-of-range value.
    const char* toString(DownstreamError error);

    /// @brief The downstream service's HTTP response (valid when DownstreamError::None).
    struct DownstreamResponse
    {
        int status {0};
        std::string body;
        /// Response headers as they came off the wire, in order, with names lower-cased (values
        /// verbatim). Capped by the client (see kMaxResponseHeaderBytes in asioUdsHttpClient.cpp) so
        /// a misbehaving local service cannot grow this unboundedly. What -- if anything -- gets
        /// reflected to the agent is each endpoint's PostProcessor's decision: /stateful forwards
        /// only Retry-After (the one header in the sync contract), everything else stays internal.
        std::vector<std::pair<std::string, std::string>> headers;
    };

    /**
     * @brief One outbound request. `socketPath` is per-request, so a single client can talk to
     *        several UDS services; `body` is a view into the caller's buffer (kept alive by the
     *        bodyKeepAlive passed to sendAsync until the send completes).
     */
    struct DownstreamRequest
    {
        std::string socketPath;
        remoted::http::Method method {remoted::http::Method::Post};
        std::string path;
        std::string contentType;
        /// Extra request headers, written verbatim in order after Content-Type. Content-Length,
        /// Host and Connection are produced by the client and must NOT be supplied here.
        ///
        /// This is how per-request context that is not part of the body reaches a downstream
        /// service -- e.g. the authenticated agent id, which /stats and /config forward as `X-Wazuh-Agent-Id`.
        std::vector<std::pair<std::string, std::string>> headers;
        std::string_view body;
        /// Per-request response deadline, ms. <=0 -> DownstreamConfig::responseTimeoutMs (the global
        /// default). Lets one endpoint wait minutes for a slow async handler without forcing every
        /// other endpoint to tolerate the same delay before a hung downstream is detected.
        int responseTimeoutMs {0};
    };

    /// @brief Delivered exactly once, on an internal I/O thread, when the response arrives or on error.
    using DownstreamCallback = std::function<void(DownstreamError, DownstreamResponse)>;

    /**
     * @brief Transport-agnostic async client for forwarding a request over a Unix-domain HTTP socket.
     *
     * Contract: `sendAsync` returns immediately. The implementation holds `bodyKeepAlive` only until
     * the request body has been fully written (send complete) and then drops it -- that is what frees
     * the caller's payload (and its in-flight byte reservation) at send time, before the response is
     * awaited. `onComplete` is invoked exactly once.
     */
    class IDownstreamClient
    {
    public:
        virtual ~IDownstreamClient() = default;

        virtual void
        sendAsync(DownstreamRequest req, std::shared_ptr<const void> bodyKeepAlive, DownstreamCallback onComplete) = 0;
    };

} // namespace remoted::downstream

#endif // _REMOTED_DOWNSTREAM_I_CLIENT_HPP
