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

namespace remoted::downstream
{

    /// @brief Why a downstream call did not yield a response (None == got an HTTP response).
    enum class DownstreamError
    {
        None,
        Connect,         ///< Could not connect to the socket.
        Timeout,         ///< Connect, write, or response deadline elapsed.
        Transport,       ///< Socket read/write error or unexpected close.
        Protocol,        ///< The response was not valid HTTP.
        ResponseTooLarge ///< The response body exceeded DownstreamConfig::maxResponseBodySize.
    };

    /// @brief The downstream service's HTTP response (valid when DownstreamError::None).
    struct DownstreamResponse
    {
        int status {0};
        std::string body;
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
        std::string_view body;
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
