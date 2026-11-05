/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_DOWNSTREAM_BLOCKING_CALL_HPP
#define _REMOTED_DOWNSTREAM_BLOCKING_CALL_HPP

#include "IDownstreamClient.hpp"

#include <chrono>
#include <memory>

namespace remoted::downstream
{

    /// @brief Outcome of sendBlocking(): the client's error and, when it is None, the response.
    struct BlockingResult
    {
        DownstreamError error {DownstreamError::Transport};
        DownstreamResponse response;
    };

    /**
     * @brief Send one request through an async client and wait for its completion.
     *
     * For callers that must answer synchronously. The wait is always bounded, so a caller can never
     * outlive the client it waits on:
     *  - a completion callback the client drops without running it (the client was stopped, or
     *    destroyed with the request still queued) comes back as Transport at once;
     *  - `backstop` caps the wait in any case, also as Transport. Pass the request's own connect +
     *    write + response deadlines plus a margin, so a healthy client always answers first.
     * Never throws: a failure to even hand the request to the client is a Transport error too.
     *
     * @param client Client to send through (must outlive the call).
     * @param request The request; its body must stay valid until the call returns.
     * @param bodyKeepAlive Optional owner of the body, handed to the client as is.
     * @param backstop Upper bound of the wait.
     */
    BlockingResult sendBlocking(IDownstreamClient& client,
                                DownstreamRequest request,
                                std::shared_ptr<const void> bodyKeepAlive,
                                std::chrono::milliseconds backstop) noexcept;

} // namespace remoted::downstream

#endif // _REMOTED_DOWNSTREAM_BLOCKING_CALL_HPP
