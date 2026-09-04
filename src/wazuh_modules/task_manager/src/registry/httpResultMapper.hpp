/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TASK_MANAGER_REGISTRY_HTTP_RESULT_MAPPER_HPP
#define _TASK_MANAGER_REGISTRY_HTTP_RESULT_MAPPER_HPP

#include "handlers/iHandler.hpp"

#include <string>

namespace task_manager::registry
{
    /// @brief libcurl codes, spelled out because http_op.h deliberately does not leak curl.h.
    constexpr int CURLE_COULDNT_CONNECT_CODE {7};
    constexpr int CURLE_OPERATION_TIMEDOUT_CODE {28};

    /**
     * @brief One consumer call's raw result, decoupled from libcurl so the mapping can be tested
     *        as a table with no transport at all.
     *
     * `returnCode` is uhttp_post's tri-state: 0 for success, the HTTP status for a non-2xx, and
     * the NEGATED libcurl code for a transport failure.
     */
    struct TransportResult
    {
        int returnCode {0};
        int curlCode {0};
        int httpStatus {0};
        /// @brief The response body, possibly empty and possibly TRUNCATED -- the buffer the
        ///        transport writes into is fixed-size and silently cuts.
        std::string body;
    };

    /**
     * @brief Map a consumer's answer onto a handler outcome.
     *
     * Read this as UDS, not TCP. Every request goes over a Unix socket, so name resolution cannot
     * fail and there is no place here for anything DNS-, TLS- or proxy-shaped; seeing such a case
     * in this table would mean it had been copied from a TCP client. The reachable transport
     * failures are exactly three: could-not-connect (socket missing, or present with nothing
     * listening), timed-out, and the mid-transfer errors when the peer dies with the request in
     * flight.
     *
     *   0                        -> ok
     *   -7  couldn't connect     -> not_ready   (a boot race must not cost retry budget)
     *   -28 timed out            -> timeout
     *   any other negative       -> retryable   (mid-transfer; the peer died)
     *   409                      -> busy        (whatever the body says, INCLUDING an unparseable one)
     *   4xx except 408/429       -> terminal, or retryable when the type forbids terminal failure
     *   5xx, 408, 429            -> retryable, honouring a body-level `retryable` flag
     *   -1 with an untouched result -> terminal, logged as a dispatcher bug
     *
     * The truncation fallbacks are the point, not a detail. An unparseable 409 falling through to
     * the 4xx rule would, for a type that must never be abandoned, produce exactly the orphaned
     * documents that allowTerminalFailure exists to prevent.
     *
     * @param result                Zero-initialise this before every call: the transport's early
     *                              error paths never write it, and a struct reused across calls
     *                              would present the previous call's values as this one's.
     * @param allowTerminalFailure  From the type's descriptor.
     */
    HandlerResult classifyTransportResult(const TransportResult& result, bool allowTerminalFailure);
} // namespace task_manager::registry

#endif // _TASK_MANAGER_REGISTRY_HTTP_RESULT_MAPPER_HPP
