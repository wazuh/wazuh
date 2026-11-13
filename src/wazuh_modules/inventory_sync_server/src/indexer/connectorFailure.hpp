/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_INDEXER_CONNECTOR_FAILURE_HPP
#define _INVSYNC_INDEXER_CONNECTOR_FAILURE_HPP

#include "IIndexerConnectorSync.hpp"

#include <optional>
#include <string>

namespace invsync::indexer
{

    /// The HTTP answer for a session that failed against the indexer.
    struct FailureResponse
    {
        int status {500};
        const char* body {nullptr};
        std::optional<std::string> retryAfter; ///< Set only for a by-query's exhausted conflicts.
    };

    constexpr auto FAILURE_UNAVAILABLE_BODY {R"({"error":"Service unavailable","code":503})"};
    constexpr auto FAILURE_INTERNAL_BODY {R"({"error":"Internal error","code":500})"};
    constexpr auto FAILURE_CONTENTION_BODY {
        R"({"error":"indexer contention","code":503,"reason":"version_conflicts"})"};

    /**
     * @brief The code the agent gets for a failure, decided by its cause alone.
     *
     * No re-query of isAvailable() after the fact: the cause already says whether the indexer was the
     * problem. 503 (the agent retries next cycle) for anything transient, 503 + `Retry-After` when a
     * by-query lost its race against a competing writer (the documents are consistent; the header
     * keeps the re-send from racing it again), 500 for a rejection a re-send alone will not fix.
     *
     * @param cause The failure's cause.
     * @param retryAfterSeconds The `Retry-After` value of the contention answer.
     */
    inline FailureResponse failureResponse(ConnectorError::Cause cause, int retryAfterSeconds)
    {
        switch (cause)
        {
            case ConnectorError::Cause::ConflictsExhausted:
                return {503, FAILURE_CONTENTION_BODY, std::to_string(retryAfterSeconds)};
            case ConnectorError::Cause::Unavailable:
            case ConnectorError::Cause::RetryExhausted: return {503, FAILURE_UNAVAILABLE_BODY, std::nullopt};
            case ConnectorError::Cause::DocumentRejected:
            case ConnectorError::Cause::Other: return {500, FAILURE_INTERNAL_BODY, std::nullopt};
        }
        return {500, FAILURE_INTERNAL_BODY, std::nullopt}; // LCOV_EXCL_LINE -- every enumerator is handled above
    }

    /// Suffix of `sync.bulk.flush.failures.<suffix>` a failure counts under.
    inline const char* failureMetric(ConnectorError::Cause cause)
    {
        switch (cause)
        {
            case ConnectorError::Cause::DocumentRejected:
            case ConnectorError::Cause::ConflictsExhausted: return "documents";
            case ConnectorError::Cause::RetryExhausted: return "exhausted";
            case ConnectorError::Cause::Unavailable: return "unavailable";
            case ConnectorError::Cause::Other: return "other";
        }
        return "other"; // LCOV_EXCL_LINE -- every enumerator is handled above
    }

} // namespace invsync::indexer

#endif // _INVSYNC_INDEXER_CONNECTOR_FAILURE_HPP
