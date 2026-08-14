/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_HTTP_TYPES_HPP
#define _HC_HTTP_TYPES_HPP

#include "https_client.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

/// Transport-level result of one HTTP attempt, already curl-free.
enum class TransportStatus
{
    Ok,          ///< The request completed and an HTTP status is available.
    Timeout,     ///< The request timed out.
    ConnectFail, ///< DNS/connect failure.
    TlsFail,     ///< TLS handshake/verification failure.
    Aborted,     ///< Interrupted through the abort flag (shutdown).
    OtherError   ///< Any other transport error.
};

/// D9 outcome classes for a completed attempt.
///
/// Each value names what was OBSERVED, not what policy applies to it: three of
/// them are retried (Unreachable, ServerError, BackPressure).

enum class OutcomeClass
{
    Ok,
    Unreachable,     ///< Transport failed; no HTTP status ever arrived.
    ServerError,     ///< Answered, unhappily, and worth retrying: 5xx other than
    ///< 503, plus the 403/426 an intermediary can inject.
    BackPressure,    ///< 503 + Retry-After / 429: server delay wins when longer.
    AuthFail,        ///< 401: one fresh-timestamp retry, then re-enrollment.
    Permanent,       ///< 400/...: retrying identical bytes cannot succeed.
    PayloadTooLarge, ///< 413: /stateless splits + resends smaller (#37835).
    VersionRejected, ///< 409 at Startup: REJECTED state, slow re-Startup.
    CompressionRejected, ///< 415: manager doesn't accept Content-Encoding: zstd;
    ///< RetrySender retries once, uncompressed.
    Interrupted      ///< Aborted by shutdown: never a silent success.
};

/// Name of an OutcomeClass, for logs: the class is the reason a request
/// failed, and an ordinal does not carry it to the reader.
inline const char* outcomeName(OutcomeClass outcome)
{
    switch (outcome)
    {
        case OutcomeClass::Ok:
            return "Ok";

        case OutcomeClass::Unreachable:
            return "Unreachable";

        case OutcomeClass::ServerError:
            return "ServerError";

        case OutcomeClass::BackPressure:
            return "BackPressure";

        case OutcomeClass::AuthFail:
            return "AuthFail";

        case OutcomeClass::Permanent:
            return "Permanent";

        case OutcomeClass::PayloadTooLarge:
            return "PayloadTooLarge";

        case OutcomeClass::VersionRejected:
            return "VersionRejected";

        case OutcomeClass::CompressionRejected:
            return "CompressionRejected";

        case OutcomeClass::Interrupted:
            return "Interrupted";

        default:
            return "Unknown";
    }
}

/// Maps an OutcomeClass onto the hc_result_t that crosses the C ABI.
inline int toHcResult(OutcomeClass outcome)
{
    switch (outcome)
    {
        case OutcomeClass::Ok:
            return HC_RESULT_OK;

        // Both cross the ABI as RETRYABLE: the C core only needs the policy,
        // and the arm/disarm decision that needs the finer fact never leaves
        // the module (ControlStream owns it), so hc_result_t is unchanged.
        case OutcomeClass::Unreachable:
        case OutcomeClass::ServerError:
            return HC_RESULT_RETRYABLE;

        case OutcomeClass::BackPressure:
            return HC_RESULT_BACKPRESSURE;

        case OutcomeClass::AuthFail:
            return HC_RESULT_AUTH_FAIL;

        case OutcomeClass::Permanent:
            return HC_RESULT_PERMANENT;

        case OutcomeClass::PayloadTooLarge:
            return HC_RESULT_PERMANENT;

        case OutcomeClass::VersionRejected:
            return HC_RESULT_PERMANENT;

        // Reached here only if RetrySender's one-shot uncompressed retry was
        // itself rejected too (unexpected -- the manager should never 415 an
        // uncompressed body) -- same terminal treatment as Permanent.
        case OutcomeClass::CompressionRejected:
            return HC_RESULT_PERMANENT;

        default:
            return HC_RESULT_ERROR;
    }
}

/// One signed HTTP attempt, as handed to the performer. TLS settings and the
/// base URL are the performer's own configuration; the spec carries only the
/// per-request data.
struct HttpRequestSpec
{
    std::string target;                ///< e.g. "/stateless" (also the MAC'd target).
    std::string contentType;           ///< Emitted as Content-Type when non-empty; empty
    ///< leaves libcurl's default (non-JSON endpoints).
    std::vector<std::string> headers;  ///< Extra headers (auth headers included).
    const uint8_t* body {nullptr};     ///< In-memory body (nullptr when file-backed).
    size_t bodyLength {0};
    std::string bodyFilePath;          ///< When non-empty: stream the body from this file.
    uint64_t bodyFileSize {0};
    std::string precompressedBodyFilePath; ///< Optional zstd-compressed sibling of
    ///< bodyFilePath, precomputed once by the caller (only /stateful today).
    ///< attemptOnce() swaps it in when compression is enabled/allowed; empty
    ///< means no such sibling exists, so bodyFilePath is sent as-is.
    uint64_t precompressedBodyFileSize {0};
    std::string responseFilePath;      ///< When non-empty: stream the response body to this
    ///< file (truncated per attempt) instead of
    ///< HttpResponse::body.
    uint64_t maxResponseBytes {0};     ///< Cap on a file-streamed response (0 = unlimited);
    ///< exceeding it aborts the transfer.
    uint32_t timeoutMs {0};
    const std::atomic<bool>* abortFlag {nullptr}; ///< Optional cooperative abort.
};

/// Result of one HTTP attempt.
struct HttpResponse
{
    TransportStatus status {TransportStatus::OtherError};
    long httpCode {0};
    long retryAfterSeconds {0}; ///< Parsed Retry-After header (0 = absent).
    std::string localIp;        ///< Local IP of the connection (CURLINFO_LOCAL_IP);
    ///< the agent's own address toward the manager.
    std::string body;
};

#endif // _HC_HTTP_TYPES_HPP
