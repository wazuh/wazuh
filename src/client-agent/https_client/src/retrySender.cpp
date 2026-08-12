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

#include "retrySender.hpp"

#include <algorithm>
#include <vector>

#include <zstd.h>

namespace
{
// Matches the level the manager's own test-only compressor
// (zstdTestHelper.hpp's zstdCompress()) uses to build its zstd fixtures.
constexpr int kCompressionLevel = 3;
} // namespace

RetrySender::RetrySender(IHttpPerformer& performer, const ISigner& signer, IClock& clock,
                         Backoff& backoff, bool compressionEnabled, CompressionGate* compressionGate,
                         AuthGate* authGate)
    : m_performer(performer)
    , m_signer(signer)
    , m_clock(clock)
    , m_backoff(backoff)
    , m_compressionEnabled(compressionEnabled)
    , m_compressionGate(compressionGate)
    , m_authGate(authGate)
{
}

RetrySender::Result RetrySender::send(const HttpRequestSpec& spec, Waiter& waiter,
                                      uint32_t maxAttempts)
{
    HttpRequestSpec base = spec;
    base.abortFlag = waiter.stopFlag();

    Result result;
    bool authRetried = false;
    bool compressionRetried = false;

    for (uint32_t attempt = 1; attempt <= maxAttempts; attempt++)
    {
        result = attemptOnce(base);

        // One-shot 401 retry: a 401 can be a just-expired/edge timestamp as
        // easily as a dead key. Resign with a fresh timestamp (attemptOnce
        // re-signs) and try once more; only a second 401 escalates below.
        if (result.outcome == OutcomeClass::AuthFail && !authRetried)
        {
            authRetried = true;
            result = attemptOnce(base);
        }

        // One-shot compression retry: a 415 means the manager doesn't accept
        // Content-Encoding: zstd. Report it to the shared gate first -- every
        // RetrySender on this agent stops compressing from here on, for the
        // rest of this run (#38308) -- then retry; attemptOnce() re-checks the
        // now-disabled gate itself, so this retry is naturally uncompressed
        // with no separate "forced uncompressed" parameter needed.
        if (result.outcome == OutcomeClass::CompressionRejected && !compressionRetried)
        {
            compressionRetried = true;

            if (m_compressionGate != nullptr)
            {
                m_compressionGate->reportRejected();
            }

            result = attemptOnce(base);
        }

        if (!isRetryable(result.outcome) || attempt == maxAttempts)
        {
            break;
        }

        if (!waiter.waitFor(delayFor(result)))
        {
            result.outcome = OutcomeClass::Interrupted; // Shutdown during the delay.
            break;
        }
    }

    if (result.outcome == OutcomeClass::Ok)
    {
        m_backoff.reset();
    }
    else if (result.outcome == OutcomeClass::AuthFail && m_authGate != nullptr)
    {
        // A 401 that survived the one-shot fresh-timestamp retry above: treat it
        // as a dead credential. Pause everything and ask for re-enrollment (once
        // per incident). #37828.
        m_authGate->reportAuthFailure();
    }

    return result;
}

RetrySender::Result RetrySender::attemptOnce(const HttpRequestSpec& base)
{
    HttpRequestSpec attempt = base; // Fresh copy: the auth pair differs per attempt.

    // In-memory bodies only -- /stateful's file-backed path is untouched (its
    // spool file is read twice, independently, by signFile() and the
    // performer; compressing it needs a different design, out of scope here).
    // Compressed before signing so the CMAC covers the wire bytes.
    std::vector<uint8_t> compressedBody;
    const bool gateAllowsCompression = m_compressionGate == nullptr || !m_compressionGate->disabled();
    if (m_compressionEnabled && gateAllowsCompression && attempt.bodyFilePath.empty() && attempt.bodyLength > 0)
    {
        compressedBody.resize(ZSTD_compressBound(attempt.bodyLength));
        const size_t written = ZSTD_compress(compressedBody.data(), compressedBody.size(), attempt.body,
                                             attempt.bodyLength, kCompressionLevel);

        if (!ZSTD_isError(written))
        {
            compressedBody.resize(written);
            attempt.body = compressedBody.data();
            attempt.bodyLength = compressedBody.size();
            attempt.headers.push_back("Content-Encoding: zstd");
        }
        // else: fall through and send the original, uncompressed body -- a
        // one-shot ZSTD_compress() into a ZSTD_compressBound()-sized buffer
        // should never actually fail, but never lose the request over it.
    }

    const auto timestamp = m_clock.wallSeconds();
    const auto headers =
        attempt.bodyFilePath.empty()
        ? m_signer.sign("POST", attempt.target, attempt.body, attempt.bodyLength, timestamp)
        : m_signer.signFile("POST", attempt.target, attempt.bodyFilePath, timestamp);

    if (!headers)
    {
        return {OutcomeClass::Permanent, {}}; // Unusable credentials: retrying cannot help.
    }

    attempt.headers.push_back(headers->protocolVersion);
    attempt.headers.push_back(headers->authorization);

    Result result;
    result.response = m_performer.perform(attempt);
    result.outcome = classifyOutcome(result.response);
    return result;
}

std::chrono::milliseconds RetrySender::delayFor(const Result& result)
{
    const auto backoffDelay = m_backoff.next();

    if (result.outcome == OutcomeClass::BackPressure)
    {
        const auto serverDelay =
            std::chrono::milliseconds {result.response.retryAfterSeconds * 1000};
        return std::max(serverDelay, backoffDelay); // The server's delay wins when longer.
    }

    return backoffDelay;
}

bool RetrySender::isRetryable(OutcomeClass outcome)
{
    return outcome == OutcomeClass::Unreachable || outcome == OutcomeClass::ServerError ||
           outcome == OutcomeClass::BackPressure;
}
