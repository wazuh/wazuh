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

#include "bodyCompressor.hpp"
#include "requestTarget.hpp"

#include <algorithm>
#include <cstdlib>
#include <utility>
#include <vector>

namespace
{
    // Below this, a Date-vs-local gap is plausibly network latency or Date's
    // 1 s granularity, not real clock skew -- applying a correction for noise
    // this small would only ever matter within the 30 s clock skew the manager
    // already tolerates, so it is not worth perturbing the token's iat over.
    // The clock-skew failures this targets (VM snapshot restore, dead CMOS
    // battery, no NTP) are minutes to hours off, far above this floor.
    constexpr std::int64_t kSkewNoiseFloorSeconds = 5;
} // namespace

RetrySender::RetrySender(IHttpPerformer& performer,
                         const ISigner& signer,
                         IClock& clock,
                         Backoff& backoff,
                         bool compressionEnabled,
                         CompressionGate* compressionGate,
                         AuthGate* authGate,
                         std::string serverEndpoint)
    : m_performer(performer)
    , m_signer(signer)
    , m_clock(clock)
    , m_backoff(backoff)
    , m_compressionEnabled(compressionEnabled)
    , m_compressionGate(compressionGate)
    , m_authGate(authGate)
    , m_serverEndpoint(std::move(serverEndpoint))
{
}

RetrySender::Result RetrySender::send(const HttpRequestSpec& spec, Waiter& waiter, uint32_t maxAttempts)
{
    HttpRequestSpec base = spec;
    base.abortFlag = waiter.stopFlag();

    Result result;
    bool authRetried = false;
    bool compressionRetried = false;

    for (uint32_t attempt = 1; attempt <= maxAttempts; attempt++)
    {
        result = attemptOnce(base);

        // Both one-shot retries below can fire in either order within the same
        // outer attempt (a 415's uncompressed retry can itself land a 401, and
        // vice versa), so loop until neither applies rather than checking each
        // only once -- otherwise a 401 produced by the compression retry would
        // skip its own auth grace-retry and escalate straight to reportAuthFailure().
        for (;;)
        {
            // One-shot 401 retry: a 401 can be a just-expired/edge timestamp,
            // a clock-skewed agent, or a dead key -- the manager deliberately
            // answers all three identically (#37828). Correct for
            // measurable skew (if the response carried the manager's Date)
            // and mint a fresh token (attemptOnce re-mints); only
            // a second 401 -- now on a timestamp already skew-corrected --
            // escalates below as a genuine credential failure.
            if (result.outcome == OutcomeClass::AuthFail && !authRetried)
            {
                authRetried = true;
                correctClockIfSkewed(result.response);
                result = attemptOnce(base);
                continue;
            }

            // One-shot compression retry: a 415 means the manager doesn't accept
            // Content-Encoding: zstd. Report it to the shared gate first -- every
            // RetrySender on this agent stops compressing from here on, for the
            // rest of this run -- then retry; attemptOnce() re-checks the
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
                continue;
            }

            break;
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

    // #38492/#38491: fold the configured endpoint into the target -- the
    // manager routes on the literal wire request-target (prefix included);
    // CurlPerformer later appends this already-prefixed string to
    // ModuleConfig::baseUrl(). Authentication does not look at it.
    attempt.target = prefixedTarget(m_serverEndpoint, attempt.target);

    // In-memory bodies: compressed here, per attempt (cheap for the small
    // buffers every other send path uses). The bearer token does not cover
    // the body, so compression and authentication are independent.
    std::vector<uint8_t> compressedBody;
    const bool gateAllowsCompression = m_compressionGate == nullptr || !m_compressionGate->disabled();

    if (m_compressionEnabled && gateAllowsCompression && attempt.bodyFilePath.empty() && attempt.bodyLength > 0)
    {
        if (auto compressed = compressBody(attempt.body, attempt.bodyLength))
        {
            compressedBody = std::move(*compressed);
            attempt.body = compressedBody.data();
            attempt.bodyLength = compressedBody.size();
            attempt.headers.push_back("Content-Encoding: zstd");
        }

        // else: fall through and send the original, uncompressed body -- a
        // one-shot ZSTD_compress() into a ZSTD_compressBound()-sized buffer
        // should never actually fail, but never lose the request over it.
    }
    else if (m_compressionEnabled && gateAllowsCompression && !attempt.bodyFilePath.empty() &&
             !attempt.precompressedBodyFilePath.empty())
    {
        // File-backed bodies (/stateful): compressing a potentially multi-MB
        // spool file per attempt would be wasteful under retries, so the
        // caller (StatefulStream) compresses once, up front, and hands us the
        // compressed sibling's path/size here. Swapped in fresh on every call,
        // exactly like the in-memory branch above -- a 415 disables the gate,
        // and the next attemptOnce() naturally falls through to this `else`
        // and sends the original, uncompressed file with no header.
        attempt.bodyFilePath = attempt.precompressedBodyFilePath;
        attempt.bodyFileSize = attempt.precompressedBodyFileSize;
        attempt.headers.push_back("Content-Encoding: zstd");
    }

    // One fresh bearer per attempt (identity only: the same call serves
    // in-memory and file-backed bodies alike).
    const auto headers = m_signer.sign(m_clock.wallSeconds());

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
        const auto serverDelay = std::chrono::milliseconds {result.response.retryAfterSeconds * 1000};
        return std::max(serverDelay, backoffDelay); // The server's delay wins when longer.
    }

    return backoffDelay;
}

bool RetrySender::isRetryable(OutcomeClass outcome)
{
    return outcome == OutcomeClass::Unreachable || outcome == OutcomeClass::ServerError ||
           outcome == OutcomeClass::BackPressure;
}

void RetrySender::correctClockIfSkewed(const HttpResponse& response)
{
    // Date is not itself authenticated (it isn't covered by any signature),
    // so this trusts whoever answered the TLS handshake -- no different from
    // trusting the 401 status/body it arrived with. Under the required TLS
    // verification modes this is the real manager; under verify_mode=none
    // (opt-in, insecure) a MITM could already forge the entire response, so
    // feeding it a bogus Date is not a new capability, only a new use of an
    // existing one.
    if (response.serverDateSeconds == 0)
    {
        return; // No Date captured/parsed: nothing to measure skew against.
    }

    // This read is only a heuristic pre-check (noise floor + log message):
    // it can race against another sender's concurrent correction and see a
    // stale wallSeconds(), but that only risks skipping/duplicating a log
    // line or a redundant call below -- m_clock.correctToServerTime()
    // recomputes the actual offset itself, from its own raw clock read
    // taken at commit time, so a stale `delta` here never corrupts the
    // applied correction (see IClock::correctToServerTime's contract).
    const auto delta =
        static_cast<std::int64_t>(response.serverDateSeconds) - static_cast<std::int64_t>(m_clock.wallSeconds());

    if (std::abs(delta) < kSkewNoiseFloorSeconds)
    {
        return; // Aligned enough: leave the clock alone, the 401 is likely a dead key.
    }

    m_clock.correctToServerTime(response.serverDateSeconds);
    LOGFN_INFO(m_logFn,
               "https_client: clock skew of %lld s detected against the manager's response "
               "(Date header); correcting the token timestamp for this and future requests.",
               static_cast<long long>(delta));
}
