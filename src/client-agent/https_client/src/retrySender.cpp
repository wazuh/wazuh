/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "retrySender.hpp"

#include "authFailureClass.hpp"
#include "bodyCompressor.hpp"
#include "clockSkew.hpp"
#include "requestTarget.hpp"

#include <algorithm>
#include <cstdlib>
#include <utility>
#include <vector>

RetrySender::RetrySender(IHttpPerformer& performer,
                         const ISigner& signer,
                         IClock& clock,
                         Backoff& backoff,
                         bool compressionEnabled,
                         CompressionGate* compressionGate,
                         AuthGate* authGate,
                         std::string serverEndpoint,
                         std::chrono::milliseconds unknownAgentRetryBound)
    : m_performer(performer)
    , m_signer(signer)
    , m_clock(clock)
    , m_backoff(backoff)
    , m_compressionEnabled(compressionEnabled)
    , m_compressionGate(compressionGate)
    , m_authGate(authGate)
    , m_serverEndpoint(std::move(serverEndpoint))
    , m_unknownAgentRetryBound(unknownAgentRetryBound)
{
}

RetrySender::Result RetrySender::send(const HttpRequestSpec& spec, Waiter& waiter, uint32_t maxAttempts, Mode mode)
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

    // Whether a surviving `unknown_agent` 401 may latch the gate. Without a window it always may.
    bool escalate = true;

    if (isUnknownAgent(result) && m_authGate != nullptr && m_unknownAgentRetryBound.count() > 0)
    {
        if (mode == Mode::Drain)
        {
            // The stop path never waits; it leaves an open window to the stream that owns it.
            escalate = !m_authGate->unknownAgentWindowOpen();
        }
        else
        {
            result = retryUnknownAgent(base, waiter, std::move(result), escalate);
        }
    }

    if (result.outcome == OutcomeClass::Ok)
    {
        m_backoff.reset();

        // Any accepted request proves the credential, whichever stream sent it.
        if (m_authGate != nullptr && m_authGate->closeUnknownAgentWindow())
        {
            LOGFN_INFO(m_logFn, "https_client: the manager accepted the current credential again; "
                       "no re-enrollment needed.");
        }
    }
    else if (result.outcome == OutcomeClass::AuthFail)
    {
        // A 401 that survived the one-shot fresh-timestamp retry and, for `unknown_agent`, the
        // gate's window. Which of the three answers it deserves is the manager's to name, not ours
        // to guess (#39064): only `unknown_agent` means the identity itself is gone, and only that
        // pauses traffic and asks for re-enrollment. Every other class -- including
        // Unclassified, the fail-safe reading -- is returned to the caller unescalated; the streams
        // already keep the batch and retry on the next tick (statelessStream.cpp), so nothing storms
        // and no second pause mechanism exists.
        const auto authClass = parseAuthFailClass(result.response.body);

        if (authClass == AuthFailClass::UnknownAgent)
        {
            if (m_authGate != nullptr && escalate)
            {
                m_authGate->reportAuthFailure(); // Once per incident. #37828.
            }
        }
        else
        {
            LOGFN_ERROR(m_logFn,
                        "https_client: the manager refused this request's credential (401, %s); "
                        "keeping the current identity and retrying.",
                        authFailClassName(authClass));
        }
    }

    return result;
}

bool RetrySender::isUnknownAgent(const Result& result)
{
    return result.outcome == OutcomeClass::AuthFail &&
           parseAuthFailClass(result.response.body) == AuthFailClass::UnknownAgent;
}

RetrySender::Result RetrySender::retryUnknownAgent(const HttpRequestSpec& base,
                                                   Waiter& waiter,
                                                   Result result,
                                                   bool& escalate)
{
    escalate = false;

    // Another stream already ran the window out and latched: the re-enrollment is under way.
    if (m_authGate->paused())
    {
        return result;
    }

    const auto incidentsAtJoin = m_authGate->incidents();
    const auto window = m_authGate->joinUnknownAgentWindow(m_clock.steadyNow(), m_unknownAgentRetryBound);

    if (window.opened)
    {
        LOGFN_WARN(m_logFn,
                   "https_client: the manager does not know this agent yet (401, unknown_agent); "
                   "retrying the current credential with backoff before re-enrolling.");
    }

    for (uint32_t step = 0; m_clock.steadyNow() < window.deadline; step++)
    {
        const auto next = std::min(m_clock.steadyNow() + unknownAgentStep(step), window.deadline);

        if (!waitUntil(waiter, next, window.generation))
        {
            result.outcome = OutcomeClass::Interrupted; // Shutdown during the wait.
            return result;
        }

        // Latched, or the window was closed or replaced meanwhile: this stream no longer owns it.
        if (m_authGate->paused() || !m_authGate->unknownAgentWindowCurrent(window.generation))
        {
            return result;
        }

        result = attemptOnce(base);

        // The gate may have been disabled since the first attempt; same one-shot rule as send().
        if (result.outcome == OutcomeClass::CompressionRejected && m_compressionGate != nullptr)
        {
            m_compressionGate->reportRejected();
            result = attemptOnce(base);
        }

        if (isUnknownAgent(result))
        {
            m_authGate->noteUnknownAgent(m_clock.steadyNow());
            continue;
        }

        if (result.outcome == OutcomeClass::AuthFail)
        {
            const auto authClass = parseAuthFailClass(result.response.body);

            // A 401 without a recognised class (a proxy's, say) says nothing about the key.
            if (authClass == AuthFailClass::Unclassified)
            {
                continue;
            }

            // The manager knows this agent again and names another problem: the window is over.
            if (m_authGate->closeUnknownAgentWindow(window.generation))
            {
                LOGFN_INFO(m_logFn,
                           "https_client: the manager knows this agent again (401, %s); no re-enrollment needed.",
                           authFailClassName(authClass));
            }

            return result;
        }

        // Ok closes the window in send(). A transport error or a 5xx says nothing about the key,
        // so the window stays open and the next 401 on any stream rejoins it.
        return result;
    }

    // Ran out on an unclassified 401: like a transport error, it leaves the window to the next 401.
    if (!isUnknownAgent(result))
    {
        return result;
    }

    // Only the closer of this window escalates, and only if no re-enrollment completed since the
    // join; a window another stream closed first was either latched or saw the credential accepted.
    if (m_authGate->closeUnknownAgentWindow(window.generation) && m_authGate->incidents() == incidentsAtJoin)
    {
        LOGFN_INFO(m_logFn, "https_client: the manager still answers unknown_agent after retrying the current "
                   "credential; re-enrolling.");
        escalate = true;
    }

    return result;
}

bool RetrySender::waitUntil(Waiter& waiter, std::chrono::steady_clock::time_point deadline, uint64_t generation)
{
    for (auto now = m_clock.steadyNow(); now < deadline; now = m_clock.steadyNow())
    {
        // Rounded up: a sub-millisecond remainder truncated to zero would spin until the deadline.
        if (!waiter.waitFor(std::chrono::ceil<std::chrono::milliseconds>(deadline - now)))
        {
            return false;
        }

        // Re-checked on each wake-up (a latch or release wakes the control stream); a window closed
        // by an accepted request wakes no one and is noticed when the step ends.
        if (m_authGate->paused() || !m_authGate->unknownAgentWindowCurrent(generation))
        {
            return true;
        }
    }

    return true;
}

std::chrono::milliseconds RetrySender::unknownAgentStep(uint32_t step)
{
    constexpr int64_t UNKNOWN_AGENT_STEP_BASE_MS = 1000;
    constexpr int64_t UNKNOWN_AGENT_STEP_CAP_MS = 15000;

    const auto ceiling = std::min(UNKNOWN_AGENT_STEP_BASE_MS << std::min<uint32_t>(step, 4), UNKNOWN_AGENT_STEP_CAP_MS);
    // Equal jitter: at least half the step, so agents of one restarted worker do not retry in lockstep.
    const auto jitter = static_cast<int64_t>(m_backoff.jitter01() * static_cast<double>(ceiling / 2));
    return std::chrono::milliseconds {ceiling / 2 + jitter};
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
    // Same decision as EnrollClient's, so it is made in one place (clockSkew.hpp), which also owns
    // the noise floor and the trust and race arguments that used to be restated here.
    const auto delta = correctClockFromServerDate(m_clock, response.serverDateSeconds);

    if (delta == 0)
    {
        return; // No Date, or inside the floor: the 401 is likely a dead key, not the clock.
    }

    LOGFN_INFO(m_logFn,
               "https_client: clock skew of %lld s detected against the manager's response "
               "(Date header); correcting the token timestamp for this and future requests.",
               static_cast<long long>(delta));
}
