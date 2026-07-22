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

RetrySender::RetrySender(IHttpPerformer& performer, const ISigner& signer, IClock& clock,
                         Backoff& backoff, AuthGate* authGate)
    : m_performer(performer)
    , m_signer(signer)
    , m_clock(clock)
    , m_backoff(backoff)
    , m_authGate(authGate)
{
}

RetrySender::Result RetrySender::send(const HttpRequestSpec& spec, Waiter& waiter,
                                      uint32_t maxAttempts)
{
    HttpRequestSpec base = spec;
    base.abortFlag = waiter.stopFlag();

    Result result;

    for (uint32_t attempt = 1; attempt <= maxAttempts; attempt++)
    {
        result = attemptOnce(base);

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
        // 401 on any endpoint: the credential is dead. Pause everything and
        // ask for re-enrollment (once per incident). #37828.
        m_authGate->reportAuthFailure();
    }

    return result;
}

RetrySender::Result RetrySender::attemptOnce(const HttpRequestSpec& base)
{
    HttpRequestSpec attempt = base; // Fresh copy: the auth pair differs per attempt.
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
    return outcome == OutcomeClass::Retryable || outcome == OutcomeClass::BackPressure;
}
