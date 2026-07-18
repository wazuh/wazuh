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

#include "statelessStream.hpp"

namespace
{
    constexpr uint32_t STATELESS_MAX_ATTEMPTS = 5;
}

StatelessStream::StatelessStream(const ModuleConfig& config, IHttpPerformer& performer,
                                 const ISigner& signer, IClock& clock, IRandom& random,
                                 ICallbackSink& sink)
    : m_config(config)
    , m_clock(clock)
    , m_accumulator(config.batchSizeBytes, config.bufferCapMultiplier, config.batchIntervalMs)
    , m_backoff(config.backoffBaseMs, config.backoffCapMs, random)
    , m_sender(performer, signer, clock, m_backoff)
    , m_sink(sink)
    , m_lastFlush(clock.steadyNow())
{
}

bool StatelessStream::submit(const uint8_t* frame, size_t length)
{
    const bool accepted = m_accumulator.append(frame, length);
    publishLevel();
    return accepted;
}

std::chrono::milliseconds StatelessStream::tick(Waiter& waiter, bool force)
{
    // Back-pressure (503/Retry-After) is honored inside RetrySender, which
    // waits and retries on this stream's own thread; the next flush is thus
    // naturally deferred while the accumulator (fed by the intake thread) keeps
    // absorbing (D5/D6).
    if (flushDue(force))
    {
        flushOnce(waiter);
    }

    return std::chrono::milliseconds {m_config.batchIntervalMs};
}

hc_buffer_level_t StatelessStream::level() const
{
    return m_accumulator.level();
}

bool StatelessStream::flushDue(bool force) const
{
    if (m_accumulator.empty())
{
    return false;
}

if (force)
{
    return true;
}

const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                         m_clock.steadyNow() - m_lastFlush)
                     .count();
return m_accumulator.flushDue(static_cast<uint64_t>(elapsed));
}

void StatelessStream::flushOnce(Waiter& waiter)
{
    const auto snapshot = m_accumulator.snapshot();

    HttpRequestSpec spec;
    spec.target = "/stateless";
    const std::string body = buildHeaderLine() + snapshot.body;
    spec.body = reinterpret_cast<const uint8_t*>(body.data());
    spec.bodyLength = body.size();
    spec.timeoutMs = m_config.requestTimeoutMs;

    const auto result = m_sender.send(spec, waiter, STATELESS_MAX_ATTEMPTS);
    m_lastFlush = m_clock.steadyNow();

    if (result.outcome == OutcomeClass::Ok || result.outcome == OutcomeClass::Permanent)
    {
        m_accumulator.consume(snapshot); // 4xx (413) also drops the batch.
        publishLevel();
    }

    // BackPressure/Retryable/AuthFail/Interrupted: keep the batch for the next tick.
}

void StatelessStream::publishLevel()
{
    const auto level = m_accumulator.level();

    if (level != m_lastLevel)
    {
        m_lastLevel = level;
        m_sink.onBufferLevel(level);
    }
}

std::string StatelessStream::buildHeaderLine() const
{
    return R"(H {"wazuh":{"agent":{"id":")" + m_config.agentId + R"("}}})" + "\n";
}
