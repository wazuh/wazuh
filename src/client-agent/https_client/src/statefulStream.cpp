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

#include "statefulStream.hpp"

namespace
{
    constexpr uint32_t STATEFUL_MAX_ATTEMPTS = 5;
    constexpr size_t STATEFUL_MAX_QUEUE = 64;
} // namespace

StatefulStream::StatefulStream(const ModuleConfig& config, IHttpPerformer& performer,
                               const ISigner& signer, IClock& clock, IRandom& random,
                               ISpoolFileFactory& spoolFactory, ICallbackSink& sink)
    : m_config(config)
    , m_backoff(config.backoffBaseMs, config.backoffCapMs, random)
    , m_sender(performer, signer, clock, m_backoff)
    , m_spoolFactory(spoolFactory)
    , m_sink(sink)
    , m_maxQueue(STATEFUL_MAX_QUEUE)
{
}

bool StatefulStream::submit(const std::string& sessionId, const uint8_t* buffer, size_t length)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_queue.size() >= m_maxQueue)
    {
        return false;
    }

    m_queue.push_back(Session {sessionId, std::vector<uint8_t>(buffer, buffer + length)});
    return true;
}

bool StatefulStream::step(Waiter& waiter)
{
    Session session;

    if (!popNext(session))
    {
        return false;
    }

    const auto result = sendSession(session, waiter);
    m_sink.onSyncResponse(session.id, result.code, result.body);
    return true;
}

bool StatefulStream::hasPending() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return !m_queue.empty();
}

bool StatefulStream::popNext(Session& out)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_queue.empty())
    {
        return false;
    }

    out = std::move(m_queue.front());
    m_queue.pop_front();
    return true;
}

StatefulStream::SendResult StatefulStream::sendSession(const Session& session, Waiter& waiter)
{
    const auto spool = m_spoolFactory.spool(session.body.data(), session.body.size());

    if (!spool)
    {
        return {HC_RESULT_ERROR, {}}; // Spool failure: reported up; the FSM will retry.
    }

    HttpRequestSpec spec;
    spec.target = "/stateful";
    spec.bodyFilePath = spool->path();
    spec.bodyFileSize = session.body.size();
    spec.timeoutMs = m_config.statefulTimeoutMs;
    spec.headers.push_back("X-Session-Id: " + session.id); // Stable across retries (LRU dedup).

    const auto result = m_sender.send(spec, waiter, STATEFUL_MAX_ATTEMPTS);
    return {toHcResult(result.outcome), result.response.body};
}
