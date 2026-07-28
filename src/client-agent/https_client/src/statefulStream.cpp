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

#include "sessionId.hpp"

namespace
{
    constexpr uint32_t STATEFUL_MAX_ATTEMPTS = 5;
    constexpr size_t STATEFUL_MAX_QUEUE = 64;
} // namespace

StatefulStream::StatefulStream(const ModuleConfig& config, IHttpPerformer& performer,
                               const ISigner& signer, IClock& clock, IRandom& random,
                               ISpoolFileFactory& spoolFactory, ICallbackSink& sink,
                               AuthGate& authGate)
    : m_config(config)
    , m_authGate(authGate)
    , m_backoff(config.backoffBaseMs, config.backoffCapMs, random)
    , m_sender(performer, signer, clock, m_backoff, &authGate)
    , m_spoolFactory(spoolFactory)
    , m_sink(sink)
    , m_maxQueue(STATEFUL_MAX_QUEUE)
{
}

bool StatefulStream::submit(const std::string& sessionId, const uint8_t* buffer, size_t length)
{
    if (!acceptableId(sessionId))
    {
        return false;
    }

    // Spool the buffer to a temp file now, so the queue never holds the bytes.
    auto spool = m_spoolFactory.spool(buffer, length);

    if (!spool)
    {
        return false; // Spool failure: nothing enqueued.
    }

    return enqueue(Session {sessionId, std::move(spool), length});
}

bool StatefulStream::submitFile(const std::string& sessionId, const std::string& filePath,
                                uint64_t size)
{
    // Adopt the file first: it is ours from here on, so every rejection below
    // still deletes it instead of stranding it in the spool directory.
    Session session {sessionId, std::make_shared<SpoolFile>(filePath), size};

    if (!acceptableId(sessionId))
    {
        return false;
    }

    return enqueue(std::move(session));
}

bool StatefulStream::acceptableId(const std::string& sessionId) const
{
    // Last gate before the id becomes an X-Session-Id header. The intake already
    // rejects illegal ids at the frame, but sessions also arrive straight from
    // the C ABI, so the check that protects the header lives next to it.
    if (isValidSessionId(sessionId))
    {
        return true;
    }

    LOGFN_WARN(m_logFn, "Rejecting a /stateful session: its id is not a valid session id.");
    return false;
}

bool StatefulStream::enqueue(Session session)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_queue.size() >= m_maxQueue)
    {
        return false; // Full: the caller applies back-pressure; SpoolFile deletes the temp file.
    }

    m_queue.push_back(std::move(session));
    return true;
}

bool StatefulStream::step(Waiter& waiter)
{
    // Paused on a dead credential (401): queued sessions wait for a new key.
    if (m_authGate.paused())
    {
        return false;
    }

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
    HttpRequestSpec spec;
    spec.target = "/stateful";
    spec.bodyFilePath = session.spool->path(); // Streamed from disk (flat memory).
    spec.bodyFileSize = session.size;
    spec.timeoutMs = m_config.statefulTimeoutMs;
    spec.headers.push_back("X-Session-Id: " + session.id); // Stable across retries (LRU dedup).

    const auto result = m_sender.send(spec, waiter, STATEFUL_MAX_ATTEMPTS);
    return {toHcResult(result.outcome), result.response.body};
}
