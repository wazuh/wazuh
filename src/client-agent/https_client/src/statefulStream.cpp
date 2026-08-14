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

#include "shared_modules/sync_protocol/include/sync_session_wire.hpp"

namespace
{
    constexpr uint32_t STATEFUL_MAX_ATTEMPTS = 5;
    constexpr size_t STATEFUL_MAX_QUEUE = 64;
} // namespace

StatefulStream::StatefulStream(const ModuleConfig& config, IHttpPerformer& performer,
                               const ISigner& signer, IClock& clock, IRandom& random,
                               ISpoolFileFactory& spoolFactory, ICallbackSink& sink,
                               AuthGate& authGate, CompressionGate& compressionGate,
                               IFileCompressor& fileCompressor)
    : m_config(config)
    , m_authGate(authGate)
    , m_compressionGate(compressionGate)
    , m_backoff(config.backoffBaseMs, config.backoffCapMs, random)
    , m_sender(performer, signer, clock, m_backoff, config.httpsCompressionEnabled, &compressionGate, &authGate)
    , m_spoolFactory(spoolFactory)
    , m_fileCompressor(fileCompressor)
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

    // The id itself is not logged: it is exactly the untrusted bytes we are
    // refusing, and control characters in it would break the log line too.
    LOGFN_WARN(m_logFn, "Refusing a /stateful session: its id (%zu bytes) is not a valid "
               "session id.", sessionId.size());
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
    m_sink.onSyncResponse(session.id, static_cast<int>(result.httpCode), result.body);
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

    // Compress once, up front -- not per retry attempt like the in-memory send
    // paths, since this body can be multi-MB and STATEFUL_MAX_ATTEMPTS allows
    // up to 5 attempts per session. RetrySender::attemptOnce() swaps the
    // precompressed sibling in per attempt (HttpRequestSpec::
    // precompressedBodyFilePath) whenever the shared gate still allows it,
    // falling back to spec.bodyFilePath (untouched here) on its own if a 415
    // disables the gate mid-session. Kept alive until send() returns, below.
    std::unique_ptr<SpoolFile> compressedSpool;

    if (m_config.httpsCompressionEnabled && !m_compressionGate.disabled() && session.size > 0)
    {
        auto compressed = m_fileCompressor.compress(spec.bodyFilePath, spec.bodyFileSize,
                                                    m_config.spoolDir, waiter.stopFlag());

        if (compressed)
        {
            compressedSpool = std::move(compressed->first);
            spec.precompressedBodyFilePath = compressedSpool->path();
            spec.precompressedBodyFileSize = compressed->second;
        }

        // else: compression failed (disk full, aborted, etc.) -- fall through
        // and send the original file uncompressed; never lose the session
        // over a compression failure.
    }

    // Operational visibility (send-time debug log, mirroring statelessStream.cpp's own
    // "Sending /stateless batch" one): logged before the request so the size is on record
    // even if the POST never completes, and so it can be lined up against what the manager
    // received.
    LOGFN_DEBUG2(m_logFn,
                 "Sending /stateful session %s (%llu bytes).",
                 session.id.c_str(),
                 static_cast<unsigned long long>(session.size));

    const auto result = m_sender.send(spec, waiter, STATEFUL_MAX_ATTEMPTS);
    // The /stateful contract is interpreted from the raw HTTP status code and body by
    // agent_sync_protocol, not from the shared D9 OutcomeClass (see SendResult::httpCode).
    // result.response.httpCode is 0 when no HTTP response was received (m_sender's retry
    // loop already exhausted its attempts via the OutcomeClass-driven retry decision).
    return {result.response.httpCode, result.response.body};
}
