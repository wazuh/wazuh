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

#ifndef _HC_STATEFUL_STREAM_HPP
#define _HC_STATEFUL_STREAM_HPP

#include "callbackSink.hpp"
#include "fileCompressor.hpp"
#include "moduleConfig.hpp"
#include "moduleLog.hpp"
#include "retrySender.hpp"
#include "spoolFile.hpp"
#include "stopToken.hpp"
#include "sysSeams.hpp"

#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>

/**
 * @brief The /stateful sender (NFR3). A whole sync session is spooled to a
 *        temp file at submit time and shipped as ONE streamed POST, so a
 *        multi-MB session never sits in memory (flat memory). Sessions can be
 *        submitted as a memory buffer (spooled here) or as an already-spooled
 *        file (adopted from the intake, which streamed it off the local
 *        socket) — the latter keeps the whole path off-heap. Retries reuse the
 *        same X-Session-Id so the manager LRU dedups; the outcome is delivered
 *        through the sink. When compression is enabled and not yet rejected,
 *        sendSession() compresses the spooled file once, up front (not per
 *        retry attempt -- unlike the in-memory send paths, this body can be
 *        multi-MB), handing RetrySender a precompressed sibling file it swaps
 *        in per attempt; a 415 falls back to the original file automatically.
 */
class StatefulStream final
{
    public:
        StatefulStream(const ModuleConfig& config, IHttpPerformer& performer, const ISigner& signer,
                       IClock& clock, IRandom& random, ISpoolFileFactory& spoolFactory,
                       ICallbackSink& sink, AuthGate& authGate, CompressionGate& compressionGate,
                       IFileCompressor& fileCompressor);

        /// Intake: spool the buffer to a temp file and enqueue it. Returns false
        /// when the queue is full or the spool fails.
        bool submit(const std::string& sessionId, const uint8_t* buffer, size_t length);

        /// Intake: adopt an already-spooled session file (the intake streamed it
        /// off the local socket). The file is deleted after the session is sent.
        /// Returns false when the queue is full.
        bool submitFile(const std::string& sessionId, const std::string& filePath, uint64_t size);

        /// One sender iteration: send the next queued session (if any) and report
        /// its result. Returns true when a session was processed.
        bool step(Waiter& waiter);

        bool hasPending() const;

    private:
        struct Session
        {
            std::string id;
            std::shared_ptr<SpoolFile> spool; ///< RAII-deletes the temp file when done.
            uint64_t size {0};
        };

        struct SendResult
        {
            /// Raw HTTP status code the manager answered with (the /stateful contract
            /// interprets these directly - it does not go through the shared D9
            /// classifier, whose numeric-code meanings are specific to /stateless).
            /// 0 means no HTTP response was received at all (timeout/connect/TLS
            /// failure/abort) - the sync protocol treats that like a 503.
            long httpCode {0};
            std::string body;
        };

        bool acceptableId(const std::string& sessionId) const;
        bool enqueue(Session session);
        bool popNext(Session& out);
        SendResult sendSession(const Session& session, Waiter& waiter);

        const ModuleConfig& m_config;
        AuthGate& m_authGate;
        CompressionGate& m_compressionGate;
        Backoff m_backoff;
        RetrySender m_sender;
        ISpoolFileFactory& m_spoolFactory;
        IFileCompressor& m_fileCompressor;
        ICallbackSink& m_sink;

        mutable std::mutex m_mutex;
        std::deque<Session> m_queue;
        size_t m_maxQueue;
        const LogFn m_logFn {HTTPS_CLIENT_LOGTAG};
};

#endif // _HC_STATEFUL_STREAM_HPP
