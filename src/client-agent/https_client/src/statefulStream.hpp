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
#include "moduleConfig.hpp"
#include "retrySender.hpp"
#include "spoolFile.hpp"
#include "stopToken.hpp"
#include "sysSeams.hpp"

#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

/**
 * @brief The /stateful sender (NFR3). A whole sync session is submitted, held
 *        in a bounded queue, spooled to a temp file, and shipped as ONE
 *        streamed POST (flat memory). Retries reuse the same X-Session-Id so
 *        the manager LRU dedups; the outcome is delivered through the sink.
 */
class StatefulStream final
{
    public:
        StatefulStream(const ModuleConfig& config, IHttpPerformer& performer, const ISigner& signer,
                       IClock& clock, IRandom& random, ISpoolFileFactory& spoolFactory,
                       ICallbackSink& sink);

        /// Intake: enqueue a session. Returns false when the queue is full.
        bool submit(const std::string& sessionId, const uint8_t* buffer, size_t length);

        /// One sender iteration: send the next queued session (if any) and report
        /// its result. Returns true when a session was processed.
        bool step(Waiter& waiter);

        bool hasPending() const;

    private:
        struct Session
        {
            std::string id;
            std::vector<uint8_t> body;
        };

        struct SendResult
        {
            int code {HC_RESULT_ERROR};
            std::string body;
        };

        bool popNext(Session& out);
        SendResult sendSession(const Session& session, Waiter& waiter);

        const ModuleConfig& m_config;
        Backoff m_backoff;
        RetrySender m_sender;
        ISpoolFileFactory& m_spoolFactory;
        ICallbackSink& m_sink;

        mutable std::mutex m_mutex;
        std::deque<Session> m_queue;
        size_t m_maxQueue;
};

#endif // _HC_STATEFUL_STREAM_HPP
