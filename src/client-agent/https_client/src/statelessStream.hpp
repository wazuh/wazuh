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

#ifndef _HC_STATELESS_STREAM_HPP
#define _HC_STATELESS_STREAM_HPP

#include "adaptivePayload.hpp"
#include "callbackSink.hpp"
#include "eventAccumulator.hpp"
#include "moduleConfig.hpp"
#include "moduleLog.hpp"
#include "retrySender.hpp"
#include "stopToken.hpp"
#include "sysSeams.hpp"

#include <chrono>
#include <string>

/**
 * @brief The /stateless sender (D6). Intake appends to the accumulator; the
 *        sender thread flushes on the size/age/forced conditions. Each flush
 *        prepends the H metadata line, signs (via RetrySender), and on success
 *        consumes the sent prefix. Back-pressure defers only this stream's
 *        next flush. The occupancy ladder is surfaced through the sink on
 *        every change.
 */
class StatelessStream final
{
    public:
        StatelessStream(const ModuleConfig& config, IHttpPerformer& performer, const ISigner& signer,
                        IClock& clock, IRandom& random, ICallbackSink& sink, AuthGate& authGate);

        /// Intake entry point (from agentd's EventForward seam). Emits a buffer
        /// level change if the append crosses a ladder threshold.
        bool submit(const uint8_t* frame, size_t length);

        /// One sender iteration. force = shutdown/notify-now drain. Returns the
        /// delay until the next tick should run.
        std::chrono::milliseconds tick(Waiter& waiter, bool force);

        /// Shutdown drain: flush repeatedly until the buffer empties or nothing
        /// more can be sent (bounded, since one flush now sends <= effective
        /// bytes rather than the whole buffer).
        void drain(Waiter& waiter);

        hc_buffer_level_t level() const;

    private:
        bool flushDue(bool force) const;
        bool flushOnce(Waiter& waiter);
        void handleOutcome(OutcomeClass outcome, const EventAccumulator::Snapshot& snapshot);
        void publishLevel();
        std::string buildHeaderLine() const;

        const ModuleConfig& m_config;
        IClock& m_clock;
        AuthGate& m_authGate;
        EventAccumulator m_accumulator;
        AdaptivePayload m_payload;
        Backoff m_backoff;
        RetrySender m_sender;
        ICallbackSink& m_sink;
        const LogFn m_logFn {HTTPS_CLIENT_LOGTAG};
        std::chrono::steady_clock::time_point m_lastFlush;
        hc_buffer_level_t m_lastLevel {HC_BUFFER_NORMAL};
        uint64_t m_oversizedDropped {0}; ///< Single events too large to ever fit.
};

#endif // _HC_STATELESS_STREAM_HPP
