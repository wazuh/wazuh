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
#include "bufferLevel.hpp"
#include "callbackSink.hpp"
#include "eventAccumulator.hpp"
#include "moduleConfig.hpp"
#include "moduleLog.hpp"
#include "retrySender.hpp"
#include "stopToken.hpp"
#include "sysSeams.hpp"

#include <chrono>
#include <functional>
#include <mutex>
#include <string>

/**
 * @brief The /stateless sender (D6). Intake appends to the accumulator; the
 *        sender thread flushes on the size/age/forced conditions. Each flush
 *        prepends the H metadata line, signs (via RetrySender), and on success
 *        consumes the sent prefix. Back-pressure defers only this stream's
 *        next flush. Occupancy is surfaced through the sink whenever
 *        BufferLevelLadder says the legacy client buffer would have reported
 *        the step.
 */
class StatelessStream final
{
    public:
        struct SubmissionResult
        {
            bool accepted;
            bool shouldWakeSender;
        };

        /// @param collectHost Pull-source for the H line's host block (agent name/version,
        ///        hostname, architecture, os.*, cluster name, groups -- see
        ///        bridge_on_collect_stateless_host()). Optional: unset (the default) means the H
        ///        line carries only wazuh.agent.id, as before this field existed.
        StatelessStream(const ModuleConfig& config, IHttpPerformer& performer, const ISigner& signer,
                        IClock& clock, IRandom& random, ICallbackSink& sink, AuthGate& authGate,
                        CompressionGate& compressionGate, std::function<std::string()> collectHost = {});

        /// Intake entry point (from agentd's EventForward seam). Emits a buffer
        /// level change if the append crosses a ladder threshold and tells the
        /// facade when the size threshold has just been reached.
        SubmissionResult submit(const uint8_t* frame, size_t length);

        /// One sender iteration. force = shutdown/notify-now drain. Returns the
        /// delay until the next tick should run.
        std::chrono::milliseconds tick(Waiter& waiter, bool force);

        /// Shutdown drain: flush repeatedly until the buffer empties or nothing
        /// more can be sent. Bounded in both directions -- a fixed iteration
        /// count and, per flush, the drain window with a single attempt.
        void drain(Waiter& waiter);

        hc_buffer_level_t level() const;
        uint64_t droppedEvents() const;

    private:
        bool flushDue(bool force) const;
        bool flushOnce(Waiter& waiter, uint32_t timeoutMs, uint32_t maxAttempts);
        void handleOutcome(OutcomeClass outcome, const EventAccumulator::Snapshot& snapshot);
        void publishLevelLocked(bool eventDropped);
        uint64_t eventBytesBudgetLocked() const;
        /// Recomputes m_headerLine from the freshest available host metadata. Caller must hold
        /// m_stateMutex: the line is read from other threads (submit()'s budget check) and this
        /// keeps that read race-free without making every read take the collectHost round trip.
        void refreshHeaderLineLocked();

        const ModuleConfig& m_config;
        IClock& m_clock;
        AuthGate& m_authGate;
        EventAccumulator m_accumulator;
        AdaptivePayload m_payload;
        Backoff m_backoff;
        RetrySender m_sender;
        ICallbackSink& m_sink;
        /// Pull-source for the H line's host block; see the constructor parameter of the same name.
        const std::function<std::string()> m_collectHost;
        /// H line prefixed to every batch. Refreshed under m_stateMutex at the start of each flush
        /// (not per event) so metadata that only becomes available after construction -- cluster
        /// name arrives from the manager's own /control handshake, which can land after this
        /// stream starts sending -- is picked up without restarting the stream. A one-flush-old
        /// value is used for the budget check in between flushes; harmless, since the accumulator
        /// self-corrects at the very next flush either way.
        std::string m_headerLine;
        const LogFn m_logFn {HTTPS_CLIENT_LOGTAG};
        std::chrono::steady_clock::time_point m_lastFlush;
        mutable std::mutex m_stateMutex;
        BufferLevelLadder m_ladder;
        uint64_t m_droppedEvents {0};
        bool m_oversizedWarned {false}; ///< Warn-once latch for unsplittable 413s.
};

#endif // _HC_STATELESS_STREAM_HPP
