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

#include "callbackSink.hpp"
#include "eventAccumulator.hpp"
#include "moduleConfig.hpp"
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
                    IClock& clock, IRandom& random, ICallbackSink& sink);

    /// Intake entry point (from agentd's EventForward seam). Emits a buffer
    /// level change if the append crosses a ladder threshold.
    bool submit(const uint8_t* frame, size_t length);

    /// One sender iteration. force = shutdown/notify-now drain. Returns the
    /// delay until the next tick should run.
    std::chrono::milliseconds tick(Waiter& waiter, bool force);

    hc_buffer_level_t level() const;

private:
    bool flushDue(bool force) const;
    void flushOnce(Waiter& waiter);
    void publishLevel();
    std::string buildHeaderLine() const;

    const ModuleConfig& m_config;
    IClock& m_clock;
    EventAccumulator m_accumulator;
    Backoff m_backoff;
    RetrySender m_sender;
    ICallbackSink& m_sink;
    std::chrono::steady_clock::time_point m_lastFlush;
    hc_buffer_level_t m_lastLevel {HC_BUFFER_NORMAL};
};

#endif // _HC_STATELESS_STREAM_HPP
