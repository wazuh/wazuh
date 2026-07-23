/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_AUTH_GATE_HPP
#define _HC_AUTH_GATE_HPP

#include "callbackSink.hpp"

#include <atomic>
#include <cstdint>
#include <functional>

/**
 * @brief The 401 -> re-enrollment latch (#37828). Any endpoint that gets a
 *        401 has a dead credential, so it reports here: all outbound traffic
 *        pauses and, once per incident, the consumer is asked to re-enroll
 *        (on_reenroll_required). hc_set_agent_key() -> release() swaps the key
 *        and un-pauses, re-arming the latch so a later dead key fires again.
 *
 * Reversible (unlike RegistrationGate). Lock-free through a SINGLE atomic
 * state (not two independent flags): "paused" and "already fired for this
 * incident" are the same fact, so a report cannot end fired-but-unpaused.
 */
class AuthGate final
{
    public:
        AuthGate(ICallbackSink& sink, std::function<void()> wake)
            : m_sink(sink)
            , m_wake(std::move(wake))
        {
        }

        /// A 401 was seen. One atomic transition to Paused: traffic is ALWAYS
        /// paused afterwards, and only the reporter that flipped Running->Paused
        /// (the exchange returns the prior state) fires the re-enroll callback
        /// and wakes the loops -- so it fires exactly once per incident.
        void reportAuthFailure()
        {
            if (m_state.exchange(State::Paused, std::memory_order_acq_rel) == State::Running)
            {
                m_sink.onReenrollRequired();
                m_wake();
            }
        }

        /// A fresh credential is in place: resume and re-arm. A stale 401 from
        /// an old in-flight request racing this costs at most one harmless
        /// extra re-enroll (the key is already fresh); it can never strand the
        /// gate paused-but-unfired or fired-but-unpaused.
        void release()
        {
            m_state.store(State::Running, std::memory_order_release);
            m_wake();
        }

        bool paused() const
        {
            return m_state.load(std::memory_order_acquire) == State::Paused;
        }

    private:
        enum class State : uint8_t { Running, Paused };

        ICallbackSink& m_sink;
        std::function<void()> m_wake;
        std::atomic<State> m_state {State::Running};
};

#endif // _HC_AUTH_GATE_HPP
