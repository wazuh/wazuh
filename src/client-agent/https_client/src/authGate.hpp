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
#include <functional>

/**
 * @brief The 401 -> re-enrollment latch (#37828). Any endpoint that gets a
 *        401 has a dead credential, so it reports here: all outbound traffic
 *        pauses and, once per incident, the consumer is asked to re-enroll
 *        (on_reenroll_required). hc_set_agent_key() -> release() swaps the key
 *        and un-pauses, re-arming the latch so a later dead key fires again.
 *
 * Reversible (unlike RegistrationGate). Lock-free: a std::atomic pause flag
 * every sender polls, and an exchange-based once-latch so the first 401 wins.
 */
class AuthGate final
{
    public:
        AuthGate(ICallbackSink& sink, std::function<void()> wake)
            : m_sink(sink)
            , m_wake(std::move(wake))
        {
        }

        /// A 401 was seen. Pauses traffic; the first call since the last
        /// release() also fires the re-enroll callback and wakes the loops.
        void reportAuthFailure()
        {
            m_paused.store(true, std::memory_order_release);

            if (!m_fired.exchange(true))
            {
                m_sink.onReenrollRequired();
                m_wake();
            }
        }

        /// A fresh credential is in place: un-pause and re-arm the once-latch.
        void release()
        {
            m_fired.store(false, std::memory_order_relaxed);
            m_paused.store(false, std::memory_order_release);
            m_wake();
        }

        bool paused() const
        {
            return m_paused.load(std::memory_order_acquire);
        }

    private:
        ICallbackSink& m_sink;
        std::function<void()> m_wake;
        std::atomic<bool> m_paused {false};
        std::atomic<bool> m_fired {false};
};

#endif // _HC_AUTH_GATE_HPP
