/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
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
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>

/**
 * @brief The 401 -> re-enrollment latch (#37828). Any endpoint that gets a
 *        401 has a dead credential, so it reports here: all outbound traffic
 *        pauses and, once per incident, the consumer is asked to re-enroll
 *        (on_reenroll_required). hc_set_agent_identity() -> release() swaps
 *        the id/key and un-pauses, re-arming the latch so a later dead key
 *        fires again.
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
                // Counted before the consumer is asked, so any release() it leads to comes after
                // this count: a reader that sees the gate released again also sees the incident.
                m_incidents.fetch_add(1, std::memory_order_acq_rel);
                m_sink.onReenrollRequired();
                m_wake();
            }
        }

        /// A fresh credential is in place: resume and re-arm. A stale 401 from
        /// an old in-flight request racing this costs at most one harmless
        /// extra re-enroll (the key is already fresh); it can never strand the
        /// gate paused-but-unfired or fired-but-unpaused.
        ///
        /// Also drops any unknown_agent window: one opened during the latch belongs to the old key,
        /// and the new key's first `unknown_agent` must get a whole window of its own.
        void release()
        {
            {
                std::lock_guard<std::mutex> lock(m_windowMutex);
                m_windowOpen.store(false, std::memory_order_release);
            }

            m_state.store(State::Running, std::memory_order_release);
            m_wake();
        }

        bool paused() const
        {
            return m_state.load(std::memory_order_acquire) == State::Paused;
        }

        /// How many incidents have latched the gate so far. A key renewed from inside
        /// on_reenroll_required can release the gate before a reader polls paused(); the count
        /// still tells that reader an incident happened (#38329). Read it after paused().
        uint64_t incidents() const
        {
            return m_incidents.load(std::memory_order_acquire);
        }

        /// The window in which every stream keeps retrying the held credential on a
        /// `401 unknown_agent` before the gate latches. One per agent, so all streams share one
        /// deadline and one start/close log, and a stream that leaves it on a transport error
        /// rejoins the same window on its next 401, unless it went stale (joinUnknownAgentWindow).
        struct UnknownAgentWindow
        {
            uint64_t generation {0}; ///< Tells this window apart from a later one.
            std::chrono::steady_clock::time_point deadline;
            bool opened {false}; ///< This call opened the window.
        };

        /// Joins the open window, or opens a new one. An expired window is still joined while
        /// `unknown_agent` keeps coming (a 401 interleaved with 5xx escalates on time), but after a
        /// whole bound without one the answers are a new incident and get a window of their own.
        UnknownAgentWindow joinUnknownAgentWindow(std::chrono::steady_clock::time_point now,
                                                  std::chrono::milliseconds bound)
        {
            std::lock_guard<std::mutex> lock(m_windowMutex);

            const bool open = m_windowOpen.load(std::memory_order_acquire);
            const bool stale = open && now >= m_windowDeadline && now - m_lastUnknownAgent > bound;
            m_lastUnknownAgent = now;

            if (open && !stale)
            {
                return {m_windowGeneration.load(std::memory_order_acquire), m_windowDeadline, false};
            }

            m_windowDeadline = now + bound;
            const auto generation = m_windowGeneration.fetch_add(1, std::memory_order_acq_rel) + 1;
            m_windowOpen.store(true, std::memory_order_release);
            return {generation, m_windowDeadline, true};
        }

        /// A retry inside the window got `unknown_agent` again.
        void noteUnknownAgent(std::chrono::steady_clock::time_point now)
        {
            std::lock_guard<std::mutex> lock(m_windowMutex);
            m_lastUnknownAgent = now;
        }

        /// Closes whichever window is open; true only for the caller that closed it, so the close
        /// is logged once. An accepted request proves the credential, so it ends any window.
        bool closeUnknownAgentWindow()
        {
            // Every accepted request calls this; skip the lock when no window is open.
            if (!m_windowOpen.load(std::memory_order_acquire))
            {
                return false;
            }

            std::lock_guard<std::mutex> lock(m_windowMutex);
            return m_windowOpen.exchange(false, std::memory_order_acq_rel);
        }

        /// Closes the window only if it is still `generation`, so a stream left on an older window
        /// can never close, and escalate, a newer one.
        bool closeUnknownAgentWindow(uint64_t generation)
        {
            std::lock_guard<std::mutex> lock(m_windowMutex);

            if (m_windowGeneration.load(std::memory_order_acquire) != generation)
            {
                return false;
            }

            return m_windowOpen.exchange(false, std::memory_order_acq_rel);
        }

        bool unknownAgentWindowOpen() const
        {
            return m_windowOpen.load(std::memory_order_acquire);
        }

        /// Whether `generation` is still the open window.
        bool unknownAgentWindowCurrent(uint64_t generation) const
        {
            return m_windowOpen.load(std::memory_order_acquire) &&
                   m_windowGeneration.load(std::memory_order_acquire) == generation;
        }

    private:
        enum class State : uint8_t { Running, Paused };

        ICallbackSink& m_sink;
        std::function<void()> m_wake;
        std::atomic<State> m_state {State::Running};
        std::atomic<uint64_t> m_incidents {0};

        std::mutex m_windowMutex;
        std::atomic<bool> m_windowOpen {false};
        std::atomic<uint64_t> m_windowGeneration {0};
        std::chrono::steady_clock::time_point m_windowDeadline {};
        std::chrono::steady_clock::time_point m_lastUnknownAgent {};
};

#endif // _HC_AUTH_GATE_HPP
