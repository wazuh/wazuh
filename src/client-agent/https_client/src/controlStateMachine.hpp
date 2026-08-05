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

#ifndef _HC_CONTROL_STATE_MACHINE_HPP
#define _HC_CONTROL_STATE_MACHINE_HPP

#include "https_client.h"

#include <atomic>

/**
 * @brief The /control client state machine (D7), pure logic: no I/O, no time.
 *
 * ControlStream drives it: it asks what to do next (nextAction), executes the
 * request, and feeds the result back as an Event (onEvent). Effects returned
 * by onEvent tell the caller which side actions to run (release the startup
 * gate, apply the handshake JSON, emit a state change). Every transition cell
 * is enumerated by the unit test.
 */
class ControlStateMachine final
{
    public:
        enum class State
        {
            Starting,   ///< Startup not accepted yet; data streams gated.
            Registered, ///< Startup accepted; Notify cadence running.
            Rejected,   ///< Version rejected; slow re-Startup.
            AuthError,  ///< Persistent auth failure; slow re-sign retry.
            Stopping    ///< Draining toward stop.
        };

        enum class Event
        {
            StartupAccepted,
            StartupRejected, ///< 409 / 400 at Startup or Notify.
            AuthFailed,      ///< 401.
            TransientFailure,
            NotifyOk,
            SettingsChanged,   ///< settings_hash mismatch: refresh Startup in place.
            CredentialRenewed, ///< hc_set_agent_key after 401: leave AuthError.
            Stop
        };

        enum class ActionKind
        {
            Startup,       ///< Send Startup (Starting/Rejected/AuthError).
            Notify,        ///< Send Notify (Registered).
            Idle           ///< Draining/Stopping: nothing to send.
        };

        struct Effects
        {
            bool releaseGate {false};    ///< Startup accepted: release the producer gate.
            bool applyHandshake {false}; ///< Apply the returned handshake JSON.
            bool stateChanged {false};   ///< The published hc_conn_state_t changed.
            bool slowCadence {false};    ///< Use the rejected-retry interval, not notify.
            /// Startup was just accepted (first connect, reconnect, or a settings-refresh
            /// in place): the hashes and any pending tasks only ever arrive on Notify, so
            /// the caller should send one immediately instead of waiting a full notify
            /// cycle for it.
            bool resetCadence {false};
        };

        ControlStateMachine() = default;
        // Movable (the atomics are loaded) so it can be returned by value;
        // production holds it as a plain member and never copies it.
        ControlStateMachine(ControlStateMachine&& other) noexcept
            : m_state(other.m_state.load())
            , m_startupRequested(other.m_startupRequested.load())
        {
        }

        /// The next request to issue given the current state.
        ActionKind nextAction() const;

        /// Applies an event; returns the side effects the caller must run.
        Effects onEvent(Event event);

        State state() const
        {
            return m_state.load(std::memory_order_acquire);
        }

        /// Maps the internal state onto the ABI's hc_conn_state_t.
        hc_conn_state_t connState() const;

        bool useSlowCadence() const
        {
            const State current = state();
            return current == State::Rejected || current == State::AuthError;
        }

    private:
        Effects transitionTo(State next);

        /// Written by the control thread, read (via state()/connState()) by any
        /// thread through the facade — so it is atomic.
        std::atomic<State> m_state {State::Starting};

        /// Armed by SettingsChanged while Registered: the next action is one
        /// in-place Startup (the gate stays open, the state stays Registered).
        std::atomic<bool> m_startupRequested {false};
};

#endif // _HC_CONTROL_STATE_MACHINE_HPP
