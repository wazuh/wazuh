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

#include "controlStateMachine.hpp"

ControlStateMachine::ActionKind ControlStateMachine::nextAction() const
{
    if (m_state == State::Registered)
    {
        // A settings refresh replaces the next Notify with one Startup.
        return m_startupRequested ? ActionKind::Startup : ActionKind::Notify;
    }

    if (m_state == State::Starting || m_state == State::Rejected)
    {
        return ActionKind::Startup;
    }

    // AuthError and Stopping send nothing: AuthError waits for a new key
    // (all traffic paused, #37828); Stopping is draining.
    return ActionKind::Idle;
}

ControlStateMachine::Effects ControlStateMachine::onEvent(Event event)
{
    if (event == Event::Stop)
    {
        return transitionTo(State::Stopping);
    }

    switch (event)
    {
        case Event::StartupAccepted:
            {
                m_startupRequested = false; // A refresh, if armed, is done.
                auto effects = transitionTo(State::Registered);
                effects.releaseGate = true;
                effects.applyHandshake = true;
                effects.resetCadence = true;
                return effects;
            }

        case Event::StartupRejected:
            {
                m_startupRequested = false; // The slow re-Startup takes over.
                auto effects = transitionTo(State::Rejected);
                effects.slowCadence = true;
                return effects;
            }

        case Event::AuthFailed:
            {
                // 401: the credential is dead. All traffic pauses (via the
                // AuthGate); recovery is hc_set_agent_key -> CredentialRenewed,
                // NOT a slow re-sign. An armed settings refresh is dropped.
                m_startupRequested = false;
                return transitionTo(State::AuthError);
            }

        case Event::CredentialRenewed:
            // A new key is in place: leave AuthError and re-register.
            return (m_state == State::AuthError) ? transitionTo(State::Starting) : Effects {};

        case Event::SettingsChanged:

            // Only meaningful while Registered: request one in-place Startup.
            // No state change, no effects (connState stays REGISTERED).
            if (m_state == State::Registered)
            {
                m_startupRequested = true;
            }

            return Effects {};

        case Event::NotifyOk:
        case Event::TransientFailure:
        default:
            // No state change; the retry loop handles it, and an armed
            // refresh survives for the next cycle.
            return Effects {};
    }
}

hc_conn_state_t ControlStateMachine::connState() const
{
    if (m_state == State::Starting)
    {
        return HC_STATE_STARTING;
    }

    if (m_state == State::Registered)
    {
        return HC_STATE_REGISTERED;
    }

    if (m_state == State::Rejected)
    {
        return HC_STATE_REJECTED;
    }

    if (m_state == State::AuthError)
    {
        return HC_STATE_AUTH_ERROR;
    }

    return HC_STATE_STOPPED; // Stopping.
}

ControlStateMachine::Effects ControlStateMachine::transitionTo(State next)
{
    Effects effects;
    effects.stateChanged = (m_state != next);
    m_state = next;
    return effects;
}
