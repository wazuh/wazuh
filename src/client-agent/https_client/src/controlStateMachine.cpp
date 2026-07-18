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
        return ActionKind::Notify;
    }

    if (m_state == State::Starting || m_state == State::Rejected || m_state == State::AuthError)
    {
        return ActionKind::Startup;
    }

    return ActionKind::Idle; // Stopping.
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
                auto effects = transitionTo(State::Registered);
                effects.releaseGate = true;
                effects.applyHandshake = true;
                effects.resetCadence = true;
                return effects;
            }

        case Event::StartupRejected:
            {
                auto effects = transitionTo(State::Rejected);
                effects.slowCadence = true;
                return effects;
            }

        case Event::AuthFailed:
            {
                auto effects = transitionTo(State::AuthError);
                effects.slowCadence = true;
                return effects;
            }

        case Event::NotifyOk:
            // A successful Notify from AuthError recovers to Registered.
            return (m_state == State::AuthError) ? transitionTo(State::Registered) : Effects {};
        case Event::TransientFailure:
        default:
            return Effects {}; // No state change; the retry loop handles it.
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
