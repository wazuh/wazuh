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

#include <gtest/gtest.h>

using State = ControlStateMachine::State;
using Event = ControlStateMachine::Event;
using ActionKind = ControlStateMachine::ActionKind;

namespace
{
    ControlStateMachine inState(State target)
    {
        ControlStateMachine machine; // Starts in Starting.

        switch (target)
        {
            case State::Starting:
                break;

            case State::Registered:
                machine.onEvent(Event::StartupAccepted);
                break;

            case State::Rejected:
                machine.onEvent(Event::StartupRejected);
                break;

            case State::AuthError:
                machine.onEvent(Event::AuthFailed);
                break;

            case State::Stopping:
                machine.onEvent(Event::Stop);
                break;
        }

        return machine;
    }
} // namespace

TEST(ControlStateMachineTest, StartsInStartingRequestingStartup)
{
    ControlStateMachine machine;
    EXPECT_EQ(State::Starting, machine.state());
    EXPECT_EQ(ActionKind::Startup, machine.nextAction());
    EXPECT_EQ(HC_STATE_STARTING, machine.connState());
    EXPECT_FALSE(machine.useSlowCadence()); // First Startup is prompt, not slow.
}

TEST(ControlStateMachineTest, StartupAcceptedRegistersAndReleasesGate)
{
    ControlStateMachine machine;
    const auto effects = machine.onEvent(Event::StartupAccepted);
    EXPECT_EQ(State::Registered, machine.state());
    EXPECT_TRUE(effects.releaseGate);
    EXPECT_TRUE(effects.applyHandshake);
    EXPECT_TRUE(effects.stateChanged);
    EXPECT_TRUE(effects.resetCadence);
    EXPECT_EQ(ActionKind::Notify, machine.nextAction());
    EXPECT_FALSE(machine.useSlowCadence());
}

TEST(ControlStateMachineTest, StartupRejectedGoesRejectedWithSlowCadence)
{
    ControlStateMachine machine;
    const auto effects = machine.onEvent(Event::StartupRejected);
    EXPECT_EQ(State::Rejected, machine.state());
    EXPECT_TRUE(effects.slowCadence);
    EXPECT_TRUE(effects.stateChanged);
    EXPECT_EQ(ActionKind::Startup, machine.nextAction()); // Keeps retrying Startup.
    EXPECT_EQ(HC_STATE_REJECTED, machine.connState());
}

TEST(ControlStateMachineTest, AuthFailedGoesAuthErrorAndCanRecover)
{
    ControlStateMachine machine;
    machine.onEvent(Event::AuthFailed);
    EXPECT_EQ(State::AuthError, machine.state());
    EXPECT_EQ(HC_STATE_AUTH_ERROR, machine.connState());
    EXPECT_EQ(ActionKind::Startup, machine.nextAction());

    // A successful request later recovers to Registered.
    const auto effects = machine.onEvent(Event::NotifyOk);
    EXPECT_EQ(State::Registered, machine.state());
    EXPECT_TRUE(effects.stateChanged);
}

TEST(ControlStateMachineTest, RegisteredNotifyOkStaysRegisteredNoChange)
{
    auto machine = inState(State::Registered);
    const auto effects = machine.onEvent(Event::NotifyOk);
    EXPECT_EQ(State::Registered, machine.state());
    EXPECT_FALSE(effects.stateChanged);
}

TEST(ControlStateMachineTest, RegisteredAuthFailedDemotesToAuthError)
{
    auto machine = inState(State::Registered);
    const auto effects = machine.onEvent(Event::AuthFailed);
    EXPECT_EQ(State::AuthError, machine.state());
    EXPECT_TRUE(effects.slowCadence);
    EXPECT_TRUE(effects.stateChanged);
}

TEST(ControlStateMachineTest, RegisteredVersionRejectionDemotesToRejected)
{
    auto machine = inState(State::Registered);
    // A 426 arriving during Notify (StartupRejected event) demotes.
    const auto effects = machine.onEvent(Event::StartupRejected);
    EXPECT_EQ(State::Rejected, machine.state());
    EXPECT_TRUE(effects.slowCadence);
}

TEST(ControlStateMachineTest, TransientFailureNeverChangesState)
{
    for (const auto state :
            {
                State::Starting, State::Registered, State::Rejected, State::AuthError
            })
    {
        auto machine = inState(state);
        const auto effects = machine.onEvent(Event::TransientFailure);
        EXPECT_EQ(state, machine.state());
        EXPECT_FALSE(effects.stateChanged);
    }
}

TEST(ControlStateMachineTest, StopFromEveryStateGoesStopping)
{
    for (const auto state :
            {
                State::Starting, State::Registered, State::Rejected, State::AuthError
            })
    {
        auto machine = inState(state);
        machine.onEvent(Event::Stop);
        EXPECT_EQ(State::Stopping, machine.state());
        EXPECT_EQ(ActionKind::Idle, machine.nextAction());
        EXPECT_EQ(HC_STATE_STOPPED, machine.connState());
    }
}

TEST(ControlStateMachineTest, RejectedRecoversOnStartupAccepted)
{
    auto machine = inState(State::Rejected);
    const auto effects = machine.onEvent(Event::StartupAccepted);
    EXPECT_EQ(State::Registered, machine.state());
    EXPECT_TRUE(effects.releaseGate);
}

TEST(ControlStateMachineTest, NotifyOkFromStartingIsANoOp)
{
    // NotifyOk only recovers AuthError; from Starting it changes nothing.
    ControlStateMachine machine;
    const auto effects = machine.onEvent(Event::NotifyOk);
    EXPECT_EQ(State::Starting, machine.state());
    EXPECT_FALSE(effects.stateChanged);
}
