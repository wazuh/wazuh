/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "vd/agentInFlightRegistry.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

using invsync::vd::AgentInFlightRegistry;
using Lane = invsync::vd::AgentInFlightRegistry::Lane;

/*
 * The registry is the per-agent exclusion the sync pipeline and the VD scan lane share (D22), and
 * every rule in it exists because breaking it corrupts data or wedges an agent:
 *
 *   - reentrancy is per-LANE, because group commit legitimately has several of one agent's staged
 *     sessions on the same worker, while a second concurrent SCAN of one agent is exactly the
 *     duplicate the exclusion exists to stop;
 *   - release is lane-CHECKED, because the pipeline's stop() drain answers queued items whose agent
 *     may be mid-scan on the other lane, and an unchecked decrement would free that scan's hold;
 *   - waitUntilIdle deliberately ignores the pause flag, or the caller that pauses an agent and then
 *     waits for it to quiesce would wait on its own fence forever.
 */

TEST(AgentInFlightRegistryTest, AnUnknownAgentIsFreeAndAcquirable)
{
    AgentInFlightRegistry registry;

    EXPECT_TRUE(registry.isFree("001"));
    EXPECT_FALSE(registry.isPaused("001"));
    EXPECT_TRUE(registry.couldAcquire("001", Lane::Scan, false));
    EXPECT_TRUE(registry.tryAcquire("001", Lane::Scan, false));
    EXPECT_FALSE(registry.isFree("001"));
}

TEST(AgentInFlightRegistryTest, APausedAgentIsRefusedByBothLanes)
{
    AgentInFlightRegistry registry;
    registry.pause("001");

    EXPECT_TRUE(registry.isPaused("001"));
    EXPECT_FALSE(registry.isFree("001"));
    EXPECT_FALSE(registry.tryAcquire("001", Lane::Scan, false));
    EXPECT_FALSE(registry.tryAcquire("001", Lane::Pipeline, true));
    EXPECT_FALSE(registry.couldAcquire("001", Lane::Pipeline, true));

    registry.resume("001");
    EXPECT_TRUE(registry.isFree("001"));
    EXPECT_TRUE(registry.tryAcquire("001", Lane::Pipeline, true));
}

/// Group commit: several staged-but-unanswered sessions of one agent coexist on its single worker.
TEST(AgentInFlightRegistryTest, TheSameLaneReacquiresReentrantlyAndTheAgentFreesOnTheLastRelease)
{
    AgentInFlightRegistry registry;

    ASSERT_TRUE(registry.tryAcquire("001", Lane::Pipeline, true));
    ASSERT_TRUE(registry.tryAcquire("001", Lane::Pipeline, true));
    EXPECT_TRUE(registry.couldAcquire("001", Lane::Pipeline, true));

    registry.release("001", Lane::Pipeline);
    EXPECT_FALSE(registry.isFree("001")) << "one hold is still outstanding";

    registry.release("001", Lane::Pipeline);
    EXPECT_TRUE(registry.isFree("001"));
}

/// The scan lane passes reentrant=false: this is the "one scan per agent" dedup.
TEST(AgentInFlightRegistryTest, ASecondNonReentrantAcquireBySameLaneIsRefused)
{
    AgentInFlightRegistry registry;

    ASSERT_TRUE(registry.tryAcquire("001", Lane::Scan, false));
    EXPECT_FALSE(registry.tryAcquire("001", Lane::Scan, false));
    EXPECT_FALSE(registry.couldAcquire("001", Lane::Scan, false));
}

TEST(AgentInFlightRegistryTest, TheOtherLaneIsRefusedEvenReentrantly)
{
    AgentInFlightRegistry registry;

    ASSERT_TRUE(registry.tryAcquire("001", Lane::Scan, false));
    EXPECT_FALSE(registry.tryAcquire("001", Lane::Pipeline, true));
    EXPECT_FALSE(registry.couldAcquire("001", Lane::Pipeline, true));
}

/**
 * The pipeline's stop() drain answers items it never acquired, and their agent may be mid-scan.
 * An unchecked decrement there would release the SCAN lane's exclusion under it.
 */
TEST(AgentInFlightRegistryTest, ReleasingFromTheWrongLaneCannotBreakTheHolder)
{
    AgentInFlightRegistry registry;
    ASSERT_TRUE(registry.tryAcquire("001", Lane::Scan, false));

    registry.release("001", Lane::Pipeline);

    EXPECT_FALSE(registry.isFree("001")) << "the scan still holds it";
    registry.release("001", Lane::Scan);
    EXPECT_TRUE(registry.isFree("001"));
}

TEST(AgentInFlightRegistryTest, ReleasingAnAgentNobodyHoldsIsANoOp)
{
    AgentInFlightRegistry registry;

    EXPECT_NO_THROW(registry.release("001", Lane::Scan));
    EXPECT_TRUE(registry.isFree("001"));
}

TEST(AgentInFlightRegistryTest, WaitUntilIdleReturnsImmediatelyForAnIdleAgent)
{
    AgentInFlightRegistry registry;

    EXPECT_TRUE(registry.waitUntilIdle("001", std::chrono::milliseconds {0}));
}

TEST(AgentInFlightRegistryTest, WaitUntilIdleTimesOutWhileTheAgentIsHeld)
{
    AgentInFlightRegistry registry;
    ASSERT_TRUE(registry.tryAcquire("001", Lane::Scan, false));

    EXPECT_FALSE(registry.waitUntilIdle("001", std::chrono::milliseconds {20}));
}

/// The fence's own use case: pause, then wait for the in-flight work to drain. The wait must not
/// see the pause it is paired with as "busy".
TEST(AgentInFlightRegistryTest, WaitUntilIdleIgnoresThePauseFlagAndWakesOnRelease)
{
    AgentInFlightRegistry registry;
    ASSERT_TRUE(registry.tryAcquire("001", Lane::Scan, false));
    registry.pause("001");

    std::thread releaser {[&registry]
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds {20});
                              registry.release("001", Lane::Scan);
                          }};

    EXPECT_TRUE(registry.waitUntilIdle("001", std::chrono::seconds {10}));
    releaser.join();

    EXPECT_TRUE(registry.isPaused("001")) << "draining does not lift the fence";
}

/// The lanes park items of busy agents; the listener is how they learn "busy" may have ended.
TEST(AgentInFlightRegistryTest, ReleaseAndResumeNotifyTheRegisteredListeners)
{
    AgentInFlightRegistry registry;
    std::atomic<int> notifications {0};
    registry.addReleaseListener([&notifications] { ++notifications; });
    registry.addReleaseListener([&notifications] { ++notifications; });

    ASSERT_TRUE(registry.tryAcquire("001", Lane::Scan, false));
    EXPECT_EQ(0, notifications.load()) << "acquiring frees nobody";

    registry.release("001", Lane::Scan);
    EXPECT_EQ(2, notifications.load());

    registry.pause("001");
    EXPECT_EQ(2, notifications.load()) << "fencing frees nobody either";

    registry.resume("001");
    EXPECT_EQ(4, notifications.load());
}

TEST(AgentInFlightRegistryTest, HoldsAreIndependentPerAgent)
{
    AgentInFlightRegistry registry;

    ASSERT_TRUE(registry.tryAcquire("001", Lane::Scan, false));
    EXPECT_TRUE(registry.tryAcquire("002", Lane::Scan, false));
    registry.pause("002");

    EXPECT_FALSE(registry.isFree("001"));
    EXPECT_FALSE(registry.isPaused("001"));
    EXPECT_TRUE(registry.isPaused("002"));
}

/// The on-demand rescan fences its agent from inside the scan, on the lane worker that holds it.
/// That hold is the caller's own, so the drain must not wait for it -- it used to wait the whole
/// quiesce bound on every on-demand scan.
TEST(AgentInFlightRegistryTest, WaitUntilIdleCanIgnoreTheCallersOwnScanHold)
{
    AgentInFlightRegistry registry;
    ASSERT_TRUE(registry.tryAcquire("001", Lane::Scan, false));
    registry.pause("001");

    const auto start = std::chrono::steady_clock::now();
    EXPECT_TRUE(registry.waitUntilIdle("001", std::chrono::seconds {30}, /*ignoreCallersScanHold=*/true));
    EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds {1});

    EXPECT_FALSE(registry.isFree("001")) << "ignoring the hold for the drain does not release it";
    registry.release("001", Lane::Scan);
    registry.resume("001");
    EXPECT_TRUE(registry.isFree("001"));
}

/// Only the CALLER's scan hold is exempt: another thread's scan of the agent is real in-flight work.
TEST(AgentInFlightRegistryTest, AnotherThreadsScanHoldIsStillWaitedFor)
{
    AgentInFlightRegistry registry;
    std::thread holder {[&registry] { ASSERT_TRUE(registry.tryAcquire("001", Lane::Scan, false)); }};
    holder.join();

    EXPECT_FALSE(registry.waitUntilIdle("001", std::chrono::milliseconds {20}, /*ignoreCallersScanHold=*/true));

    registry.release("001", Lane::Scan);
    EXPECT_TRUE(registry.waitUntilIdle("001", std::chrono::milliseconds {0}, /*ignoreCallersScanHold=*/true));
}

/// A pipeline session is never the caller's scan, whichever thread holds it.
TEST(AgentInFlightRegistryTest, APipelineHoldIsStillWaitedForEvenOnTheCallersThread)
{
    AgentInFlightRegistry registry;
    ASSERT_TRUE(registry.tryAcquire("001", Lane::Pipeline, true));

    EXPECT_FALSE(registry.waitUntilIdle("001", std::chrono::milliseconds {20}, /*ignoreCallersScanHold=*/true));
}
