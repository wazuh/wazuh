/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "vd/serverScanCoordinator.hpp"

#include "vd/agentInFlightRegistry.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <memory>

using invsync::vd::AgentInFlightRegistry;
using invsync::vd::ServerScanCoordinator;

/*
 * ServerScanCoordinator fences an agent out of session dispatch for the vulnerability scanner's
 * feed-update scans, and waits for anything already in flight to drain -- all through the shared
 * AgentInFlightRegistry, because with the scan synchronous "session in flight" and "scan in
 * flight" are the same thing (doc 06 §5), so no separate session table is needed.
 */

namespace
{
    struct CoordinatorUnderTest
    {
        std::shared_ptr<AgentInFlightRegistry> registry {std::make_shared<AgentInFlightRegistry>()};
        std::shared_ptr<ServerScanCoordinator> coordinator;

        explicit CoordinatorUnderTest(std::chrono::seconds pauseQuiesceTimeout = std::chrono::seconds {5})
            : coordinator {std::make_shared<ServerScanCoordinator>(registry, pauseQuiesceTimeout)}
        {
        }
    };
} // namespace

TEST(ServerScanCoordinatorTest, TheFenceQuiescesTheAgentAndComesOffOnResume)
{
    CoordinatorUnderTest fixture;

    EXPECT_TRUE(fixture.coordinator->pauseAgent("001", "feed update full scan in progress"));
    EXPECT_TRUE(fixture.registry->isPaused("001"));
    EXPECT_FALSE(fixture.registry->isFree("001")) << "a fenced agent must not dispatch";

    fixture.coordinator->resumeAgent("001");
    EXPECT_TRUE(fixture.registry->isFree("001"));
}

/**
 * Fenced means QUIESCED, and the wait for that is BOUNDED: a scan-length stall must not hold up the
 * whole fleet pass. On timeout the fence comes off, because the caller is told it failed and will
 * never resume it.
 */
TEST(ServerScanCoordinatorTest, AFenceThatCannotQuiesceInTimeIsRefusedAndLeavesNoFenceBehind)
{
    CoordinatorUnderTest fixture {std::chrono::seconds {0}};
    ASSERT_TRUE(fixture.registry->tryAcquire("001", AgentInFlightRegistry::Lane::Pipeline, true));

    EXPECT_FALSE(fixture.coordinator->pauseAgent("001", "feed update full scan in progress"));
    EXPECT_FALSE(fixture.registry->isPaused("001")) << "a refused fence must not leave the agent parked";

    fixture.registry->release("001", AgentInFlightRegistry::Lane::Pipeline);
    EXPECT_TRUE(fixture.registry->isFree("001"));
}
