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

#include "sync/fullSessionValidator.hpp"
#include "sync/syncPipeline.hpp"
#include "testIndexerConnectorFakes.hpp"
#include "testSessionBuilder.hpp"
#include "vd/agentInFlightRegistry.hpp"
#include "vd/vdScanLane.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <variant>
#include <vector>

using invsync::http::HttpRequest;
using invsync::http::HttpResponse;
using invsync::http::IHttpResponder;
using invsync::sync::SyncPipeline;
using invsync::test::ConnectorEvents;
using invsync::test::FakeIndexerConnectorSync;
using invsync::test::FakeVdScanner;
using invsync::test::SessionSpec;
using invsync::test::ValueSpec;
using invsync::vd::AgentInFlightRegistry;
using invsync::vd::ServerScanCoordinator;
using invsync::vd::VdScanLane;
using invsync::vd::VdScanLaneConfig;

/*
 * ServerScanCoordinator answers the vulnerability scanner's feed-update questions from the shared
 * agent registry plus the lane's short queue -- there is no session table, because with the scan
 * synchronous "session in flight" and "scan in flight" are the same thing (doc 06 §5).
 *
 * Two things here are easy to get wrong and are what these tests pin:
 *   - the lane is held WEAKLY, so a scanner call that raced stop() must degrade to "no sessions"
 *     instead of touching a torn-down lane;
 *   - "active" spans BOTH being applied (visible in the registry) and still queued (invisible there,
 *     because queued items acquire only at dispatch), which is why the answer is a bounded poll.
 */

namespace
{
    constexpr auto CLUSTER {"test-cluster"};
    constexpr auto WAIT {std::chrono::seconds {10}};

    class FutureResponder final : public IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            if (!m_sent.exchange(true))
            {
                m_promise.set_value(std::move(response));
            }
        }

        HttpResponse get()
        {
            auto future = m_promise.get_future();
            if (future.wait_for(WAIT) != std::future_status::ready)
            {
                ADD_FAILURE() << "no response arrived within the deadline";
                return HttpResponse {0, "", {}};
            }
            return future.get();
        }

    private:
        std::promise<HttpResponse> m_promise;
        std::atomic<bool> m_sent {false};
    };

    SyncPipeline::Item makeItem(std::string body, std::shared_ptr<FutureResponder> responder, const char* agent)
    {
        auto request = std::make_shared<HttpRequest>();
        request->body = std::move(body);

        auto result = invsync::sync::validateFullSession(request->body, agent, CLUSTER);
        auto* session = std::get_if<invsync::sync::ValidatedSession>(&result);
        if (session == nullptr)
        {
            throw std::runtime_error {"test session failed validation"};
        }
        return SyncPipeline::Item {request, std::move(responder), std::move(*session)};
    }

    std::string vdBody(invsync::test::fb::Option option, const char* agentId, const char* docId)
    {
        SessionSpec spec;
        spec.option = option;
        spec.agentId = agentId;
        ValueSpec value;
        value.id = docId;
        return invsync::test::buildSyncDataSession(spec, {value});
    }

    bool waitFor(const std::function<bool()>& condition)
    {
        const auto deadline = std::chrono::steady_clock::now() + WAIT;
        while (std::chrono::steady_clock::now() < deadline)
        {
            if (condition())
            {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds {5});
        }
        return false;
    }

    struct CoordinatorUnderTest
    {
        std::shared_ptr<ConnectorEvents> events {std::make_shared<ConnectorEvents>()};
        std::shared_ptr<AgentInFlightRegistry> registry {std::make_shared<AgentInFlightRegistry>()};
        std::shared_ptr<VdScanLane> lane;
        std::shared_ptr<ServerScanCoordinator> coordinator;

        explicit CoordinatorUnderTest(VdScanLaneConfig config = {},
                                      std::chrono::seconds pauseQuiesceTimeout = std::chrono::seconds {5})
        {
            lane = std::make_shared<VdScanLane>(config,
                                                std::make_shared<FakeVdScanner>(events),
                                                std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> {
                                                    std::make_shared<FakeIndexerConnectorSync>(events, "sync")},
                                                registry,
                                                CLUSTER);
            coordinator = std::make_shared<ServerScanCoordinator>(registry, lane, pauseQuiesceTimeout);
        }

        ~CoordinatorUnderTest()
        {
            // A failed ASSERT may leave a worker parked at a closed gate, and the lane's stop()
            // would then join forever. Opening the gates makes teardown unconditional.
            events->openScanGate();
            events->openFlushGate();
        }
    };
} // namespace

TEST(ServerScanCoordinatorTest, AQuietServerReportsNoSessionsAnywhere)
{
    CoordinatorUnderTest fixture;

    EXPECT_TRUE(fixture.coordinator->agentsWithActiveVDFirstSessions().empty());
    EXPECT_FALSE(fixture.coordinator->waitForVDSyncSessionsToDrain(std::chrono::seconds {1}))
        << "nothing to wait for reports false";
    EXPECT_FALSE(fixture.coordinator->hasActiveSessionForAgent("001", std::chrono::seconds {0}));
}

/// The feed-update fleet scan skips these agents: their own first scan is already coming.
TEST(ServerScanCoordinatorTest, AgentsWithAVDFirstSessionInFlightAreReportedToTheScanner)
{
    CoordinatorUnderTest fixture;
    fixture.events->closeScanGate();

    auto responder = std::make_shared<FutureResponder>();
    ASSERT_EQ(
        VdScanLane::Admission::Accepted,
        fixture.lane->tryEnqueue(makeItem(vdBody(invsync::test::fb::Option_VDFirst, "1", "doc-1"), responder, "1")));
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_scanEntered.load() == 1; }));

    const auto agents = fixture.coordinator->agentsWithActiveVDFirstSessions();
    EXPECT_EQ(1U, agents.size());
    EXPECT_EQ(1U, agents.count("001"));

    fixture.events->openScanGate();
    EXPECT_EQ(200, responder->get().status);
}

/**
 * The drain reports whether there WAS anything to wait for -- that is what the scanner logs -- and
 * it must actually wait for it, not just answer.
 */
TEST(ServerScanCoordinatorTest, TheDrainWaitsForAnInFlightVDSyncSessionAndReportsItHadOne)
{
    CoordinatorUnderTest fixture;
    fixture.events->closeScanGate();

    auto responder = std::make_shared<FutureResponder>();
    ASSERT_EQ(
        VdScanLane::Admission::Accepted,
        fixture.lane->tryEnqueue(makeItem(vdBody(invsync::test::fb::Option_VDSync, "1", "doc-1"), responder, "1")));
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_scanEntered.load() == 1; }));

    // Let the session finish while the drain is blocked on it, so the wait is satisfied rather
    // than merely timing out.
    std::thread opener {[&fixture]
                        {
                            std::this_thread::sleep_for(std::chrono::milliseconds {30});
                            fixture.events->openScanGate();
                        }};

    EXPECT_TRUE(fixture.coordinator->waitForVDSyncSessionsToDrain(WAIT));
    opener.join();

    EXPECT_EQ(200, responder->get().status);
    EXPECT_FALSE(fixture.coordinator->waitForVDSyncSessionsToDrain(std::chrono::seconds {1}))
        << "drained: there is nothing left to have waited for";
}

/// Being APPLIED is visible in the registry, and the answer holds until the deadline.
TEST(ServerScanCoordinatorTest, AnAgentBeingScannedIsActiveUntilTheTimeoutExpires)
{
    CoordinatorUnderTest fixture;
    fixture.events->closeScanGate();

    auto responder = std::make_shared<FutureResponder>();
    ASSERT_EQ(
        VdScanLane::Admission::Accepted,
        fixture.lane->tryEnqueue(makeItem(vdBody(invsync::test::fb::Option_VDFirst, "1", "doc-1"), responder, "1")));
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_scanEntered.load() == 1; }));

    // A non-zero timeout so the bounded poll actually loops before giving its answer.
    EXPECT_TRUE(fixture.coordinator->hasActiveSessionForAgent("001", std::chrono::seconds {1}));
    EXPECT_FALSE(fixture.coordinator->hasActiveSessionForAgent("002", std::chrono::seconds {0}))
        << "another agent is unaffected";

    fixture.events->openScanGate();
    EXPECT_EQ(200, responder->get().status);
}

/**
 * A QUEUED session is invisible to the registry (queued items acquire the agent only at dispatch),
 * so the lane's queue is the other half of the answer. Missing this would let a feed-update scan
 * run against an agent whose session is about to land.
 */
TEST(ServerScanCoordinatorTest, AnAgentStillWaitingInTheQueueCountsAsActive)
{
    VdScanLaneConfig config;
    config.workers = 1;
    config.queueSlots = 4;
    CoordinatorUnderTest fixture {config};
    fixture.events->closeScanGate();

    auto busy = std::make_shared<FutureResponder>();
    ASSERT_EQ(VdScanLane::Admission::Accepted,
              fixture.lane->tryEnqueue(makeItem(vdBody(invsync::test::fb::Option_VDFirst, "1", "doc-1"), busy, "1")));
    ASSERT_TRUE(waitFor([&] { return fixture.events->m_scanEntered.load() == 1; }));

    // The single worker is parked, so this one stays queued and never touches the registry.
    auto queued = std::make_shared<FutureResponder>();
    ASSERT_EQ(VdScanLane::Admission::Accepted,
              fixture.lane->tryEnqueue(makeItem(vdBody(invsync::test::fb::Option_VDFirst, "2", "doc-2"), queued, "2")));

    EXPECT_TRUE(fixture.registry->isFree("002")) << "queued work holds nothing yet";
    EXPECT_TRUE(fixture.coordinator->hasActiveSessionForAgent("002", std::chrono::seconds {0}))
        << "but the coordinator must still see it";

    fixture.events->openScanGate();
    EXPECT_EQ(200, busy->get().status);
    EXPECT_EQ(200, queued->get().status);
}

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
    CoordinatorUnderTest fixture {VdScanLaneConfig {}, std::chrono::seconds {0}};
    ASSERT_TRUE(fixture.registry->tryAcquire("001", AgentInFlightRegistry::Lane::Pipeline, true));

    EXPECT_FALSE(fixture.coordinator->pauseAgent("001", "feed update full scan in progress"));
    EXPECT_FALSE(fixture.registry->isPaused("001")) << "a refused fence must not leave the agent parked";

    fixture.registry->release("001", AgentInFlightRegistry::Lane::Pipeline);
    EXPECT_TRUE(fixture.registry->isFree("001"));
}

/**
 * stop() removes this coordinator from the scanner's registry before tearing the lane down, but a
 * call already past the registry snapshot can still land here. It must answer from the registry
 * alone rather than touch a dead lane.
 */
TEST(ServerScanCoordinatorTest, ADestroyedLaneDegradesToTheRegistryAlone)
{
    auto events = std::make_shared<ConnectorEvents>();
    auto registry = std::make_shared<AgentInFlightRegistry>();
    auto lane = std::make_shared<VdScanLane>(VdScanLaneConfig {},
                                             std::make_shared<FakeVdScanner>(events),
                                             std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> {
                                                 std::make_shared<FakeIndexerConnectorSync>(events, "sync")},
                                             registry,
                                             CLUSTER);
    ServerScanCoordinator coordinator {registry, lane, std::chrono::seconds {1}};

    lane->stop();
    lane.reset(); // the weak_ptr is now expired

    EXPECT_TRUE(coordinator.agentsWithActiveVDFirstSessions().empty());
    EXPECT_FALSE(coordinator.waitForVDSyncSessionsToDrain(std::chrono::seconds {1}));
    EXPECT_FALSE(coordinator.hasActiveSessionForAgent("001", std::chrono::seconds {0}));

    // The registry half still answers.
    ASSERT_TRUE(registry->tryAcquire("001", AgentInFlightRegistry::Lane::Pipeline, true));
    EXPECT_TRUE(coordinator.hasActiveSessionForAgent("001", std::chrono::seconds {0}));
    registry->release("001", AgentInFlightRegistry::Lane::Pipeline);
}
