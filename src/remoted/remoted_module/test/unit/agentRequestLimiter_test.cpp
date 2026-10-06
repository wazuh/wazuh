/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * October 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Validates the per-agent AgentRequestLimiter and its AdmittedResponder: the cap is per agent and
// never shared between agents, a released slot frees its agent's share and erases an idle entry,
// the responder gives the slot back when the reply leaves (or when it is dropped unanswered), and
// the accounting stays exact under concurrency.
#include "endpoints/agentRequestLimiter.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using remoted::endpoints::AdmittedResponder;
using remoted::endpoints::AgentRequestLimiter;

namespace
{
    class CountingResponder final : public remoted::http::IHttpResponder
    {
    public:
        void send(remoted::http::HttpResponse response) override
        {
            ++sends;
            lastStatus = response.status;
        }
        void stream(remoted::http::StreamResponse) override
        {
            ++streams;
        }
        int sends {0};
        int streams {0};
        int lastStatus {0};
    };
} // namespace

TEST(AgentRequestLimiter, AcquireUpToTheCapThenRefuse)
{
    const auto limiter = std::make_shared<AgentRequestLimiter>(2);
    EXPECT_EQ(limiter->capacity(), 2U);

    auto a = limiter->tryAcquire("001");
    auto b = limiter->tryAcquire("001");
    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());
    EXPECT_TRUE(static_cast<bool>(*a));
    EXPECT_EQ(limiter->openRequests("001"), 2U);

    EXPECT_FALSE(limiter->tryAcquire("001").has_value());
    EXPECT_EQ(limiter->rejectedTotal(), 1U);
    EXPECT_EQ(limiter->openRequests("001"), 2U) << "a refusal must not count as an open request";
}

TEST(AgentRequestLimiter, OneAgentAtItsCapDoesNotTouchAnother)
{
    // The whole point of the limiter: the busy agent is refused, everyone else is not.
    const auto limiter = std::make_shared<AgentRequestLimiter>(1);
    auto busy = limiter->tryAcquire("001");
    ASSERT_TRUE(busy.has_value());
    EXPECT_FALSE(limiter->tryAcquire("001").has_value());

    auto other = limiter->tryAcquire("002");
    ASSERT_TRUE(other.has_value());
    EXPECT_EQ(limiter->openRequests("002"), 1U);
    EXPECT_EQ(limiter->trackedAgents(), 2U);
}

TEST(AgentRequestLimiter, ReleasingFreesTheShareAndErasesAnIdleAgent)
{
    // The table must hold only agents with a request open, or it would grow with the fleet.
    const auto limiter = std::make_shared<AgentRequestLimiter>(1);
    {
        auto slot = limiter->tryAcquire("001");
        ASSERT_TRUE(slot.has_value());
        EXPECT_EQ(limiter->trackedAgents(), 1U);
    }
    EXPECT_EQ(limiter->openRequests("001"), 0U);
    EXPECT_EQ(limiter->trackedAgents(), 0U);
    EXPECT_TRUE(limiter->tryAcquire("001").has_value());
}

TEST(AgentRequestLimiter, ASlotReleasesExactlyOnceAcrossMovesAndExplicitRelease)
{
    const auto limiter = std::make_shared<AgentRequestLimiter>(2);
    auto first = limiter->tryAcquire("001");
    auto second = limiter->tryAcquire("001");
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());

    AgentRequestLimiter::Slot moved {std::move(*first)};
    EXPECT_FALSE(static_cast<bool>(*first));
    EXPECT_EQ(limiter->openRequests("001"), 2U) << "a move transfers the slot, it does not release it";

    moved.release();
    moved.release(); // idempotent
    EXPECT_EQ(limiter->openRequests("001"), 1U);

    // Move-assigning over a held slot releases the one being overwritten.
    auto third = limiter->tryAcquire("001");
    ASSERT_TRUE(third.has_value());
    EXPECT_EQ(limiter->openRequests("001"), 2U);
    *second = std::move(*third);
    EXPECT_EQ(limiter->openRequests("001"), 1U);
    second.reset();
    EXPECT_EQ(limiter->openRequests("001"), 0U);
}

TEST(AgentRequestLimiter, CapacityZeroDisablesTheLimit)
{
    const auto limiter = std::make_shared<AgentRequestLimiter>(0);
    std::vector<AgentRequestLimiter::Slot> slots;
    for (int i = 0; i < 100; ++i)
    {
        auto slot = limiter->tryAcquire("001");
        ASSERT_TRUE(slot.has_value());
        slots.push_back(std::move(*slot));
    }
    EXPECT_EQ(limiter->trackedAgents(), 0U) << "a disabled limiter tracks nothing";
    EXPECT_EQ(limiter->rejectedTotal(), 0U);
}

TEST(AgentRequestLimiter, ASlotKeepsItsLimiterAliveAfterTheLastOtherOwnerIsGone)
{
    // The gateway's routes own the limiter; a reply delivered after they are gone (a forward still
    // in flight during shutdown) must release safely, not touch freed memory.
    std::optional<AgentRequestLimiter::Slot> slot;
    {
        auto limiter = std::make_shared<AgentRequestLimiter>(1);
        slot = limiter->tryAcquire("001");
        ASSERT_TRUE(slot.has_value());
    }
    slot.reset(); // runs under ASan without a use-after-free
}

TEST(AgentRequestLimiter, ConcurrentAcquiresNeverExceedTheCap)
{
    constexpr std::size_t kCap = 4;
    constexpr int kThreads = 32;
    const auto limiter = std::make_shared<AgentRequestLimiter>(kCap);

    std::atomic<int> admitted {0};
    std::atomic<bool> go {false};
    std::vector<std::optional<AgentRequestLimiter::Slot>> held(kThreads);
    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i)
    {
        threads.emplace_back(
            [&, i]
            {
                while (!go.load())
                {
                    std::this_thread::yield();
                }
                held[static_cast<std::size_t>(i)] = limiter->tryAcquire("001");
                if (held[static_cast<std::size_t>(i)].has_value())
                {
                    admitted.fetch_add(1);
                }
            });
    }
    go.store(true);
    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(static_cast<std::size_t>(admitted.load()), kCap);
    EXPECT_EQ(limiter->openRequests("001"), kCap);
    EXPECT_EQ(limiter->rejectedTotal(), static_cast<std::uint64_t>(kThreads) - kCap);
    held.clear();
    EXPECT_EQ(limiter->trackedAgents(), 0U);
}

TEST(AdmittedResponder, ReleasesTheSlotWhenTheReplyLeaves)
{
    const auto limiter = std::make_shared<AgentRequestLimiter>(1);
    const auto inner = std::make_shared<CountingResponder>();
    auto slot = limiter->tryAcquire("001");
    ASSERT_TRUE(slot.has_value());

    // Something (a forward, a parked handler) still holds the responder after it answers: the slot
    // must not wait for that last owner, only for the reply.
    const auto responder = std::make_shared<AdmittedResponder>(inner, std::move(*slot));
    EXPECT_EQ(limiter->openRequests("001"), 1U);
    responder->send(remoted::http::HttpResponse::json(200, "{}"));
    EXPECT_EQ(inner->sends, 1);
    EXPECT_EQ(inner->lastStatus, 200);
    EXPECT_EQ(limiter->openRequests("001"), 0U);
}

TEST(AdmittedResponder, ReleasesTheSlotWhenAStreamIsHandedOver)
{
    const auto limiter = std::make_shared<AgentRequestLimiter>(1);
    const auto inner = std::make_shared<CountingResponder>();
    auto slot = limiter->tryAcquire("001");
    ASSERT_TRUE(slot.has_value());

    const auto responder = std::make_shared<AdmittedResponder>(inner, std::move(*slot));
    responder->stream(remoted::http::StreamResponse {});
    EXPECT_EQ(inner->streams, 1);
    EXPECT_EQ(limiter->openRequests("001"), 0U);
}

TEST(AdmittedResponder, ReleasesTheSlotWhenDroppedUnanswered)
{
    const auto limiter = std::make_shared<AgentRequestLimiter>(1);
    auto slot = limiter->tryAcquire("001");
    ASSERT_TRUE(slot.has_value());
    {
        AdmittedResponder responder {std::make_shared<CountingResponder>(), std::move(*slot)};
        EXPECT_EQ(limiter->openRequests("001"), 1U);
    }
    EXPECT_EQ(limiter->openRequests("001"), 0U);
}
