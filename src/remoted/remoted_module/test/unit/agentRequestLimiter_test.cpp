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
        // Keeps the source like the transport's pump does, so a test decides when the transfer ends.
        void stream(remoted::http::StreamResponse response) override
        {
            ++streams;
            source = std::move(response.source);
        }
        std::shared_ptr<remoted::http::IByteSource> source;
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

namespace
{
    class FixedByteSource final : public remoted::http::IByteSource
    {
    public:
        std::size_t read(char* buffer, std::size_t capacity) override
        {
            const std::size_t n = capacity < 3 ? capacity : 3;
            for (std::size_t i = 0; i < n; ++i)
            {
                buffer[i] = 'x';
            }
            return n;
        }
    };
} // namespace

// A download counts for as long as it runs, not just until it starts: the slot rides in the stream
// source, which the transport's pump drops only when the transfer ends. Otherwise one agent could
// hold the fleet-wide connection cap with slow downloads its request cap never saw.
TEST(AdmittedResponder, AStreamHoldsTheSlotUntilTheTransportDropsTheSource)
{
    const auto limiter = std::make_shared<AgentRequestLimiter>(1);
    const auto inner = std::make_shared<CountingResponder>();
    auto slot = limiter->tryAcquire("001");
    ASSERT_TRUE(slot.has_value());

    const auto responder = std::make_shared<AdmittedResponder>(inner, std::move(*slot));
    remoted::http::StreamResponse response;
    response.source = std::make_shared<FixedByteSource>();
    responder->stream(std::move(response));
    ASSERT_EQ(inner->streams, 1);
    ASSERT_NE(inner->source, nullptr);
    EXPECT_EQ(limiter->openRequests("001"), 1U) << "still streaming";
    EXPECT_FALSE(limiter->tryAcquire("001").has_value()) << "a running download counts against the cap";

    // The wrapped source still reads through to the real one.
    char buffer[8] {};
    EXPECT_EQ(inner->source->read(buffer, sizeof(buffer)), 3U);
    EXPECT_EQ(buffer[0], 'x');

    inner->source.reset(); // the pump drops it: finished, failed, peer gone, or teardown
    EXPECT_EQ(limiter->openRequests("001"), 0U);
}

TEST(AdmittedResponder, AStreamWithoutASourceReleasesTheSlotAtOnce)
{
    const auto limiter = std::make_shared<AgentRequestLimiter>(1);
    const auto inner = std::make_shared<CountingResponder>();
    auto slot = limiter->tryAcquire("001");
    ASSERT_TRUE(slot.has_value());

    const auto responder = std::make_shared<AdmittedResponder>(inner, std::move(*slot));
    responder->stream(remoted::http::StreamResponse {}); // misuse the transport answers 500 to
    EXPECT_EQ(inner->streams, 1);
    EXPECT_EQ(limiter->openRequests("001"), 0U);
}

// The byte share bounds what one agent's decoded bodies hold across ALL its open requests, so a
// route may accept one body far larger than any other without that agent holding the budget.
TEST(AgentRequestLimiter, ChargesFitTheByteShareAcrossTheAgentsRequests)
{
    const auto limiter = std::make_shared<AgentRequestLimiter>(4, 1000);
    EXPECT_EQ(limiter->byteShare(), 1000U);

    auto first = limiter->tryAcquire("001");
    auto second = limiter->tryAcquire("001");
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());

    EXPECT_TRUE(first->charge(600));
    EXPECT_FALSE(second->charge(401)) << "600 + 401 is over the share";
    EXPECT_EQ(limiter->heldBytes("001"), 600U) << "a refused charge takes nothing";
    EXPECT_TRUE(second->charge(400)) << "exactly at the share is fine";
    EXPECT_EQ(limiter->heldBytes("001"), 1000U);
    EXPECT_EQ(limiter->rejectedTotal(), 1U);

    // Another agent has its own share.
    auto other = limiter->tryAcquire("002");
    ASSERT_TRUE(other.has_value());
    EXPECT_TRUE(other->charge(1000));

    // Releasing a slot gives its bytes back with it.
    first.reset();
    EXPECT_EQ(limiter->heldBytes("001"), 400U);
    EXPECT_TRUE(second->charge(600));
    second.reset();
    EXPECT_EQ(limiter->heldBytes("001"), 0U);
    EXPECT_EQ(limiter->trackedAgents(), 1U) << "only agent 002 is left";
}

TEST(AgentRequestLimiter, ChargedBytesMoveWithTheSlotAndAZeroShareIsUnlimited)
{
    const auto limiter = std::make_shared<AgentRequestLimiter>(2, 100);
    auto slot = limiter->tryAcquire("001");
    ASSERT_TRUE(slot.has_value());
    ASSERT_TRUE(slot->charge(100));

    AgentRequestLimiter::Slot moved {std::move(*slot)};
    slot.reset(); // the moved-from slot gives back nothing
    EXPECT_EQ(limiter->heldBytes("001"), 100U);
    moved.release();
    EXPECT_EQ(limiter->heldBytes("001"), 0U);

    const auto unlimited = std::make_shared<AgentRequestLimiter>(1, 0);
    auto big = unlimited->tryAcquire("001");
    ASSERT_TRUE(big.has_value());
    EXPECT_TRUE(big->charge(std::size_t {1} << 40));

    // A disabled limiter hands out disengaged slots, which accept any charge.
    const auto disabled = std::make_shared<AgentRequestLimiter>(0, 100);
    auto none = disabled->tryAcquire("001");
    ASSERT_TRUE(none.has_value());
    EXPECT_TRUE(none->charge(1000));
}

// A refund gives back part of a charge whose allocation did not happen, without closing the slot:
// the request is still open, only the bytes it was charged for a growth that never came are freed.
TEST(AgentRequestLimiter, ARefundGivesBytesBackAndKeepsTheSlotOpen)
{
    const auto limiter = std::make_shared<AgentRequestLimiter>(2, 1000);
    auto slot = limiter->tryAcquire("001");
    ASSERT_TRUE(slot.has_value());
    ASSERT_TRUE(slot->charge(800));

    slot->refund(700);
    EXPECT_EQ(limiter->heldBytes("001"), 100U);
    EXPECT_EQ(limiter->openRequests("001"), 1U);
    EXPECT_TRUE(slot->charge(900)) << "the refunded bytes are free for the next charge";

    slot->refund(5000); // clamped to what the slot holds
    EXPECT_EQ(limiter->heldBytes("001"), 0U);
    slot->release();
    EXPECT_EQ(limiter->trackedAgents(), 0U);

    // A disengaged slot (disabled limiter) ignores a refund like it accepts any charge.
    const auto disabled = std::make_shared<AgentRequestLimiter>(0, 100);
    auto none = disabled->tryAcquire("001");
    ASSERT_TRUE(none.has_value());
    none->refund(10);
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

namespace
{
    // Thread-safe stand-in for the transport's send-once responder, for the race below.
    class SendOnceResponder final : public remoted::http::IHttpResponder
    {
    public:
        void send(remoted::http::HttpResponse /*response*/) override
        {
            ++sends;
        }
        void stream(remoted::http::StreamResponse /*response*/) override
        {
            ++sends;
        }
        std::atomic<int> sends {0};
    };
} // namespace

// send() may race: the deferred forwarder's pool thread answering while the gateway's error path,
// after the handler threw, answers 500. The slot must be given back exactly once, or the agent's
// request count drops below what it holds and its byte total wraps.
TEST(AdmittedResponder, ConcurrentAnswersReleaseTheSlotExactlyOnce)
{
    constexpr int kRounds = 200;
    constexpr int kThreads = 8;
    const auto limiter = std::make_shared<AgentRequestLimiter>(2, 100);

    for (int round = 0; round < kRounds; ++round)
    {
        // A second request of the same agent stays open throughout: a double release would take
        // ITS count and bytes too.
        auto other = limiter->tryAcquire("001");
        ASSERT_TRUE(other.has_value());
        ASSERT_TRUE(other->charge(3));
        auto slot = limiter->tryAcquire("001");
        ASSERT_TRUE(slot.has_value());
        ASSERT_TRUE(slot->charge(5));

        const auto responder =
            std::make_shared<AdmittedResponder>(std::make_shared<SendOnceResponder>(), std::move(*slot));
        std::atomic<bool> go {false};
        std::vector<std::thread> threads;
        for (int t = 0; t < kThreads; ++t)
        {
            threads.emplace_back(
                [&go, &responder, t]
                {
                    while (!go.load())
                    {
                    }
                    if (t % 2 == 0)
                    {
                        responder->send(remoted::http::HttpResponse::json(200, "{}"));
                    }
                    else
                    {
                        responder->stream(remoted::http::StreamResponse {});
                    }
                });
        }
        go = true;
        for (auto& thread : threads)
        {
            thread.join();
        }

        ASSERT_EQ(limiter->openRequests("001"), 1U) << "round " << round;
        ASSERT_EQ(limiter->heldBytes("001"), 3U) << "round " << round;
        other->release();
        ASSERT_EQ(limiter->trackedAgents(), 0U) << "round " << round;
    }
}
