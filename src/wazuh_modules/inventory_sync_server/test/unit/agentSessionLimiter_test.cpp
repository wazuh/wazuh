/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * October 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// D28: the per-agent cap on sessions admitted and not yet answered, and the responder decorator that
// gives the slot back when the session is answered (or dropped unanswered).
#include "sync/agentSessionLimiter.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

using invsync::sync::AdmittedSessionResponder;
using invsync::sync::AgentSessionLimiter;

namespace
{
    class CountingResponder final : public wazuh::uds_http::IHttpResponder
    {
    public:
        void send(wazuh::uds_http::HttpResponse response) override
        {
            ++sends;
            lastStatus = response.status;
        }
        int sends {0};
        int lastStatus {0};
    };
} // namespace

TEST(AgentSessionLimiterTest, AdmitsUpToTheCapPerAgentAndNeverAcrossAgents)
{
    const auto limiter = std::make_shared<AgentSessionLimiter>(2);
    EXPECT_EQ(2U, limiter->capacity());
    auto a = limiter->tryAcquire("001");
    auto b = limiter->tryAcquire("001");
    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());
    EXPECT_FALSE(limiter->tryAcquire("001").has_value());
    EXPECT_EQ(1U, limiter->rejectedTotal());
    EXPECT_EQ(2U, limiter->pendingSessions("001"));

    auto other = limiter->tryAcquire("002");
    ASSERT_TRUE(other.has_value());
    EXPECT_EQ(2U, limiter->trackedAgents());
}

TEST(AgentSessionLimiterTest, ReleasingErasesAnIdleAgentAndIsIdempotentAcrossMoves)
{
    const auto limiter = std::make_shared<AgentSessionLimiter>(1);
    auto slot = limiter->tryAcquire("001");
    ASSERT_TRUE(slot.has_value());

    AgentSessionLimiter::Slot moved {std::move(*slot)};
    slot.reset(); // the moved-from slot gives back nothing
    EXPECT_EQ(1U, limiter->pendingSessions("001"));
    moved.release();
    moved.release();
    EXPECT_EQ(0U, limiter->pendingSessions("001"));
    EXPECT_EQ(0U, limiter->trackedAgents());
    EXPECT_TRUE(limiter->tryAcquire("001").has_value());
}

TEST(AgentSessionLimiterTest, CapacityZeroDisablesTheLimit)
{
    const auto limiter = std::make_shared<AgentSessionLimiter>(0);
    std::vector<AgentSessionLimiter::Slot> slots;
    for (int i = 0; i < 50; ++i)
    {
        auto slot = limiter->tryAcquire("001");
        ASSERT_TRUE(slot.has_value());
        slots.push_back(std::move(*slot));
    }
    EXPECT_EQ(0U, limiter->trackedAgents());
}

TEST(AgentSessionLimiterTest, ConcurrentAdmissionsNeverExceedTheCap)
{
    constexpr std::size_t kCap = 3;
    constexpr int kThreads = 24;
    const auto limiter = std::make_shared<AgentSessionLimiter>(kCap);

    std::atomic<bool> go {false};
    std::atomic<int> admitted {0};
    std::vector<std::optional<AgentSessionLimiter::Slot>> held(kThreads);
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

    EXPECT_EQ(kCap, static_cast<std::size_t>(admitted.load()));
    EXPECT_EQ(static_cast<std::uint64_t>(kThreads) - kCap, limiter->rejectedTotal());
    held.clear();
    EXPECT_EQ(0U, limiter->trackedAgents());
}

TEST(AdmittedSessionResponderTest, AnsweringTheSessionReleasesItsSlot)
{
    const auto limiter = std::make_shared<AgentSessionLimiter>(1);
    const auto inner = std::make_shared<CountingResponder>();
    auto slot = limiter->tryAcquire("001");
    ASSERT_TRUE(slot.has_value());

    // A worker still holds the responder after answering; only the answer matters.
    const auto responder = std::make_shared<AdmittedSessionResponder>(inner, std::move(*slot));
    EXPECT_EQ(1U, limiter->pendingSessions("001"));
    responder->send(wazuh::uds_http::HttpResponse {200, "{}", {}});
    EXPECT_EQ(1, inner->sends);
    EXPECT_EQ(200, inner->lastStatus);
    EXPECT_EQ(0U, limiter->pendingSessions("001"));
}

TEST(AdmittedSessionResponderTest, DroppingItUnansweredReleasesItsSlot)
{
    const auto limiter = std::make_shared<AgentSessionLimiter>(1);
    auto slot = limiter->tryAcquire("001");
    ASSERT_TRUE(slot.has_value());
    {
        AdmittedSessionResponder responder {std::make_shared<CountingResponder>(), std::move(*slot)};
        EXPECT_EQ(1U, limiter->pendingSessions("001"));
    }
    EXPECT_EQ(0U, limiter->pendingSessions("001"));
}

namespace
{
    // Thread-safe stand-in for the server's send-once responder, for the race below.
    class SendOnceResponder final : public wazuh::uds_http::IHttpResponder
    {
    public:
        void send(wazuh::uds_http::HttpResponse /*response*/) override
        {
            ++sends;
        }
        std::atomic<int> sends {0};
    };
} // namespace

// send() may race (an answering worker against an error path): the slot must be given back exactly
// once, or the agent's pending count drops below what it really has and it can exceed its cap.
TEST(AdmittedSessionResponderTest, ConcurrentAnswersReleaseTheSlotExactlyOnce)
{
    constexpr int kRounds = 200;
    constexpr int kThreads = 8;
    const auto limiter = std::make_shared<AgentSessionLimiter>(2);

    for (int round = 0; round < kRounds; ++round)
    {
        // A second session of the same agent stays pending throughout: a double release would
        // release it too.
        auto other = limiter->tryAcquire("001");
        ASSERT_TRUE(other.has_value());
        auto slot = limiter->tryAcquire("001");
        ASSERT_TRUE(slot.has_value());

        const auto responder =
            std::make_shared<AdmittedSessionResponder>(std::make_shared<SendOnceResponder>(), std::move(*slot));
        std::atomic<bool> go {false};
        std::vector<std::thread> threads;
        for (int t = 0; t < kThreads; ++t)
        {
            threads.emplace_back(
                [&go, &responder]
                {
                    while (!go.load())
                    {
                    }
                    responder->send(wazuh::uds_http::HttpResponse {200, "{}", {}});
                });
        }
        go = true;
        for (auto& thread : threads)
        {
            thread.join();
        }

        ASSERT_EQ(1U, limiter->pendingSessions("001")) << "round " << round;
        other->release();
        ASSERT_EQ(0U, limiter->trackedAgents()) << "round " << round;
    }
}
