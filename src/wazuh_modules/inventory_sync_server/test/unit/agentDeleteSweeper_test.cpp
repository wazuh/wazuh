/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// The post-deletion sweeper (I146, I146b, I146c; CA-E7c-5) on a REAL runtime of the client library served by the
// library's in-process fake indexer (IC/tests/fake). The fake keeps no documents, so the oracles are the wire --
// one `_delete_by_query` per index, its `terms._id` ids, the spacing of the passes, the chunking -- and the
// `deleted` count the fake is scripted to answer, which is what the sweeper reports as `residual`.
#include "indexer/agentDeleteSweeper.hpp"

#include "testLogRecorder.hpp"
#include "testRealIndexer.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <vector>

using invsync::indexer::AgentDeleteSweeper;
using invsync::test::dbqBody;
using invsync::test::dbqRuleFor;
using invsync::test::RealIndexer;
using invsync::test::waitUntil;

namespace
{
    using namespace std::chrono_literals;

    constexpr auto CONFIG_INDEX {"wazuh-agent-config"};
    constexpr auto STATS_INDEX {"wazuh-agent-stats"};

    /// The sweep window every test uses: short, so a test is a few windows long; the tick is the window.
    constexpr auto WINDOW {400ms};

    /// "001".."0nn": canonical agent ids.
    std::vector<std::string> agentIds(std::size_t count, std::size_t first = 1)
    {
        std::vector<std::string> ids;
        ids.reserve(count);
        for (std::size_t i = first; i < first + count; ++i)
        {
            auto text = std::to_string(i);
            ids.emplace_back(std::string(text.size() < 6 ? 6 - text.size() : 0, '0') + text);
        }
        return ids;
    }

    std::set<std::string> asSet(const std::vector<std::string>& ids)
    {
        return {ids.begin(), ids.end()};
    }
} // namespace

class AgentDeleteSweeperTest : public ::testing::Test
{
protected:
    /// Runtime + Client + sweeper on the fake. Rules a test wants for the by-query routes go in BEFORE this call.
    void start(std::chrono::milliseconds window = WINDOW, std::chrono::milliseconds deadline = 3000ms)
    {
        real.startRuntime();
        ASSERT_TRUE(real.runtimeStarted) << real.startError;
        ASSERT_TRUE(real.makeClient(RealIndexer::specs())) << real.startError;
        sweeper = std::make_unique<AgentDeleteSweeper>(real.client->query(), window, deadline, real.closing);
    }

    /// Lets half a window pass after start(): the sweeper's first tick is one window after its thread started, and an
    /// id noted in the very first microseconds would be exactly a window old at it. Noting after this, every id of a
    /// test is half a window old at the first tick (not due) and older than a window at the second (due) -- never split
    /// between two passes by scheduling.
    void settle() const
    {
        std::this_thread::sleep_for(WINDOW / 2);
    }

    void TearDown() override
    {
        if (sweeper)
        {
            sweeper->stop();
        }
        sweeper.reset();
        real.shutdown();
    }

    /// The `terms._id` ids of every delete-by-query received on @p index, one set per request, in arrival order.
    std::vector<std::vector<std::string>> idsPerRequest(const char* index) const
    {
        std::vector<std::vector<std::string>> result;
        for (const auto& request : real.dbqRequests(index))
        {
            result.push_back(RealIndexer::termsIds(request));
        }
        return result;
    }

    RealIndexer real;
    std::unique_ptr<AgentDeleteSweeper> sweeper;
};

/// 50 ids noted inside one window are swept by ONE delete-by-query per index -- the two `wazuh-agent-*` indices,
/// each its own request so a missing one cannot void the other -- carrying all 50 in `terms._id`.
TEST_F(AgentDeleteSweeperTest, OneDbqPerIndex)
{
    start();
    settle();
    const auto ids = agentIds(50);
    for (const auto& id : ids)
    {
        sweeper->note(id);
    }

    ASSERT_TRUE(waitUntil([&] { return sweeper->stats().runs == 1; }, 4000ms));
    ASSERT_TRUE(waitUntil([&] { return real.dbqRequests(STATS_INDEX).size() == 1; }));

    for (const auto* index : {CONFIG_INDEX, STATS_INDEX})
    {
        const auto requests = idsPerRequest(index);
        ASSERT_EQ(1U, requests.size()) << index;
        EXPECT_EQ(ids, requests.front()) << index << ": the ids, in note order";
    }
    EXPECT_EQ(0U, real.dbqRequests("wazuh-states-*").size()) << "the sweeper never touches the states indices";
    EXPECT_EQ(0U, sweeper->stats().failures);
}

/// A note every W/4 for four windows: however many ids arrive, a pass runs at most once per window, and the passes
/// are at least a window apart on the wire. A pass per note (the mutation) would be sixteen.
TEST_F(AgentDeleteSweeperTest, TrickleIsOnePassPerWindow)
{
    start();
    const auto begin = std::chrono::steady_clock::now();
    const auto ids = agentIds(16);
    for (const auto& id : ids)
    {
        sweeper->note(id);
        std::this_thread::sleep_for(WINDOW / 4);
    }
    // Let the last due ids be swept: they are due one to two windows after their note.
    ASSERT_TRUE(waitUntil([&] { return sweeper->stats().runs >= 3; }, 4000ms));
    std::this_thread::sleep_for(WINDOW / 2);

    // `runs` counts a pass when it starts: let an in-flight one finish its two requests before reading the wire.
    ASSERT_TRUE(waitUntil(
        [&]
        {
            return real.dbqRequests(STATS_INDEX).size() == sweeper->stats().runs &&
                   real.dbqRequests(CONFIG_INDEX).size() == sweeper->stats().runs;
        }));
    const auto total = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin);
    const auto runs = sweeper->stats().runs;
    // The sweeper was built shortly before `begin`: at most one tick per window since, plus the one in progress.
    const auto maxRuns = static_cast<std::uint64_t>(total.count() / WINDOW.count()) + 2;
    EXPECT_GE(runs, 2U);
    EXPECT_LE(runs, maxRuns) << "at most one pass per window, whatever the trickle";
    EXPECT_LT(runs, ids.size()) << "never one pass per note";

    for (const auto* index : {CONFIG_INDEX, STATS_INDEX})
    {
        const auto requests = real.dbqRequests(index);
        EXPECT_EQ(runs, requests.size()) << index << ": exactly one delete-by-query per pass";
        for (std::size_t i = 1; i < requests.size(); ++i)
        {
            const auto gap = std::chrono::duration_cast<std::chrono::milliseconds>(requests[i].receivedAt -
                                                                                   requests[i - 1].receivedAt);
            EXPECT_GE(gap.count(), WINDOW.count() * 6 / 10) << index << ": passes " << i - 1 << " and " << i;
        }
    }
}

/// An id noted right after a pass waits its own window: the next tick, one window later, finds it younger than a
/// window and leaves it; the tick after that sweeps it. A sweep of young ids (the mutation) would show at the tick.
TEST_F(AgentDeleteSweeperTest, YoungIdsWaitTheirWindow)
{
    start();
    const auto old = agentIds(1, 1);
    sweeper->note(old.front());
    ASSERT_TRUE(waitUntil([&] { return sweeper->stats().runs == 1; }, 4000ms));

    // Right after the pass: the next tick is about one window away and this id is no older than that.
    const auto young = agentIds(1, 2);
    sweeper->note(young.front());

    std::this_thread::sleep_for(WINDOW * 3 / 2); // Past the next tick, short of the one after it.
    EXPECT_EQ(1U, sweeper->stats().runs) << "the tick found nothing due: no pass, no delete-by-query";
    EXPECT_EQ(1U, real.dbqRequests(STATS_INDEX).size());

    ASSERT_TRUE(waitUntil([&] { return sweeper->stats().runs == 2; }, 4000ms));
    ASSERT_TRUE(waitUntil([&] { return real.dbqRequests(STATS_INDEX).size() == 2; }));
    const auto requests = idsPerRequest(STATS_INDEX);
    ASSERT_EQ(2U, requests.size());
    EXPECT_EQ(old, requests[0]);
    EXPECT_EQ(young, requests[1]) << "the young id rides the pass after its own window, alone";
}

/// One index missing (the indexer answers 404 to its delete-by-query: the library gives an empty success) does not
/// stop the sweep of the other: both are asked, and the other's deleted documents are the residual.
TEST_F(AgentDeleteSweeperTest, OneIndexMissingStillSweepsOther)
{
    real.fake->addRule(
        dbqRuleFor(CONFIG_INDEX,
                   404,
                   R"({"error":{"root_cause":[{"type":"index_not_found_exception","reason":"no such index"}],)"
                   R"("type":"index_not_found_exception","reason":"no such index"},"status":404})"));
    real.fake->addRule(dbqRuleFor(STATS_INDEX, 200, dbqBody(2)));
    start();
    settle();
    sweeper->note("000007");

    ASSERT_TRUE(
        waitUntil([&] { return sweeper->stats().runs == 1 && real.dbqRequests(STATS_INDEX).size() == 1; }, 4000ms));
    ASSERT_TRUE(waitUntil([&] { return sweeper->stats().residual == 2; }));

    EXPECT_EQ(1U, real.dbqRequests(CONFIG_INDEX).size()) << "the missing index was asked";
    EXPECT_EQ(1U, real.dbqRequests(STATS_INDEX).size()) << "and the other was swept regardless";
    EXPECT_EQ(2U, sweeper->stats().residual);
    EXPECT_EQ(0U, sweeper->stats().failures) << "a missing index is nothing to sweep, not a failure";
}

/// 25 000 ids are swept in chunks of at most 10 000 -- three requests per index -- and the ids of all the chunks
/// are exactly the ids noted.
TEST_F(AgentDeleteSweeperTest, ChunksOf10000)
{
    start(WINDOW, 10000ms);
    settle();
    const auto ids = agentIds(25000);
    for (const auto& id : ids)
    {
        sweeper->note(id);
    }

    ASSERT_TRUE(waitUntil([&] { return real.dbqRequests(STATS_INDEX).size() == 3; }, 8000ms));
    ASSERT_TRUE(waitUntil([&] { return sweeper->stats().runs == 1; }));

    for (const auto* index : {CONFIG_INDEX, STATS_INDEX})
    {
        const auto requests = idsPerRequest(index);
        ASSERT_EQ(3U, requests.size()) << index;
        EXPECT_EQ(10000U, requests[0].size());
        EXPECT_EQ(10000U, requests[1].size());
        EXPECT_EQ(5000U, requests[2].size());
        std::vector<std::string> all;
        for (const auto& chunk : requests)
        {
            all.insert(all.end(), chunk.begin(), chunk.end());
        }
        EXPECT_EQ(ids, all) << index << ": every id once, in note order";
    }
    EXPECT_EQ(AgentDeleteSweeper::MAX_IDS_PER_QUERY, 10000U);
}

/// What the passes deleted is the residual: the `deleted` of every answer, summed.
TEST_F(AgentDeleteSweeperTest, ResidualIsDeleted)
{
    real.fake->addRule(dbqRuleFor(CONFIG_INDEX, 200, dbqBody(3)));
    real.fake->addRule(dbqRuleFor(STATS_INDEX, 200, dbqBody(0)));
    start();
    settle();
    sweeper->note("000007");

    ASSERT_TRUE(waitUntil([&] { return sweeper->stats().runs == 1 && sweeper->stats().residual > 0; }, 4000ms));

    const auto stats = sweeper->stats();
    EXPECT_EQ(3U, stats.residual);
    EXPECT_EQ(1U, stats.runs);
    EXPECT_EQ(0U, stats.failures);
    EXPECT_EQ(0U, stats.dropped);
}

/// stop() with ids still pending wakes the thread, joins it, drops what it holds and counts it; nothing is sent, and a
/// note() after stop() is dropped too.
TEST_F(AgentDeleteSweeperTest, StopDropsCounted)
{
    start(std::chrono::hours {1}); // Nothing is ever due.
    const auto ids = agentIds(7);
    for (const auto& id : ids)
    {
        sweeper->note(id);
    }
    EXPECT_EQ(0U, sweeper->stats().dropped);

    const auto begin = std::chrono::steady_clock::now();
    sweeper->stop();
    EXPECT_LT(std::chrono::steady_clock::now() - begin, 1s)
        << "stop() wakes the thread: it does not sleep out its tick";

    EXPECT_EQ(7U, sweeper->stats().dropped);
    EXPECT_EQ(0U, sweeper->stats().runs);
    EXPECT_EQ(0U, real.dbqRequests(CONFIG_INDEX).size() + real.dbqRequests(STATS_INDEX).size());

    sweeper->note("000099");
    EXPECT_EQ(8U, sweeper->stats().dropped) << "a late note is abandoned and counted";
    sweeper->stop(); // Idempotent.
    EXPECT_EQ(8U, sweeper->stats().dropped);
}

/// A delete-by-query that fails (a non-retryable 400 here) is counted once per chunk; its ids are retried on the next
/// pass and, failing again, dropped -- never swept forever.
TEST_F(AgentDeleteSweeperTest, FailureCounted)
{
    real.fake->addRule(dbqRuleFor(
        STATS_INDEX,
        400,
        R"({"error":{"root_cause":[{"type":"parse_exception","reason":"boom"}],"type":"parse_exception","reason":"boom"},"status":400})"));
    start();
    settle();
    const auto ids = agentIds(3);
    for (const auto& id : ids)
    {
        sweeper->note(id);
    }

    ASSERT_TRUE(waitUntil([&] { return sweeper->stats().runs == 1 && sweeper->stats().failures >= 1; }, 4000ms));
    EXPECT_EQ(1U, sweeper->stats().failures) << "one chunk failed in the pass";
    EXPECT_EQ(0U, sweeper->stats().dropped) << "its ids are retried once";

    // The retry is one window later (its note is older than a window: due at the next tick) and fails again.
    ASSERT_TRUE(waitUntil([&] { return sweeper->stats().runs == 2 && sweeper->stats().dropped == 3; }, 4000ms));
    EXPECT_EQ(2U, sweeper->stats().failures);
    EXPECT_EQ(3U, sweeper->stats().dropped) << "dropped after the second failure";
    EXPECT_EQ(2U, real.dbqRequests(STATS_INDEX).size());
}

/// A pass that outlasts the window (its first delete-by-query answers after 1.75 windows) must not make the next ones
/// chain: the pass that starts late, right after it, is followed by one no sooner than a window after ITS start. A
/// feeder notes an id every 40 ms so something is due at every tick; the first delete-by-query of each pass is on the
/// config index, so its arrival is the pass's start on the wire.
TEST_F(AgentDeleteSweeperTest, SlowPassDoesNotChainPasses)
{
    auto slow = dbqRuleFor(CONFIG_INDEX, 200, dbqBody(0), WINDOW * 7 / 4);
    slow.times = 1; // Only the first pass is slow.
    real.fake->addRule(std::move(slow));
    start();

    std::atomic<bool> feeding {true};
    std::thread feeder {[&]
                        {
                            std::size_t next {1};
                            while (feeding.load())
                            {
                                sweeper->note(agentIds(1, next++).front());
                                std::this_thread::sleep_for(40ms);
                            }
                        }};
    const auto enough = waitUntil([&] { return real.dbqRequests(CONFIG_INDEX).size() >= 4; }, 8000ms);
    feeding.store(false);
    feeder.join();
    ASSERT_TRUE(enough);

    const auto requests = real.dbqRequests(CONFIG_INDEX);
    for (std::size_t i = 1; i < requests.size(); ++i)
    {
        const auto gap =
            std::chrono::duration_cast<std::chrono::milliseconds>(requests[i].receivedAt - requests[i - 1].receivedAt);
        EXPECT_GE(gap.count(), WINDOW.count() * 8 / 10) << "passes " << i - 1 << " and " << i << " started too close";
    }
}

/// The sweep's delete-by-query proceeds on version conflicts: a document deleted meanwhile is not a failure.
TEST_F(AgentDeleteSweeperTest, DbqProceedsOnConflicts)
{
    start();
    settle();
    sweeper->note("000007");

    ASSERT_TRUE(waitUntil([&] { return real.dbqRequests(STATS_INDEX).size() == 1; }, 4000ms));
    for (const auto* index : {CONFIG_INDEX, STATS_INDEX})
    {
        const auto requests = real.dbqRequests(index);
        ASSERT_EQ(1U, requests.size()) << index;
        EXPECT_NE(std::string::npos, requests.front().target.find("conflicts=proceed"))
            << index << ": " << requests.front().target;
    }
}

/// The module stops while a delete-by-query is in flight and it answers a failure (the library answers ClientClosed to
/// an in-flight query on close): not a failure of the sweep -- no `failures`, no WARN -- and the ids are dropped, not
/// retried.
TEST_F(AgentDeleteSweeperTest, ClosingCutsPass)
{
    auto held = dbqRuleFor(
        CONFIG_INDEX,
        400,
        R"({"error":{"root_cause":[{"type":"parse_exception","reason":"boom"}],"type":"parse_exception","reason":"boom"},"status":400})");
    held.hold = true;
    real.fake->addRule(std::move(held));
    start();
    settle();
    invsync::test::LogRecorder::clear();
    const auto ids = agentIds(3);
    for (const auto& id : ids)
    {
        sweeper->note(id);
    }

    ASSERT_TRUE(waitUntil([&] { return real.dbqRequests(CONFIG_INDEX).size() == 1; }, 4000ms));
    real.closing->store(true);
    real.fake->releaseHeld(); // The held delete-by-query now answers its failure.

    ASSERT_TRUE(waitUntil([&] { return sweeper->stats().runs == 1; }));
    std::this_thread::sleep_for(100ms); // Let the pass finish its bookkeeping.
    EXPECT_EQ(0U, sweeper->stats().failures) << "a failure caused by the stop is not counted";
    EXPECT_EQ(0U, real.dbqRequests(STATS_INDEX).size()) << "the pass was cut: the other index is not swept";
    EXPECT_FALSE(invsync::test::LogRecorder::sawMessageContaining("retried once"));

    sweeper->stop();
    EXPECT_EQ(3U, sweeper->stats().dropped) << "the cut pass's ids are dropped at stop()";
    EXPECT_EQ(0U, sweeper->stats().failures);
    EXPECT_FALSE(invsync::test::LogRecorder::sawMessageContaining("retried once"));
}

/// An agent enrolled again with a deleted id reports within the window: forget() withdraws that id before its pass,
/// so neither index is swept for it, while the other ids of the pass still are. Without forget() the pass would carry
/// it and delete the new agent's documents.
TEST_F(AgentDeleteSweeperTest, ForgetWithdrawsPendingId)
{
    start();
    settle();
    sweeper->note("000007");
    sweeper->note("000008");
    sweeper->note("000007"); // A second deletion of the same id: both notes go.
    sweeper->forget("000007");

    ASSERT_TRUE(
        waitUntil([&] { return sweeper->stats().runs == 1 && real.dbqRequests(STATS_INDEX).size() == 1; }, 4000ms));
    for (const auto* index : {CONFIG_INDEX, STATS_INDEX})
    {
        const auto requests = idsPerRequest(index);
        ASSERT_EQ(1U, requests.size()) << index;
        EXPECT_EQ(std::vector<std::string> {"000008"}, requests.front()) << index;
    }
    EXPECT_EQ(1U, sweeper->stats().forgotten);

    // Nothing left for a later pass, and nothing to drop at stop().
    std::this_thread::sleep_for(WINDOW * 5 / 2);
    EXPECT_EQ(1U, real.dbqRequests(STATS_INDEX).size());
    sweeper->stop();
    EXPECT_EQ(0U, sweeper->stats().dropped);
}

/// forget() of an id that is not pending changes nothing: no count, and the pass carries every noted id.
TEST_F(AgentDeleteSweeperTest, ForgetOfUnknownIdIsNoop)
{
    start();
    sweeper->forget("000001"); // Nothing pending at all: the lock-free path.
    settle();
    sweeper->note("000007");
    sweeper->forget("000099");

    ASSERT_TRUE(
        waitUntil([&] { return sweeper->stats().runs == 1 && real.dbqRequests(STATS_INDEX).size() == 1; }, 4000ms));
    EXPECT_EQ(std::vector<std::string> {"000007"}, idsPerRequest(STATS_INDEX).front());
    EXPECT_EQ(0U, sweeper->stats().forgotten);
}

/// forget() while the pass holding the id is in flight: the delete-by-query already sent cannot be recalled, but the
/// chunk not sent yet (the second index) leaves the id out -- here it was alone, so that request is not sent at all --
/// and a failure of the first chunk does not bring the id back on the next pass.
TEST_F(AgentDeleteSweeperTest, ForgetDuringPassSparesUnsentChunksAndRetry)
{
    auto held = dbqRuleFor(
        CONFIG_INDEX,
        400,
        R"({"error":{"root_cause":[{"type":"parse_exception","reason":"boom"}],"type":"parse_exception","reason":"boom"},"status":400})");
    held.hold = true;
    real.fake->addRule(std::move(held));
    start();
    settle();
    sweeper->note("000007");

    ASSERT_TRUE(waitUntil([&] { return real.dbqRequests(CONFIG_INDEX).size() == 1; }, 4000ms));
    sweeper->forget("000007");
    real.fake->releaseHeld(); // The in-flight request answers its failure; the pass goes on to the other index.

    ASSERT_TRUE(waitUntil([&] { return sweeper->stats().failures == 1; }));
    EXPECT_EQ(1U, sweeper->stats().forgotten);

    std::this_thread::sleep_for(WINDOW * 5 / 2); // Past the pass a retry would have run in.
    EXPECT_EQ(0U, real.dbqRequests(STATS_INDEX).size()) << "the withdrawn id is not sent to the second index";
    EXPECT_EQ(1U, real.dbqRequests(CONFIG_INDEX).size()) << "nor retried after the first index failed";
    EXPECT_EQ(1U, sweeper->stats().runs);
    sweeper->stop();
    EXPECT_EQ(0U, sweeper->stats().dropped) << "a withdrawn id is not pending, so stop() has nothing to drop";
}
