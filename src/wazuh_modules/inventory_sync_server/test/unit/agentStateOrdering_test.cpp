/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// The `agent-state` bucket's ordering contract as the whole-agent deletion relies on it (I147, I147c, I147d,
// I149; CA-E7c-3, CA-E7c-4), on a REAL runtime and the module's own bucket spec (`ordered`, Reject, unlimited
// retry), served by the library's in-process fake indexer. The fake keeps no documents: every oracle is the order
// and the content of the `_bulk` requests it received, and the answers it was scripted to give.
#include "testRealIndexer.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using indexer_client::testing::BulkItem;
using indexer_client::testing::BulkOp;
using indexer_client::testing::BulkScript;
using invsync::test::RealIndexer;
using invsync::test::waitUntil;

namespace
{
    using namespace std::chrono_literals;

    constexpr auto CONFIG_INDEX {"wazuh-agent-config"};
    constexpr auto STATS_INDEX {"wazuh-agent-stats"};

    /// What POST /stats does: index the report under the agent's id, tagged with the agent.
    indexer_client::Op report(const std::string& agent, const std::string& body = R"({"modules":{"agent":{"n":1}}})")
    {
        indexer_client::Op op;
        op.kind = indexer_client::Op::Kind::Index;
        op.index = STATS_INDEX;
        op.id = agent;
        op.body = body;
        op.tag = agent;
        return op;
    }

    indexer_client::Op deletion(const char* index, const std::string& agent)
    {
        indexer_client::Op op;
        op.kind = indexer_client::Op::Kind::Delete;
        op.index = index;
        op.id = agent;
        op.tag = agent;
        return op;
    }

    /// The wire as text, for failure messages: one line per `_bulk`, `action:index/id` per op.
    std::string describe(const std::vector<std::vector<BulkOp>>& requests)
    {
        std::string text;
        for (std::size_t i = 0; i < requests.size(); ++i)
        {
            text += "\n  request " + std::to_string(i) + ":";
            for (const auto& op : requests[i])
            {
                text += " " + op.action + ":" + op.index + "/" + op.id.value_or("-");
            }
        }
        return text;
    }

    bool isDeleteOf(const BulkOp& op, const std::string& agent)
    {
        return op.action == "delete" && op.id && *op.id == agent;
    }

    bool isReportOf(const BulkOp& op, const std::string& agent)
    {
        return op.action == "index" && op.index == STATS_INDEX && op.id && *op.id == agent;
    }
} // namespace

class AgentStateOrdering : public ::testing::Test
{
protected:
    /// Runtime + Client with the module's two buckets; the agent-state bucket flushes after 20 ms instead of its
    /// production 5 s so that a lone post does not make the test wait, nothing else of its spec is touched.
    void start()
    {
        real.startRuntime();
        ASSERT_TRUE(real.runtimeStarted) << real.startError;
        auto specs = RealIndexer::specs();
        ASSERT_TRUE(specs.agentState.ordered) << "the production agent-state spec must be ordered";
        specs.agentState.bulk.maxAge = 20ms;
        ASSERT_TRUE(real.makeClient(specs)) << real.startError;
        writer = real.agentStateWriter();
        ASSERT_NE(nullptr, writer);
    }

    void TearDown() override
    {
        writer.reset();
        real.shutdown();
    }

    /// The two by-id deletes of a deletion, one Group committed at once, as the pipeline worker does it.
    indexer_client::GroupTicket commitDeletion(const std::string& agent)
    {
        auto group = writer->group();
        EXPECT_EQ(indexer_client::Cause::None, group.add(deletion(CONFIG_INDEX, agent))) << group.lastAddReason();
        EXPECT_EQ(indexer_client::Cause::None, group.add(deletion(STATS_INDEX, agent))) << group.lastAddReason();
        return group.commit();
    }

    /// The `_bulk` requests received, each as its ops.
    std::vector<std::vector<BulkOp>> requests() const
    {
        return real.bulk->received();
    }

    RealIndexer real;
    std::shared_ptr<indexer_client::IWriter> writer;
};

/// The ordering is per KEY: an op waits for the earlier ops of its own (index, _id), so the document the report
/// writes -- `wazuh-agent-stats/007` -- is the one whose delete is constrained; the delete of `wazuh-agent-config/007`
/// is another key and may go out beside, or ahead of, the report.
static bool isStatsDeleteOf(const BulkOp& op, const std::string& agent)
{
    return isDeleteOf(op, agent) && op.index == STATS_INDEX;
}

/**
 * A report whose `_bulk` was answered 503 is retained for retry; the delete of the same document committed behind
 * it must not be sent before that report has its final answer, and never in the same `_bulk` -- else the retry could
 * land after the delete and resurrect the document. The first answer is held and 503; the bucket keeps at most one
 * bulk in flight, so nothing at all is sent meanwhile; the stats delete goes out after the report's second attempt.
 */
TEST_F(AgentStateOrdering, DeleteAfterRetainedReport)
{
    real.bulk->push(BulkScript::serverError(503).held());
    start();

    ASSERT_TRUE(writer->post(report("007")).accepted);
    ASSERT_TRUE(waitUntil([&] { return real.bulk->answered() == 1; })) << "the report's first attempt never arrived";

    auto ticket = commitDeletion("007");
    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(1U, real.bulk->answered()) << "something was sent while the report's bulk was still unresolved";
    EXPECT_FALSE(ticket.ready());

    real.fake->releaseHeld(); // The 503 goes out; the report is retried (20 ms base) and answered 200.

    const auto results = ticket.wait(std::chrono::steady_clock::now() + 10s);
    ASSERT_TRUE(results.ok()) << indexer_client::toString(results.cause) << ": " << results.reason;
    ASSERT_EQ(2U, results.value.size());
    for (const auto& result : results.value)
    {
        EXPECT_EQ(indexer_client::Status::Ok, result.status);
    }

    const auto received = requests();
    std::vector<std::size_t> reportRequests;
    std::size_t statsDeleteRequest {received.size()};
    for (std::size_t i = 0; i < received.size(); ++i)
    {
        bool hasReport {false};
        bool hasStatsDelete {false};
        for (const auto& op : received[i])
        {
            hasReport = hasReport || isReportOf(op, "007");
            hasStatsDelete = hasStatsDelete || isStatsDeleteOf(op, "007");
        }
        EXPECT_FALSE(hasReport && hasStatsDelete) << "request " << i << " shares a key" << describe(received);
        if (hasReport)
        {
            reportRequests.push_back(i);
        }
        if (hasStatsDelete)
        {
            statsDeleteRequest = i;
        }
    }
    ASSERT_EQ(2U, reportRequests.size()) << "the report (503), then the report again (200)" << describe(received);
    EXPECT_LT(reportRequests.back(), statsDeleteRequest)
        << "the delete of the report's document was sent before the report's final response" << describe(received);
}

/**
 * A report refused per item with a 429 is retried item by item; the delete of its document never shares a `_bulk`
 * with the report's retry, whatever the timing, and comes after the last request that carried the report.
 */
TEST_F(AgentStateOrdering, ItemRetryNeverSharesBulk)
{
    real.bulk->push(BulkScript::items({{0, BulkItem::rejected()}}));
    real.bulk->push(BulkScript::items({{0, BulkItem::rejected()}}));
    start();

    ASSERT_TRUE(writer->post(report("007")).accepted);
    auto ticket = commitDeletion("007");

    const auto results = ticket.wait(std::chrono::steady_clock::now() + 10s);
    ASSERT_TRUE(results.ok()) << indexer_client::toString(results.cause) << ": " << results.reason;

    const auto received = requests();
    std::size_t lastReport {0};
    std::size_t statsDelete {received.size()};
    std::size_t reportAttempts {0};
    for (std::size_t i = 0; i < received.size(); ++i)
    {
        bool hasReport {false};
        bool hasStatsDelete {false};
        for (const auto& op : received[i])
        {
            hasReport = hasReport || isReportOf(op, "007");
            hasStatsDelete = hasStatsDelete || isStatsDeleteOf(op, "007");
        }
        EXPECT_FALSE(hasReport && hasStatsDelete)
            << "request " << i << " carries the report and its delete together" << describe(received);
        if (hasReport)
        {
            lastReport = i;
            ++reportAttempts;
        }
        if (hasStatsDelete)
        {
            statsDelete = std::min(statsDelete, i);
        }
    }
    EXPECT_EQ(3U, reportAttempts) << "two 429s, then the report was applied" << describe(received);
    EXPECT_LT(lastReport, statsDelete) << "the delete must follow the report's last attempt" << describe(received);
}

/**
 * cancel(agent) drops what the agent still has pending in the bucket: of 1 000 reports posted for one agent, the one
 * already in flight (a held 503) is the only one that ever reaches the wire, nothing of the agent is sent after the
 * cancel, the deletes go through, and the CancelTicket completes. Another agent's pending report is untouched.
 */
TEST_F(AgentStateOrdering, CancelDropsPending)
{
    real.bulk->push(BulkScript::serverError(503).held());
    start();

    // One in flight (the first of its key goes alone: the key is ordered), 999 pending behind it.
    for (int i = 0; i < 1000; ++i)
    {
        ASSERT_TRUE(writer->post(report("007", R"({"modules":{"agent":{"n":)" + std::to_string(i) + "}}}")).accepted);
    }
    ASSERT_TRUE(writer->post(report("008")).accepted);
    ASSERT_TRUE(waitUntil([&] { return real.bulk->answered() == 1; })) << "the first report never went out";

    auto cancelled = writer->cancel("007");
    auto ticket = commitDeletion("007");

    real.fake->releaseHeld(); // The in-flight report's 503: marked by the cancel, it is never requeued.

    const auto cancelResult = cancelled.wait(std::chrono::steady_clock::now() + 10s);
    EXPECT_TRUE(cancelResult.ok()) << indexer_client::toString(cancelResult.cause) << ": " << cancelResult.reason;
    const auto results = ticket.wait(std::chrono::steady_clock::now() + 10s);
    ASSERT_TRUE(results.ok()) << indexer_client::toString(results.cause) << ": " << results.reason;
    for (const auto& result : results.value)
    {
        EXPECT_EQ(indexer_client::Status::Ok, result.status) << indexer_client::toString(result.cause);
    }

    // Agent 008's report was not tagged for the cancel: it is sent (before or after the deletes, either is fine).
    ASSERT_TRUE(waitUntil(
        [&]
        {
            for (const auto& op : real.bulkOps())
            {
                if (isReportOf(op, "008"))
                {
                    return true;
                }
            }
            return false;
        }));

    std::size_t reportsOf007 {0};
    std::size_t deletesOf007 {0};
    std::size_t reportsOf008 {0};
    for (const auto& op : real.bulkOps())
    {
        reportsOf007 += isReportOf(op, "007") ? 1 : 0;
        deletesOf007 += isDeleteOf(op, "007") ? 1 : 0;
        reportsOf008 += isReportOf(op, "008") ? 1 : 0;
    }
    EXPECT_EQ(1U, reportsOf007) << "only the report already in flight reached the indexer; the other 999 were dropped";
    EXPECT_EQ(2U, deletesOf007) << "the deletes of the agent's two documents";
    EXPECT_EQ(1U, reportsOf008);

    // Nothing of the cancelled agent, but its delete, went out after the cancel: the first delete is the last op
    // that names agent 007 in any way other than a delete.
    bool deleteSeen {false};
    for (const auto& op : real.bulkOps())
    {
        if (isDeleteOf(op, "007"))
        {
            deleteSeen = true;
        }
        else if (deleteSeen && isReportOf(op, "007"))
        {
            ADD_FAILURE() << "a report of the cancelled agent was sent after its delete";
        }
    }
}
