/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

// Edge-triggered and summarized logging (plan-E5c §Tests, CA-16, RF-16, I102, I104; contract runtime/logSummary.hpp):
// a bounded summary of 10 000 failures, the quota edges with their hysteresis (per bucket and for the global cap), the
// callback overruns, the timer and the final summary at shutdown, and the WARN of an abandoned PIT delete. Every
// summary is forced with detail::testing::flushLogSummary() except where the timer itself is under test.

#include <cstdarg>
#include <cstdio>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

#include "queryFixture.hpp"
#include "runtime/logSummary.hpp"
#include "writeFixture.hpp"

using namespace write_component;

namespace
{
    struct Line final
    {
        int level {0};
        std::string text;
    };

    /// The process log function of the case: every line, formatted, with its level.
    class Sink final
    {
    public:
        indexer_client::LogFunction function()
        {
            return
                [this](
                    const int level, const char*, const char*, const int, const char*, const char* format, va_list args)
            {
                va_list copy;
                va_copy(copy, args);
                char buffer[16384];
                std::vsnprintf(buffer, sizeof(buffer), format, copy);
                va_end(copy);
                std::lock_guard<std::mutex> lock(m_mutex);
                m_lines.push_back({level, buffer});
            };
        }

        std::size_t count(int level, const std::string& part) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::size_t n = 0;
            for (const auto& line : m_lines)
            {
                n += (line.level == level && line.text.find(part) != std::string::npos) ? 1 : 0;
            }
            return n;
        }

        /// Lines at `level` or above containing `part`.
        std::vector<Line> atLeast(int level, const std::string& part) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::vector<Line> out;
            for (const auto& line : m_lines)
            {
                if (line.level >= level && line.text.find(part) != std::string::npos)
                {
                    out.push_back(line);
                }
            }
            return out;
        }

        std::vector<Line> lines() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_lines;
        }

        std::string dump() const
        {
            std::string out;
            for (const auto& line : lines())
            {
                out += "\n[" + std::to_string(line.level) + "] " + line.text;
            }
            return out;
        }

    private:
        mutable std::mutex m_mutex;
        std::vector<Line> m_lines;
    };

    // loggerHelper.h levels as the library passes them to the log function.
    constexpr int DEBUG = 0;
    constexpr int INFO = 1;
    constexpr int WARN = 2;

    ic::OpResult failed(ic::Cause cause, std::string type, std::string reason)
    {
        ic::OpResult r;
        r.status = ic::Status::Failed;
        r.cause = cause;
        r.itemErrorType = std::move(type);
        r.reason = std::move(reason);
        return r;
    }
} // namespace

class LogSummaryTest : public WriteTest
{
protected:
    Sink m_logs;

    void SetUp() override
    {
        WriteTest::SetUp();
        indexer_client::setLogFunction(m_logs.function()); // Valid only while no runtime runs (I56).
    }

    void TearDown() override
    {
        WriteTest::TearDown();
        indexer_client::setLogFunction({});
    }

    /// The batches the sink holds, in dispatch order, for a case that resolves a chosen number of ops.
    std::deque<std::shared_ptr<wr::OpState>> m_held;

    void collectHeld(std::size_t total)
    {
        ASSERT_TRUE(m_sink->waitDispatched(total));
        for (auto& batch : m_sink->take())
        {
            for (auto& op : batch.ops)
            {
                m_held.push_back(std::move(op));
            }
        }
    }

    /// Resolves the `n` oldest held ops Ok.
    void resolveOldest(std::size_t n)
    {
        ASSERT_LE(n, m_held.size());
        for (std::size_t i = 0; i < n; ++i)
        {
            ASSERT_TRUE(m_path->resolve(bucketOf(*m_held.front()), m_held.front(), TestSink::ok()));
            m_held.pop_front();
        }
    }
};

// CA-16 (TenThousandFailedItemsBoundedLog †): 10 000 ops failed over 12 itemErrorTypes, each reason carrying a
// document, between two flushLogSummary(): per bucket at most 2 lines at INFO or above (one WARN with 8 keys plus
// `other`, one INFO with the totals), none with a document or a reason; one sample at DEBUG, truncated to 256 bytes.
// Mutant: one line per key.
TEST_F(LogSummaryTest, TenThousandFailedItemsBoundedLog)
{
    constexpr std::size_t OPS = 10000;
    constexpr std::size_t TYPES = 12;
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::Hold);
    auto c = client("c", {bucketSpec("b", 64u << 20, ic::Overflow::Kind::Reject, 0, 500)});
    auto writer = c->writer("b");
    ASSERT_TRUE(ic::detail::testing::flushLogSummary());
    const auto before = m_logs.lines().size();

    for (std::size_t i = 0; i < OPS; ++i)
    {
        ASSERT_TRUE(writer->submit(indexOp("d" + std::to_string(i))).accepted) << i;
    }
    ASSERT_NO_FATAL_FAILURE(collectHeld(OPS / 500));
    ASSERT_EQ(m_held.size(), OPS);
    std::size_t i = 0;
    for (const auto& op : m_held)
    {
        const auto type = "type_" + std::to_string(i % TYPES);
        const auto reason = "failed to parse field [doc] of document {\"secret\":\"SECRETDOC-" + std::to_string(i) +
                            "\",\"pad\":\"" + std::string(400, 'z') + "\"}";
        ASSERT_TRUE(m_path->resolve(bucketOf(*op), op, failed(ic::Cause::ItemPermanent, type, reason)));
        ++i;
    }
    m_held.clear();
    ASSERT_TRUE(ic::detail::testing::flushLogSummary());

    const auto all = m_logs.lines();
    std::vector<Line> lines(all.begin() + static_cast<std::ptrdiff_t>(before), all.end());
    std::vector<Line> loud;
    std::vector<Line> debug;
    for (const auto& line : lines)
    {
        if (line.text.find("'c/b'") == std::string::npos)
        {
            continue;
        }
        (line.level >= INFO ? loud : debug).push_back(line);
    }
    ASSERT_LE(loud.size(), 2u) << m_logs.dump();
    ASSERT_EQ(loud.size(), 2u) << m_logs.dump();
    std::size_t warns = 0;
    for (const auto& line : loud)
    {
        EXPECT_EQ(line.text.find("SECRETDOC"), std::string::npos) << line.text;
        EXPECT_EQ(line.text.find("failed to parse"), std::string::npos) << line.text;
        if (line.level == WARN)
        {
            ++warns;
            // First come: type_0 … type_7 (834 or 833 each); the other four types (4 × 833) are `other`.
            for (std::size_t t = 0; t < 8; ++t)
            {
                const auto count = OPS / TYPES + (t < OPS % TYPES ? 1 : 0);
                EXPECT_NE(line.text.find("item_permanent/type_" + std::to_string(t) + "=" + std::to_string(count)),
                          std::string::npos)
                    << t << ": " << line.text;
            }
            EXPECT_EQ(line.text.find("type_8"), std::string::npos) << line.text;
            EXPECT_NE(line.text.find("other=3332."), std::string::npos) << line.text;
        }
        else
        {
            EXPECT_NE(line.text.find(": 10000 accepted, 0 ok, 10000 failed, 0 dropped."), std::string::npos)
                << line.text;
        }
    }
    EXPECT_EQ(warns, 1u);
    ASSERT_EQ(debug.size(), 1u) << m_logs.dump();
    const auto& sample = debug.front().text;
    EXPECT_EQ(sample.find("sample reason (item_permanent/type_0): failed to parse"), sample.find("sample reason"));
    const auto reasonAt = sample.find("): ") + 3;
    EXPECT_LE(sample.size() - reasonAt, ic::detail::logging::SAMPLE_REASON_MAX) << sample;
    EXPECT_EQ(debug.front().level, DEBUG);

    // The next interval is empty: nothing at all.
    const auto quiet = m_logs.lines().size();
    ASSERT_TRUE(ic::detail::testing::flushLogSummary());
    EXPECT_EQ(m_logs.lines().size(), quiet) << m_logs.dump();
}

// CA-16, obj. 1, N22 (QuotaEdgesWithHysteresis †): 85 % (WARN 80), 82 % (nothing), a submit refused QueueFull (WARN
// full), 95 % (nothing), a second refusal (nothing), 65 % (re-arm, nothing), 85 % (WARN 80 again), a refusal (WARN full
// again: the full edge re-armed too); a QueueFull storm at a low charge logs a single full WARN. The same sequence for
// the global cap with two buckets whose quotas each cover the cap: a refusal of the cap never fires a bucket's «no
// room» line. Mutants: the 80 % line by level (no arming); the full edge never re-armed (bucket and global).
TEST_F(LogSummaryTest, QuotaEdgesWithHysteresis)
{
    const auto unit = indexOp("q0000");
    const std::uint64_t charge = wireSize(unit) + wr::RESULT_RESERVE;
    const auto op = [](std::size_t i)
    {
        return indexOp("q" + std::to_string(1000 + i));
    };
    // An op of about 20 charges: over the room left at 82 % and at 95 %, under the quota and the bulk cap.
    const auto big = [charge]
    {
        return indexOp("big", 20 * charge);
    };
    std::size_t next = 0;
    std::size_t dispatched = 0;
    const auto submitN = [&](ic::IWriter& writer, std::size_t n)
    {
        for (std::size_t i = 0; i < n; ++i)
        {
            ASSERT_TRUE(writer.submit(op(next++)).accepted) << next;
        }
        dispatched += n;
        ASSERT_NO_FATAL_FAILURE(collectHeld(dispatched));
    };

    // Per bucket.
    {
        SCOPED_TRACE("bucket");
        ASSERT_NO_FATAL_FAILURE(start());
        installSink(TestSink::Mode::Hold);
        auto c = client("c",
                        {bucketSpec("b", 100 * charge, ic::Overflow::Kind::Reject, 0, 1),
                         bucketSpec("s", 100 * charge, ic::Overflow::Kind::Reject, 0, 1)});
        auto writer = c->writer("b");
        const std::string at80 = "Indexer client bucket 'c/b' reached 80% of its quota";
        const std::string full = "Indexer client bucket 'c/b' has no room for new operations";

        ASSERT_NO_FATAL_FAILURE(submitN(*writer, 79));
        EXPECT_EQ(m_logs.count(WARN, at80), 0u) << "79 %";
        ASSERT_NO_FATAL_FAILURE(submitN(*writer, 6));
        EXPECT_EQ(m_logs.count(WARN, at80), 1u) << "85 %";
        ASSERT_NO_FATAL_FAILURE(resolveOldest(3));
        EXPECT_EQ(m_logs.count(WARN, at80), 1u) << "82 %";
        EXPECT_EQ(m_logs.count(WARN, full), 0u) << "82 %";
        EXPECT_EQ(writer->submit(big()).cause, ic::Cause::QueueFull);
        EXPECT_EQ(m_logs.count(WARN, full), 1u) << "refused at 82 %";
        ASSERT_NO_FATAL_FAILURE(submitN(*writer, 13));
        EXPECT_EQ(m_logs.count(WARN, at80), 1u) << "95 %";
        EXPECT_EQ(writer->submit(big()).cause, ic::Cause::QueueFull);
        EXPECT_EQ(m_logs.count(WARN, full), 1u) << "refused again at 95 %";
        ASSERT_NO_FATAL_FAILURE(resolveOldest(30));
        EXPECT_EQ(m_logs.count(WARN, at80), 1u) << "65 %: re-armed, nothing logged";
        ASSERT_NO_FATAL_FAILURE(submitN(*writer, 20));
        EXPECT_EQ(m_logs.count(WARN, at80), 2u) << "85 % after the re-arm";
        EXPECT_EQ(m_logs.count(WARN, full), 1u);
        EXPECT_EQ(writer->submit(big()).cause, ic::Cause::QueueFull);
        EXPECT_EQ(m_logs.count(WARN, full), 2u) << "refused at 85 % after the re-arm";

        // N22: a storm of refusals at 10 % never re-arms: one full WARN.
        auto storm = c->writer("s");
        ASSERT_NO_FATAL_FAILURE(submitN(*storm, 10));
        for (int i = 0; i < 5; ++i)
        {
            EXPECT_EQ(storm->submit(indexOp("huge", 95 * charge)).cause, ic::Cause::QueueFull);
        }
        EXPECT_EQ(m_logs.count(WARN, "Indexer client bucket 'c/s' has no room"), 1u) << m_logs.dump();
        EXPECT_EQ(m_logs.count(WARN, "'c/s' reached 80%"), 0u);
        EXPECT_EQ(m_logs.count(WARN, "Indexer client global quota"), 0u) << "the default cap is far away";

        ASSERT_NO_FATAL_FAILURE(resolveOldest(m_held.size()));
        ASSERT_TRUE(component::eventually([this] { return drainedNow(); }, 5s));
        c.reset();
        ASSERT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);
    }

    // The global cap: a and b with the whole cap as quota; only the cap overflows.
    {
        SCOPED_TRACE("global");
        next = 0;
        dispatched = 0;
        ASSERT_NO_FATAL_FAILURE(start(1, 2, {{"global_quota_bytes", std::to_string(100 * charge)}}));
        installSink(TestSink::Mode::Hold);
        auto c = client("c",
                        {bucketSpec("a", 100 * charge, ic::Overflow::Kind::Reject, 0, 1),
                         bucketSpec("b", 100 * charge, ic::Overflow::Kind::Reject, 0, 1)});
        auto a = c->writer("a");
        auto b = c->writer("b");
        const std::string at80 = "Indexer client global quota reached 80%";
        const std::string full = "Indexer client global quota is full";
        const auto bucket80 = m_logs.count(WARN, "reached 80% of its quota");
        const auto bucketFull = m_logs.count(WARN, "has no room for new operations");

        ASSERT_NO_FATAL_FAILURE(submitN(*a, 45));
        ASSERT_NO_FATAL_FAILURE(submitN(*b, 34));
        EXPECT_EQ(m_logs.count(WARN, at80), 0u) << "79 %";
        ASSERT_NO_FATAL_FAILURE(submitN(*b, 6));
        EXPECT_EQ(m_logs.count(WARN, at80), 1u) << "85 %";
        ASSERT_NO_FATAL_FAILURE(resolveOldest(3));
        EXPECT_EQ(m_logs.count(WARN, at80), 1u) << "82 %";
        EXPECT_EQ(a->submit(big()).cause, ic::Cause::QueueFull);
        EXPECT_EQ(m_logs.count(WARN, full), 1u) << "refused at 82 %";
        ASSERT_NO_FATAL_FAILURE(submitN(*b, 13));
        EXPECT_EQ(m_logs.count(WARN, at80), 1u) << "95 %";
        EXPECT_EQ(b->submit(big()).cause, ic::Cause::QueueFull);
        EXPECT_EQ(m_logs.count(WARN, full), 1u) << "refused again at 95 %";
        ASSERT_NO_FATAL_FAILURE(resolveOldest(30));
        EXPECT_EQ(m_logs.count(WARN, at80), 1u) << "65 %";
        ASSERT_NO_FATAL_FAILURE(submitN(*a, 20));
        EXPECT_EQ(m_logs.count(WARN, at80), 2u) << "85 % after the re-arm";
        EXPECT_EQ(m_logs.count(WARN, full), 1u);
        EXPECT_EQ(a->submit(big()).cause, ic::Cause::QueueFull);
        EXPECT_EQ(m_logs.count(WARN, full), 2u) << "refused at 85 % after the re-arm";
        EXPECT_EQ(m_logs.count(WARN, "reached 80% of its quota"), bucket80) << "no bucket passed 80 % of its own quota";
        EXPECT_EQ(m_logs.count(WARN, "has no room for new operations"), bucketFull)
            << "the cap refused, no bucket's quota did" << m_logs.dump();

        ASSERT_NO_FATAL_FAILURE(resolveOldest(m_held.size()));
    }
}

// CA-16 (OverrunSummarized): 50 callbacks of twice the budget: one WARN for the client and the interval, with 50 and
// the slowest duration; none for a client without overruns, none in the next interval.
TEST_F(LogSummaryTest, OverrunSummarized)
{
    constexpr int BUDGET_MS = 5;
    ASSERT_NO_FATAL_FAILURE(start(1, 2, {{"callback_budget_ms", std::to_string(BUDGET_MS)}}));
    installSink(TestSink::Mode::ResolveOk);
    auto slow = client("slow", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 0, 1)});
    auto quick = client("quick", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 0, 1)});
    ASSERT_TRUE(ic::detail::testing::flushLogSummary());
    auto results = Results::create();
    for (int i = 0; i < 50; ++i)
    {
        ASSERT_TRUE(slow->writer("b")
                        ->submit(indexOp("s" + std::to_string(i)),
                                 [](const ic::OpResult&)
                                 { std::this_thread::sleep_for(std::chrono::milliseconds(2 * BUDGET_MS)); })
                        .accepted);
        ASSERT_TRUE(quick->writer("b")->submit(indexOp("q" + std::to_string(i)), results->callback(i)).accepted);
    }
    ASSERT_TRUE(results->waitTotal(50));
    ASSERT_TRUE(component::eventually([&] { return slow->metrics().callbackOverruns >= 50; }, 10s))
        << slow->metrics().callbackOverruns;
    ASSERT_TRUE(ic::detail::testing::flushLogSummary());
    const auto lines = m_logs.atLeast(WARN, "callbacks exceeded");
    ASSERT_EQ(lines.size(), 1u) << m_logs.dump();
    const auto& text = lines.front().text;
    EXPECT_NE(
        text.find("Indexer client consumer 'slow': 50 callbacks exceeded the callback budget of 5 ms in the last"),
        std::string::npos)
        << text;
    const auto slowest = text.find("(the slowest took ");
    ASSERT_NE(slowest, std::string::npos) << text;
    EXPECT_GE(std::stoull(text.substr(slowest + 18)), 2u * BUDGET_MS) << text;
    EXPECT_EQ(m_logs.count(WARN, "'quick'"), 0u);

    ASSERT_TRUE(ic::detail::testing::flushLogSummary());
    EXPECT_EQ(m_logs.atLeast(WARN, "callbacks exceeded").size(), 1u) << "a delta per interval";
}

// CA-16 (SummaryTimerFiresAndFlushesAtStop): with log_summary_interval_ms = 1000 the timer summarizes within 3 s on its
// own; three failures resolved and one op still unresolved at shutdown() are all summarized, the unresolved one by the
// last summary (it runs after the shutdown sweep: `1 dropped`, key `shutdown`), and the seam is refused afterwards.
// No clock premise: the timer may or may not run between the resolves and shutdown(), so the oracle adds the lines up.
TEST_F(LogSummaryTest, SummaryTimerFiresAndFlushesAtStop)
{
    ASSERT_NO_FATAL_FAILURE(start(1, 2, {{"log_summary_interval_ms", "1000"}}));
    installSink(TestSink::Mode::Hold);
    auto c = client("c", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 0, 1)});
    auto writer = c->writer("b");
    ASSERT_TRUE(writer->submit(indexOp("a")).accepted);
    ASSERT_NO_FATAL_FAILURE(collectHeld(1));
    ASSERT_NO_FATAL_FAILURE(resolveOldest(1));
    const auto start = std::chrono::steady_clock::now();
    ASSERT_TRUE(
        component::eventually([&] { return m_logs.count(INFO, ": 1 accepted, 1 ok, 0 failed, 0 dropped.") == 1; }, 3s))
        << m_logs.dump();
    EXPECT_LE(std::chrono::steady_clock::now() - start, 3s);

    // Three failures, then one op left unresolved for the shutdown sweep.
    for (int i = 0; i < 4; ++i)
    {
        ASSERT_TRUE(writer->submit(indexOp("f" + std::to_string(i))).accepted);
    }
    ASSERT_NO_FATAL_FAILURE(collectHeld(5));
    ASSERT_EQ(m_held.size(), 4u);
    for (std::size_t i = 0; i < 3; ++i)
    {
        ASSERT_TRUE(m_path->resolve(bucketOf(*m_held[i]), m_held[i], failed(ic::Cause::ItemPermanent, "x", "r")));
    }
    m_held.clear();
    ASSERT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);

    const std::string info = "Indexer client bucket 'c/b' in the last ";
    std::vector<std::string> totals;
    std::size_t failedSum = 0;
    for (const auto& line : m_logs.lines())
    {
        if (line.level == INFO && line.text.find(info) != std::string::npos)
        {
            totals.push_back(line.text);
            const auto at = line.text.find(" ok, ");
            ASSERT_NE(at, std::string::npos) << line.text;
            failedSum += std::stoull(line.text.substr(at + 5));
        }
    }
    ASSERT_GE(totals.size(), 2u) << m_logs.dump();
    EXPECT_EQ(failedSum, 3u) << m_logs.dump();
    EXPECT_NE(totals.back().find(", 1 dropped."), std::string::npos)
        << "the last summary follows the sweep" << m_logs.dump();
    const auto warns = m_logs.atLeast(WARN, "Indexer client bucket 'c/b' unsuccessful operations in the last");
    ASSERT_FALSE(warns.empty()) << m_logs.dump();
    EXPECT_NE(warns.back().text.find("shutdown=1"), std::string::npos) << warns.back().text;
    std::size_t keyed = 0;
    for (const auto& line : warns)
    {
        const auto at = line.text.find("item_permanent/x=");
        keyed += at == std::string::npos ? 0 : std::stoull(line.text.substr(at + 17));
    }
    EXPECT_EQ(keyed, 3u) << m_logs.dump();
    EXPECT_FALSE(ic::detail::testing::flushLogSummary());
}

// D133 (ClosedDuringShutdownInLastSummary): the close order of modulesd (client.hpp: beginShutdown, then each consumer
// requestClose()s, awaitClosed()s and drops its Client, then shutdown()) still puts what that close dropped in the last
// summary: one op held by the sink (Dropped(Shutdown) by the sweep) and two still pending (Dropped(ClientClosed)). The
// consumer name is released by awaitClosed as before (a new client may take it). Mutant: releaseClientName without the
// retention (the old code) => no line for 'closing/b'.
TEST_F(LogSummaryTest, ClosedDuringShutdownInLastSummary)
{
    ASSERT_NO_FATAL_FAILURE(start());
    installSink(TestSink::Mode::Hold, 1);
    auto c = client("closing", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 0, 1)});
    auto writer = c->writer("b");
    ASSERT_TRUE(writer->submit(indexOp("held")).accepted);
    ASSERT_TRUE(m_sink->waitDispatched(1));
    ASSERT_TRUE(writer->submit(indexOp("p1")).accepted);
    ASSERT_TRUE(writer->submit(indexOp("p2")).accepted);
    writer.reset();

    ASSERT_EQ(ic::RuntimeOwner::beginShutdown(std::chrono::steady_clock::now() + 2s), ic::Cause::None);
    c->requestClose();
    const auto report = c->awaitClosed(std::chrono::steady_clock::now() + 1s);
    ASSERT_TRUE(report.ok()) << ic::toString(report.cause);
    EXPECT_EQ(report.value.droppedShutdown, 1u);
    EXPECT_EQ(report.value.droppedClientClosed, 2u);
    c.reset(); // The consumer's handle is gone before the runtime stops (VD and invsync reset theirs).
    auto again = m_ref.client("closing", {bucketSpec("b", 1u << 20, ic::Overflow::Kind::Reject, 0, 1)});
    EXPECT_TRUE(again.ok()) << "awaitClosed still releases the consumer name: " << again.reason;
    again.value.reset();
    EXPECT_EQ(m_logs.count(INFO, "Indexer client bucket 'closing/b' in the last "), 0u) << m_logs.dump();

    ASSERT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);
    const auto warns = m_logs.atLeast(WARN, "Indexer client bucket 'closing/b' unsuccessful operations in the last");
    ASSERT_EQ(warns.size(), 1u) << m_logs.dump();
    EXPECT_NE(warns.front().text.find("shutdown=1"), std::string::npos) << warns.front().text;
    EXPECT_NE(warns.front().text.find("client_closed=2"), std::string::npos) << warns.front().text;
    EXPECT_EQ(m_logs.count(INFO, "Indexer client bucket 'closing/b' in the last "), 1u) << m_logs.dump();
    EXPECT_EQ(m_logs.count(INFO, ": 3 accepted, 0 ok, 0 failed, 3 dropped."), 1u) << m_logs.dump();
}

/// The PIT cases: QueryTest plus the log sink.
class LogSummaryPitTest : public QueryTest
{
protected:
    Sink m_logs;

    void SetUp() override
    {
        QueryTest::SetUp();
        indexer_client::setLogFunction(m_logs.function());
    }

    void TearDown() override
    {
        QueryTest::TearDown();
        indexer_client::setLogFunction({});
    }
};

// I104 (PitAbandonedDeleteWarns): a PIT whose DELETE is confirmed logs nothing; one whose DELETE expires with the
// indexer down (keep_alive 1 s, before the shutdown) logs one WARN with the id truncated to 16 bytes.
TEST_F(LogSummaryPitTest, PitAbandonedDeleteWarns)
{
    namespace q = ic::detail::query;
    const std::string confirmedId = "CONFIRMEDPIT-0123456789-ABCDEFGHIJ";
    const std::string abandonedId = "ABANDONEDPIT-0123456789-ABCDEFGHIJ";
    auto node = fake(
        {query_component::rule("POST", "/confirmed/_search/point_in_time", 200, R"({"pit_id":")" + confirmedId + "\"}"),
         query_component::rule("POST", "/abandoned/_search/point_in_time", 200, R"({"pit_id":")" + abandonedId + "\"}"),
         query_component::rule("DELETE", "/_search/point_in_time", 200, R"({"pits":[]})")});
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}));
    auto c = client();
    const std::string gaveUp = "Indexer client gave up";

    const auto before = q::pitStats();
    {
        auto pit = c->query()->pit(
            {"confirmed"}, query_component::keepAlive(60s), query_component::fastOptions(), query_component::in(5s));
        ASSERT_TRUE(pit.ok()) << ic::toString(pit.cause) << ": " << pit.reason;
    }
    ASSERT_TRUE(component::eventually([&] { return q::pitStats().deletesConfirmed == before.deletesConfirmed + 1; },
                                      query_component::scaled(5s)));
    ASSERT_TRUE(ic::detail::testing::flushLogSummary());
    EXPECT_EQ(m_logs.atLeast(WARN, gaveUp).size(), 0u) << m_logs.dump();

    {
        auto pit = c->query()->pit(
            {"abandoned"}, query_component::keepAlive(1s), query_component::fastOptions(), query_component::in(5s));
        ASSERT_TRUE(pit.ok()) << ic::toString(pit.cause) << ": " << pit.reason;
        node->stop(); // The indexer goes away before the last handle does.
    }
    ASSERT_TRUE(component::eventually([&] { return q::pitStats().deletesExpired == before.deletesExpired + 1; },
                                      query_component::scaled(10s)))
        << "the DELETE never expired: " << q::pitStats().deletesPending << " pending";
    EXPECT_TRUE(ic::RuntimeOwner::running()) << "expired before the shutdown";
    ASSERT_TRUE(ic::detail::testing::flushLogSummary());
    const auto lines = m_logs.atLeast(WARN, gaveUp);
    ASSERT_EQ(lines.size(), 1u) << m_logs.dump();
    EXPECT_NE(lines.front().text.find("gave up 1 PIT delete(s)"), std::string::npos) << lines.front().text;
    EXPECT_NE(lines.front().text.find("'" + abandonedId.substr(0, 16) + "...'"), std::string::npos)
        << lines.front().text;
    EXPECT_EQ(lines.front().text.find(abandonedId), std::string::npos) << "the id is truncated";
    ASSERT_TRUE(ic::detail::testing::flushLogSummary());
    EXPECT_EQ(m_logs.atLeast(WARN, gaveUp).size(), 1u) << "one line per expiry";
}

// Obj. 4 of the G-diff (PitDeleteGivenUpAtShutdownLogged): a PIT still open at shutdown() whose DELETE the indexer
// holds; the drain gives it up at its end and the last summary, which runs after the drain, logs it.
TEST_F(LogSummaryPitTest, PitDeleteGivenUpAtShutdownLogged)
{
    namespace q = ic::detail::query;
    const std::string id = "SHUTDOWNPIT-0123456789-ABCDEFGHIJ";
    auto held = query_component::rule("DELETE", "/_search/point_in_time", 200, R"({"pits":[]})");
    held.hold = true;
    auto node = fake({query_component::rule("POST", "/idx/_search/point_in_time", 200, R"({"pit_id":")" + id + "\"}"),
                      std::move(held)});
    ASSERT_NO_FATAL_FAILURE(start({node->baseUrl()}, {{"drain_ms", "2000"}}));
    const auto before = q::pitStats();
    std::unique_ptr<ic::Pit> open;
    {
        auto c = client();
        auto pit = c->query()->pit(
            {"idx"}, query_component::keepAlive(60s), query_component::fastOptions(), query_component::in(5s));
        ASSERT_TRUE(pit.ok()) << ic::toString(pit.cause) << ": " << pit.reason;
        open = std::make_unique<ic::Pit>(pit.value);
    }
    EXPECT_EQ(m_logs.atLeast(WARN, "Indexer client gave up").size(), 0u);
    EXPECT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None);
    EXPECT_EQ(q::pitStats().deletesExpired, before.deletesExpired + 1);
    const auto lines = m_logs.atLeast(WARN, "Indexer client gave up 1 PIT delete(s)");
    ASSERT_EQ(lines.size(), 1u) << m_logs.dump();
    EXPECT_NE(lines.front().text.find("'" + id.substr(0, 16) + "...'"), std::string::npos) << lines.front().text;
    node->releaseHeld();
    open.reset();
}
