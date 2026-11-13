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

// No shared read-modify-write per op. The action lines of the kinds without `_id`
// live in the write path's HeadTable (append-only, 256 entries, never freed before the write path; past the cap an op
// builds its own line) and the ops point at them; WritePath::resolve takes the bucket from its caller (OpState keeps
// none). The lines outlive the producer thread and every reader (the pool's assembly during a shutdown, a group of a
// dead path), and the dead-bucket branch of a group commit stays intact. ASAN gives the use-after-free verdict;
// without it each case checks what it can observe.

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "bulkFixture.hpp"
#include "testTimeScale.hpp"
#include "transport/seams.hpp"

using namespace write_component;
using component::eventually;
using indexer_client::testing::scaled;

namespace
{
    constexpr auto R = wr::RESULT_RESERVE;

    ic::Op streamOp(const std::string& index, std::size_t key)
    {
        ic::Op op;
        op.kind = ic::Op::Kind::IndexDataStream;
        op.index = index;
        op.body = R"({"n":)" + std::to_string(key) + "}";
        return op;
    }

    /// An IndexDataStream op with an `_id`: its own line, never the table's.
    ic::Op streamOpWithId(const std::string& index, std::size_t key, std::string docId)
    {
        auto op = streamOp(index, key);
        op.id = std::move(docId);
        return op;
    }

    /// The bytes of `op` built on its own (no table): the reference for a shared line.
    std::string ownWire(ic::Op op)
    {
        auto encoded = wr::encode(std::move(op), ic::ConflictPolicy {});
        EXPECT_TRUE(encoded.ok()) << encoded.reason;
        EXPECT_EQ(encoded.value.cachedHead, nullptr);
        return wireOf(encoded.value);
    }
} // namespace

class WriteEncoding : public BulkTest
{
};

class WriteGroup : public WriteTest
{
};

// A producer thread posts ops on two indices, alternating (the engine's raw + events), and ends while they are still
// held by the sink: every op keeps its exact bytes, points at the table's line of its index (two lines in all, one
// per index: no duplicate), and resolves afterwards.
TEST_F(WriteEncoding, SharedHeadOutlivesProducerThread)
{
    ic::testing_hooks::setProbeAutoStart(false);
    ASSERT_NO_FATAL_FAILURE(start());
    auto sink = installSink();
    constexpr std::size_t OPS = 40;
    auto c = client("c", {bucketSpec("w", 1u << 20, ic::Overflow::Kind::Reject, 0, OPS)});
    auto writer = c->writer("w");
    const std::vector<std::string> indices {"wazuh-events-raw", "wazuh-events-v5-system"};
    std::thread producer(
        [&]
        {
            for (std::size_t k = 0; k < OPS; ++k)
            {
                EXPECT_TRUE(writer->post(streamOp(indices[k % 2], k)).accepted);
            }
        });
    producer.join(); // Its thread_local cache is gone; the lines are the write path's.
    ASSERT_TRUE(sink->waitDispatched(1));
    auto batches = sink->take();
    ASSERT_EQ(batches.size(), 1u);
    ASSERT_EQ(batches[0].ops.size(), OPS);
    std::set<const std::string*> lines;
    for (std::size_t k = 0; k < OPS; ++k)
    {
        const auto& op = *batches[0].ops[k];
        EXPECT_EQ(wireOf(op), ownWire(streamOp(indices[k % 2], k))) << k;
        ASSERT_NE(op.cachedHead, nullptr) << k;
        EXPECT_EQ(op.cachedHead, m_path->heads().find(ic::Op::Kind::IndexDataStream, indices[k % 2])) << k;
        EXPECT_TRUE(op.head.empty());
        lines.insert(op.cachedHead);
    }
    EXPECT_EQ(lines.size(), 2u);
    EXPECT_EQ(m_path->heads().size(), 2u);
    std::size_t won = 0;
    for (const auto& op : batches[0].ops)
    {
        won += m_path->resolve(batches[0].bucket, op, TestSink::ok()) ? 1 : 0;
    }
    EXPECT_EQ(won, OPS);
}

// 300 indices: the first 256 enter the table and are shared; the other 44 build their own line (no cache, no table
// entry) with the same bytes; an index already in the table keeps hitting it, one beyond the cap never does.
// The cap is per runtime lifetime, so a full table must cost no lock: past 256 entries a new index never takes
// the append mutex (one take per entry stored, none after).
TEST_F(WriteEncoding, HeadTableCapFallsBack)
{
    wr::HeadTable table;
    constexpr std::size_t INDICES = 300;
    const auto index = [](std::size_t i)
    {
        return "wazuh-events-cap-" + std::to_string(i);
    };
    for (std::size_t i = 0; i < INDICES; ++i)
    {
        SCOPED_TRACE(i);
        auto encoded = wr::encode(streamOp(index(i), i), ic::ConflictPolicy {}, false, &table);
        ASSERT_TRUE(encoded.ok()) << encoded.reason;
        EXPECT_EQ(wireOf(encoded.value), ownWire(streamOp(index(i), i)));
        if (i < wr::HeadTable::CAPACITY)
        {
            EXPECT_NE(encoded.value.cachedHead, nullptr);
            EXPECT_TRUE(encoded.value.head.empty());
            EXPECT_EQ(table.appendLocks(), i + 1) << "one take of the append mutex per entry stored";
        }
        else
        {
            EXPECT_EQ(encoded.value.cachedHead, nullptr) << "past the cap: the op's own line";
            EXPECT_FALSE(encoded.value.head.empty());
            EXPECT_EQ(table.appendLocks(), wr::HeadTable::CAPACITY) << "a full table never takes the append mutex";
        }
    }
    EXPECT_EQ(table.size(), wr::HeadTable::CAPACITY);
    EXPECT_TRUE(table.full());
    const auto first = wr::encode(streamOp(index(0), 0), ic::ConflictPolicy {}, false, &table);
    ASSERT_TRUE(first.ok());
    EXPECT_EQ(first.value.cachedHead, table.find(ic::Op::Kind::IndexDataStream, index(0)));
    const auto beyond = wr::encode(streamOp(index(INDICES - 1), 1), ic::ConflictPolicy {}, false, &table);
    ASSERT_TRUE(beyond.ok());
    EXPECT_EQ(beyond.value.cachedHead, nullptr);
    EXPECT_EQ(table.size(), wr::HeadTable::CAPACITY);
    std::string line = "unused";
    EXPECT_EQ(table.intern(ic::Op::Kind::IndexDataStream, index(INDICES - 1), std::move(line)), nullptr);
    EXPECT_EQ(table.intern(ic::Op::Kind::IndexDataStream, index(0), std::string("unused")),
              table.find(ic::Op::Kind::IndexDataStream, index(0)))
        << "a full table still hands out the lines it holds";
    EXPECT_EQ(table.appendLocks(), wr::HeadTable::CAPACITY) << "intern() on a full table takes no mutex either";

    // A second table (a new runtime) never matches the first one's cache entries (generation, not address).
    wr::HeadTable other;
    EXPECT_GT(other.generation(), table.generation());
    const auto fresh = wr::encode(streamOp(index(0), 0), ic::ConflictPolicy {}, false, &other);
    ASSERT_TRUE(fresh.ok());
    EXPECT_EQ(fresh.value.cachedHead, other.find(ic::Op::Kind::IndexDataStream, index(0)));
    EXPECT_NE(fresh.value.cachedHead, first.value.cachedHead);
}

// On one thread, an op without `_id` fills the per-thread cache and the table; an op with an
// `_id` to the same index afterwards carries its own line with that `_id` (cachedHead null, the cache never consulted);
// the op without `_id` keeps the shared line, and the next one without `_id` still hits it. Mutant: sharedKind ignores
// the `_id` (the second op takes the cached line, without its `_id`).
TEST_F(WriteEncoding, DataStreamIdNeverUsesSharedHead)
{
    wr::HeadTable table;
    const std::string index = "wazuh-events-id-after";
    auto first = wr::encode(streamOp(index, 1), ic::ConflictPolicy {}, false, &table);
    ASSERT_TRUE(first.ok()) << first.reason;
    const auto* line = table.find(ic::Op::Kind::IndexDataStream, index);
    ASSERT_NE(line, nullptr);
    EXPECT_EQ(first.value.cachedHead, line) << "precondition: the op without _id is shared";
    EXPECT_EQ(table.size(), 1u);

    auto withId = wr::encode(streamOpWithId(index, 2, "doc-2"), ic::ConflictPolicy {}, false, &table);
    ASSERT_TRUE(withId.ok()) << withId.reason;
    EXPECT_EQ(withId.value.cachedHead, nullptr) << "an op with an _id never takes the shared line";
    EXPECT_EQ(std::string(withId.value.headView()), "{\"create\":{\"_index\":\"" + index + "\",\"_id\":\"doc-2\"}}\n");
    EXPECT_EQ(wireOf(withId.value), ownWire(streamOpWithId(index, 2, "doc-2")));
    EXPECT_EQ(table.size(), 1u) << "the line with an _id is not interned";
    EXPECT_EQ(*line, "{\"create\":{\"_index\":\"" + index + "\"}}\n") << "the shared line is untouched";

    EXPECT_EQ(first.value.cachedHead, line) << "the first op still points at the shared line";
    EXPECT_EQ(wireOf(first.value), ownWire(streamOp(index, 1)));
    auto again = wr::encode(streamOp(index, 3), ic::ConflictPolicy {}, false, &table);
    ASSERT_TRUE(again.ok()) << again.reason;
    EXPECT_EQ(again.value.cachedHead, line) << "an op without _id still shares the line";
    EXPECT_EQ(table.size(), 1u);
}

// The inverse order on an empty table: an op with `_id` a, then one without, then one with `_id`
// b, all to one index: three distinct lines; the table only ever holds the line without `_id`; cachedHead is null
// exactly for the ops with an `_id`. Mutant: sharedKind ignores the `_id` (the first op interns its line with `_id` a,
// and the other two take it).
TEST_F(WriteEncoding, DataStreamIdFirstNeverInterned)
{
    wr::HeadTable table;
    const std::string index = "wazuh-events-id-first";
    auto a = wr::encode(streamOpWithId(index, 1, "a"), ic::ConflictPolicy {}, false, &table);
    ASSERT_TRUE(a.ok()) << a.reason;
    EXPECT_EQ(a.value.cachedHead, nullptr);
    EXPECT_EQ(table.size(), 0u) << "a line with an _id is never interned";
    EXPECT_EQ(table.find(ic::Op::Kind::IndexDataStream, index), nullptr);

    auto none = wr::encode(streamOp(index, 2), ic::ConflictPolicy {}, false, &table);
    ASSERT_TRUE(none.ok()) << none.reason;
    ASSERT_NE(none.value.cachedHead, nullptr);
    EXPECT_EQ(table.size(), 1u);
    EXPECT_EQ(none.value.cachedHead, table.find(ic::Op::Kind::IndexDataStream, index));

    auto b = wr::encode(streamOpWithId(index, 3, "b"), ic::ConflictPolicy {}, false, &table);
    ASSERT_TRUE(b.ok()) << b.reason;
    EXPECT_EQ(b.value.cachedHead, nullptr);
    EXPECT_EQ(table.size(), 1u);

    const std::string lineA(a.value.headView());
    const std::string lineNone(none.value.headView());
    const std::string lineB(b.value.headView());
    EXPECT_EQ(lineA, "{\"create\":{\"_index\":\"" + index + "\",\"_id\":\"a\"}}\n");
    EXPECT_EQ(lineNone, "{\"create\":{\"_index\":\"" + index + "\"}}\n");
    EXPECT_EQ(lineB, "{\"create\":{\"_index\":\"" + index + "\",\"_id\":\"b\"}}\n");
    EXPECT_EQ(*table.find(ic::Op::Kind::IndexDataStream, index), lineNone) << "the table holds no line with an _id";
    EXPECT_EQ(wireOf(a.value), ownWire(streamOpWithId(index, 1, "a")));
    EXPECT_EQ(wireOf(none.value), ownWire(streamOp(index, 2)));
    EXPECT_EQ(wireOf(b.value), ownWire(streamOpWithId(index, 3, "b")));
}

// No reader of a line outlives the write path: the runtime shuts down while the pool assembles a bulk of shared-line
// ops (seam beforeAssembly parks it), and the write path is still alive when the assembly reads them; it dies with the
// runtime afterwards. A group built on that path and committed after it died resolves Dropped(Shutdown) without
// reading its ops' lines.
TEST_F(WriteEncoding, NoHeadReaderAfterRuntime)
{
    const auto node = startNode();
    ASSERT_NO_FATAL_FAILURE(startOn({node.url()}, std::chrono::milliseconds(3600000), {{"drain_ms", "200"}}));
    std::weak_ptr<wr::WritePath> weakPath = m_path;

    struct Gate final
    {
        std::mutex mutex;
        std::condition_variable cv;
        bool reached {false};
        bool open {false};
        std::optional<bool> pathAlive;
    };
    auto gate = std::make_shared<Gate>();
    ic::testing_hooks::setBeforeAssembly(
        [gate, weakPath]
        {
            std::unique_lock<std::mutex> lock(gate->mutex);
            if (gate->reached)
            {
                return; // Only the first assembly parks.
            }
            gate->reached = true;
            gate->cv.notify_all();
            gate->cv.wait(lock, [&] { return gate->open; });
            gate->pathAlive = !weakPath.expired(); // The assembly reads the lines right after this returns.
        });

    std::optional<ic::Group> group;
    {
        auto c = client("c", {bucketSpec("w", 1u << 20, ic::Overflow::Kind::Reject, 0, 4, ic::Duration {1})});
        auto g = client("g", {bucketSpec("w", 1u << 20, ic::Overflow::Kind::Reject)});
        {
            auto writer = c->writer("w");
            for (std::size_t k = 0; k < 4; ++k)
            {
                ASSERT_TRUE(writer->post(streamOp("wazuh-events-shutdown", k)).accepted);
            }
            auto groupWriter = g->writer("w");
            group.emplace(groupWriter->group());
            ASSERT_EQ(group->add(streamOp("wazuh-events-group", 1)), ic::Cause::None) << group->lastAddReason();
        }
        std::unique_lock<std::mutex> lock(gate->mutex);
        ASSERT_TRUE(gate->cv.wait_for(lock, scaled(std::chrono::seconds(5)), [&] { return gate->reached; }));
    } // ~Client x2 (awaitClosed, drain_ms 200): the parked bulk is swept; the group stays Building.

    m_path.reset(); // Only the runtime keeps the write path now.
    m_ref = ic::RuntimeRef {};
    std::thread opener(
        [gate]
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(50)); // The shutdown waits for the parked assembly.
            {
                std::lock_guard<std::mutex> lock(gate->mutex);
                gate->open = true;
            }
            gate->cv.notify_all();
        });
    EXPECT_EQ(ic::RuntimeOwner::shutdown(), ic::Cause::None); // The owner thread's call.
    opener.join();
    ic::testing_hooks::setBeforeAssembly({});
    {
        std::lock_guard<std::mutex> lock(gate->mutex);
        ASSERT_TRUE(gate->pathAlive.has_value());
        EXPECT_TRUE(*gate->pathAlive) << "the assembly ran after the write path (and its lines) died";
    }
    EXPECT_TRUE(weakPath.expired()) << "the write path outlived the runtime: the case proves nothing";

    const auto ticket = group->commit(); // A dead path: Dropped(Shutdown), no line read.
    const auto outcome = ticket.wait(std::chrono::steady_clock::now() + scaled(std::chrono::seconds(5)));
    ASSERT_TRUE(outcome.ok()) << ic::toString(outcome.cause);
    ASSERT_EQ(outcome.value.size(), 1u);
    EXPECT_EQ(outcome.value[0].status, ic::Status::Dropped);
    EXPECT_EQ(outcome.value[0].cause, ic::Cause::Shutdown);
    group.reset();
}

// A group of shared-line ops whose client, writer and bucket die before the commit (the group alone keeps it): the
// commit takes the dead-bucket branch (resolve with no bucket) — every op Dropped(ClientClosed), the payload
// and `building` back at once, the reserves when the group state dies — and never touches the dead bucket.
TEST_F(WriteGroup, CommitAfterBucketDied)
{
    constexpr std::uint64_t N = 3;
    ASSERT_NO_FATAL_FAILURE(start());
    installSink();
    std::uint64_t charge = 0;
    std::optional<ic::Group> group;
    {
        auto c = client("c", {bucketSpec("b", 1u << 20)});
        auto writer = c->writer("b");
        group.emplace(writer->group());
        for (std::uint64_t i = 0; i < N; ++i)
        {
            auto op = streamOp("wazuh-events-group-dead", i);
            charge += wireSize(op) + R;
            ASSERT_EQ(group->add(std::move(op)), ic::Cause::None) << group->lastAddReason();
        }
        EXPECT_NE(m_path->heads().find(ic::Op::Kind::IndexDataStream, "wazuh-events-group-dead"), nullptr);
        writer.reset();
    }
    EXPECT_EQ(m_path->stats().buckets.size(), 0u) << "the bucket is gone";
    EXPECT_EQ(globalCharge(), charge);

    {
        const auto ticket = group->commit();
        const auto outcome = ticket.wait(std::chrono::steady_clock::now() + scaled(std::chrono::seconds(5)));
        ASSERT_TRUE(outcome.ok()) << ic::toString(outcome.cause) << ": " << outcome.reason;
        ASSERT_EQ(outcome.value.size(), N);
        for (const auto& result : outcome.value)
        {
            EXPECT_EQ(result.status, ic::Status::Dropped);
            EXPECT_EQ(result.cause, ic::Cause::ClientClosed);
        }
        EXPECT_EQ(globalCharge(), N * R) << "payload back, the reserves wait for the group state";
    }
    group.reset();
    EXPECT_EQ(globalCharge(), 0u);
}
