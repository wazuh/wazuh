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

// CA-28 against a real OpenSearch (D45): the Painless of ReplacePreserving, its version guard, `"upsert":{}` (I71),
// retry_on_conflict under two concurrent clients, and the per-item outcomes of a bulk.

#include <atomic>
#include <iostream>
#include <thread>

#include "openSearchSupport.hpp"
#include "write/encoding.hpp"

using namespace indexer_client;
using namespace indexer_client::opensearch;
using namespace std::chrono_literals;

namespace
{
    Op preserving(const std::string& index, const std::string& id, const nlohmann::json& doc)
    {
        Op op;
        op.kind = Op::Kind::Index;
        op.index = index;
        op.id = id;
        op.body = doc.dump();
        op.mode.kind = WriteMode::Kind::ReplacePreserving;
        op.mode.preservedPaths = {"case.status", "case.notes.a"};
        return op;
    }

    Op versioned(const std::string& index, const std::string& id, std::uint64_t version, const nlohmann::json& doc)
    {
        Op op;
        op.kind = Op::Kind::IndexVersionedScript;
        op.index = index;
        op.id = id;
        op.version = std::to_string(version);
        op.body = doc.dump();
        return op;
    }

    Op plainIndex(const std::string& index, const std::string& id, const nlohmann::json& doc)
    {
        Op op;
        op.kind = Op::Kind::Index;
        op.index = index;
        op.id = id;
        op.body = doc.dump();
        return op;
    }

    Op deleteOp(const std::string& index, const std::string& id)
    {
        Op op;
        op.kind = Op::Kind::Delete;
        op.index = index;
        op.id = id;
        return op;
    }

    const BucketMetrics& bucketOf(const ClientMetrics& metrics)
    {
        return metrics.buckets.at(0);
    }
} // namespace

class OpenSearchPreserve : public OpenSearchTest
{
protected:
    // A wide node window lets many one-document bulks of the same id be in flight at once (ConcurrentRetryOnConflict).
    std::map<std::string, std::string> runtimeOptions() const override
    {
        auto options = OpenSearchTest::runtimeOptions();
        options["node_window_max"] = "16";
        return options;
    }
};

class OpenSearchBulk : public OpenSearchTest
{
};

TEST_F(OpenSearchPreserve, ReplacePreservingKeepsNestedUserPaths)
{
    auto client = makeClient("os-preserve", {quickBucket("inventory")});
    ASSERT_NE(client, nullptr);
    auto writer = client->writer("inventory");

    // The agent's first sync creates the document (scripted_upsert runs the script on the upsert).
    const nlohmann::json first = {{"agent", {{"id", "001"}}}, {"os", {{"name", "linux"}, {"x", "only-in-v1"}}}};
    auto created = submitAndWait(*writer, preserving(m_index, "doc-1", first));
    ASSERT_EQ(created.status, Status::Ok) << toString(created.cause) << ": " << created.reason;
    EXPECT_EQ(created.outcome, ItemOutcome::Created);

    // The user adds the case fields out of band.
    const auto user = raw(
        "POST", "/" + m_index + "/_update/doc-1", R"({"doc":{"case":{"status":"open","notes":{"a":"n1","b":"n2"}}}})");
    ASSERT_EQ(user.status, 200) << user.body;

    // The agent re-syncs without os.x and with its own case.status: user wins at the preserved paths.
    const nlohmann::json second = {
        {"agent", {{"id", "001"}}}, {"os", {{"name", "linux2"}}}, {"case", {{"status", "from-agent"}}}};
    auto updated = submitAndWait(*writer, preserving(m_index, "doc-1", second));
    ASSERT_EQ(updated.status, Status::Ok) << toString(updated.cause) << ": " << updated.reason;
    EXPECT_EQ(updated.outcome, ItemOutcome::Updated);

    std::int64_t version = 0;
    const auto source = getSource(m_index, "doc-1", &version);
    ASSERT_TRUE(source.has_value());
    std::cout << "E6B-BODY preserve._source=" << source->dump() << "\n";
    EXPECT_FALSE(source->at("os").contains("x")) << "a field the agent no longer sends must disappear";
    EXPECT_EQ(source->at("os").at("name"), "linux2");
    EXPECT_EQ(source->at("agent").at("id"), "001");
    ASSERT_TRUE(source->contains("case")) << source->dump();
    EXPECT_EQ(source->at("case").value("status", ""), "open") << "the stored value wins at a preserved path";
    ASSERT_TRUE(source->at("case").contains("notes")) << source->dump();
    EXPECT_EQ(source->at("case").at("notes").value("a", ""), "n1");
    EXPECT_FALSE(source->at("case").at("notes").contains("b")) << "only the preserved paths come back";
    EXPECT_EQ(version, 3);
}

TEST_F(OpenSearchPreserve, OlderVersionIsNoop)
{
    auto client = makeClient("os-noop", {quickBucket("inventory")});
    ASSERT_NE(client, nullptr);
    auto writer = client->writer("inventory");

    auto make = [&](std::uint64_t version, const std::string& data)
    {
        auto op = versioned(m_index,
                            "doc-1",
                            version,
                            {{"state", {{"document_version", version}}}, {"data", data}, {"case", {{"status", "x"}}}});
        op.mode.kind = WriteMode::Kind::ReplacePreserving;
        op.mode.preservedPaths = {"case.status"};
        return op;
    };

    auto created = submitAndWait(*writer, make(5, "v5"));
    ASSERT_EQ(created.status, Status::Ok) << created.reason;
    EXPECT_EQ(created.outcome, ItemOutcome::Created);
    std::int64_t versionBefore = 0;
    const auto before = getSource(m_index, "doc-1", &versionBefore);
    ASSERT_TRUE(before.has_value());

    auto older = submitAndWait(*writer, make(3, "v3"));
    EXPECT_EQ(older.status, Status::Ok) << older.reason;
    EXPECT_EQ(older.outcome, ItemOutcome::Noop);

    std::int64_t versionAfter = 0;
    const auto after = getSource(m_index, "doc-1", &versionAfter);
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(*after, *before) << "a noop leaves _source intact";
    EXPECT_EQ(after->at("data"), "v5");
    EXPECT_EQ(versionAfter, versionBefore);
}

TEST_F(OpenSearchPreserve, UpsertEmptyCreatesAgentDoc)
{
    // I71 / D45: is `"upsert":{}` equivalent to the library's `"upsert":<doc>` for a missing document? The raw line is
    // written by hand with the production script; the library's line goes to another id; both must create the doc.
    const nlohmann::json doc = {{"agent", {{"id", "002"}}}, {"os", {{"name", "windows"}}}, {"n", 7}};
    const nlohmann::json action = {{"update", {{"_index", m_index}, {"_id", "raw-empty-upsert"}}}};
    const nlohmann::json script = {
        {"script",
         {{"source", std::string(detail::write::PRESERVE_SOURCE)},
          {"lang", "painless"},
          {"params", {{"paths", nlohmann::json::array({nlohmann::json::array({"case", "status"})})}, {"doc", doc}}}}},
        {"upsert", nlohmann::json::object()},
        {"scripted_upsert", true}};
    const auto bulk = raw("POST", "/_bulk", action.dump() + "\n" + script.dump() + "\n", "application/x-ndjson");
    std::cout << "E6B-BODY upsert_empty.bulk=" << bulk.body << "\n";
    ASSERT_EQ(bulk.status, 200) << bulk.body;
    const auto response = nlohmann::json::parse(bulk.body);
    EXPECT_FALSE(response.at("errors").get<bool>());
    const auto& item = response.at("items").at(0).at("update");
    EXPECT_EQ(item.at("result"), "created");
    EXPECT_EQ(item.at("status"), 201);
    const auto rawSource = getSource(m_index, "raw-empty-upsert", nullptr);
    ASSERT_TRUE(rawSource.has_value());
    EXPECT_EQ(*rawSource, doc) << "the agent's document, not {}";

    auto client = makeClient("os-upsert", {quickBucket("inventory")});
    ASSERT_NE(client, nullptr);
    auto writer = client->writer("inventory");
    auto op = preserving(m_index, "lib-upsert", doc);
    auto created = submitAndWait(*writer, std::move(op));
    ASSERT_EQ(created.status, Status::Ok) << created.reason;
    EXPECT_EQ(created.outcome, ItemOutcome::Created);
    const auto libSource = getSource(m_index, "lib-upsert", nullptr);
    ASSERT_TRUE(libSource.has_value());
    EXPECT_EQ(*libSource, *rawSource) << "\"upsert\":{} and \"upsert\":<doc> must create the same document";
    std::cout << MEASURE << "upsert_empty.equivalent=" << (*libSource == *rawSource ? 1 : 0) << "\n";
}

TEST_F(OpenSearchPreserve, ConcurrentRetryOnConflict)
{
    // Two clients write the same id at once (ReplacePreserving without guard, ConflictPolicy::Retry): every write must
    // apply exactly once, so _version ends at N1 + N2. The server absorbs most conflicts itself (retry_on_conflict =
    // 1), so a 409 reaches the client only now and then: the clients write rounds of ROUND writes each until one was
    // seen (at most MAX_ROUNDS); N1 and N2 are the totals written.
    constexpr int ROUND = 500;
    constexpr int MAX_ROUNDS = 10;
    auto spec = [](const std::string& name)
    {
        auto bucket = quickBucket(name);
        bucket.bulk.maxDocs = 1;
        bucket.bulk.maxAge = Duration {2};
        bucket.onConflict.kind = ConflictPolicy::Kind::Retry;
        bucket.onConflict.retryOnConflict = 1;
        bucket.retry.maxAttempts = std::nullopt;
        bucket.retry.maxDuration = Duration {120000};
        bucket.retry.base = Duration {5};
        bucket.retry.cap = Duration {100};
        return bucket;
    };
    auto first = makeClient("os-conc-1", {spec("conc")});
    auto second = makeClient("os-conc-2", {spec("conc")});
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);
    auto conflicts = [](const Client& client)
    {
        return bucketOf(client.metrics()).retries[static_cast<std::size_t>(RetryCause::VersionConflict)];
    };

    int n1 = 0;
    int n2 = 0;
    int rounds = 0;
    int created = 0;
    int updated = 0;
    int other = 0;
    int failed = 0;
    auto produce = [&](Client& client, int writerId, const std::atomic<bool>& go, std::vector<Ticket>& tickets)
    {
        auto writer = client.writer("conc");
        while (!go.load())
        {
            std::this_thread::yield();
        }
        for (int i = 0; i < ROUND; ++i)
        {
            auto op = preserving(m_index, "shared", {{"agent", {{"id", "003"}}}, {"writer", writerId}, {"n", i}});
            auto submit = writer->submit(std::move(op));
            ASSERT_TRUE(submit.accepted) << submit.reason;
            tickets.push_back(submit.ticket);
        }
    };
    while (rounds < MAX_ROUNDS && conflicts(*first) + conflicts(*second) == 0)
    {
        ++rounds;
        std::vector<Ticket> tickets1;
        std::vector<Ticket> tickets2;
        std::atomic<bool> go {false};
        std::thread t1(produce, std::ref(*first), 1, std::cref(go), std::ref(tickets1));
        std::thread t2(produce, std::ref(*second), 2, std::cref(go), std::ref(tickets2));
        go.store(true);
        t1.join();
        t2.join();
        ASSERT_EQ(tickets1.size(), static_cast<std::size_t>(ROUND));
        ASSERT_EQ(tickets2.size(), static_cast<std::size_t>(ROUND));
        n1 += ROUND;
        n2 += ROUND;
        for (auto* tickets : {&tickets1, &tickets2})
        {
            for (const auto& ticket : *tickets)
            {
                const auto result = ticket.wait(after(indexer_client::testing::scaled(120s)));
                ASSERT_TRUE(result.ok()) << toString(result.cause);
                if (result.value.status != Status::Ok)
                {
                    ++failed;
                    ADD_FAILURE() << toString(result.value.cause) << " " << result.value.httpStatus << " "
                                  << result.value.reason;
                    continue;
                }
                switch (result.value.outcome)
                {
                    case ItemOutcome::Created: ++created; break;
                    case ItemOutcome::Updated: ++updated; break;
                    default: ++other; break;
                }
            }
        }
    }
    std::int64_t version = 0;
    ASSERT_TRUE(getSource(m_index, "shared", &version).has_value());
    const auto conflicts1 = conflicts(*first);
    const auto conflicts2 = conflicts(*second);
    const auto bulks = bucketOf(first->metrics()).bulkRequests + bucketOf(second->metrics()).bulkRequests;
    std::cout << MEASURE << "concurrent.version=" << version << " n1=" << n1 << " n2=" << n2 << " rounds=" << rounds
              << " created=" << created << " updated=" << updated << " noop_or_other=" << other << " failed=" << failed
              << " retries.version_conflict(409 items requeued)=" << (conflicts1 + conflicts2) << " (" << conflicts1
              << "+" << conflicts2 << ") bulks=" << bulks << "\n";
    EXPECT_EQ(version, n1 + n2);
    EXPECT_EQ(created, 1);
    EXPECT_EQ(updated, n1 + n2 - 1);
    EXPECT_EQ(other, 0);
    EXPECT_EQ(failed, 0);
    // Informative only: retry_on_conflict = 1 (the library's minimum, I73) lets the server absorb almost every
    // conflict, so whether a 409 reaches the client in MAX_ROUNDS is chance (measured: 0-2). The client's own retry of
    // a 409 is pinned by the fake's suites; here the contract is that no write is lost or duplicated.
    RecordProperty("client_visible_409", std::to_string(conflicts1 + conflicts2));
}

TEST_F(OpenSearchBulk, ErrorsFalseOutcomes)
{
    auto client = makeClient("os-bulk", {quickBucket("events")});
    ASSERT_NE(client, nullptr);
    auto writer = client->writer("events");

    ASSERT_EQ(submitAndWait(*writer, plainIndex(m_index, "upd", {{"v", 1}})).outcome, ItemOutcome::Created);
    ASSERT_EQ(submitAndWait(*writer, versioned(m_index, "noop", 5, {{"state", {{"document_version", 5}}}})).outcome,
              ItemOutcome::Created);
    const auto bulksBefore = bucketOf(client->metrics()).bulkRequests;

    // One bulk with no item error (errors:false): created, updated and noop.
    auto group = writer->group();
    ASSERT_EQ(group.add(plainIndex(m_index, "new", {{"v", 1}})), Cause::None) << group.lastAddReason();
    ASSERT_EQ(group.add(plainIndex(m_index, "upd", {{"v", 2}})), Cause::None) << group.lastAddReason();
    ASSERT_EQ(group.add(versioned(m_index, "noop", 3, {{"state", {{"document_version", 3}}}})), Cause::None)
        << group.lastAddReason();
    const auto results = group.commit().wait(after(indexer_client::testing::scaled(60s)));
    ASSERT_TRUE(results.ok()) << toString(results.cause);
    ASSERT_EQ(results.value.size(), 3U);
    const ItemOutcome expected[] = {ItemOutcome::Created, ItemOutcome::Updated, ItemOutcome::Noop};
    for (std::size_t i = 0; i < 3; ++i)
    {
        EXPECT_EQ(results.value[i].status, Status::Ok) << i << ": " << results.value[i].reason;
        EXPECT_EQ(results.value[i].cause, Cause::None) << i;
        EXPECT_EQ(results.value[i].outcome, expected[i]) << i;
    }
    EXPECT_EQ(bucketOf(client->metrics()).bulkRequests - bulksBefore, 1U) << "the three items travel in one bulk";
}

TEST_F(OpenSearchBulk, DeleteOutcomes)
{
    auto client = makeClient("os-delete", {quickBucket("events")});
    ASSERT_NE(client, nullptr);
    auto writer = client->writer("events");
    ASSERT_EQ(submitAndWait(*writer, plainIndex(m_index, "present", {{"v", 1}})).outcome, ItemOutcome::Created);

    auto group = writer->group();
    ASSERT_EQ(group.add(deleteOp(m_index, "present")), Cause::None) << group.lastAddReason();
    ASSERT_EQ(group.add(deleteOp(m_index, "absent")), Cause::None) << group.lastAddReason();
    const auto results = group.commit().wait(after(indexer_client::testing::scaled(60s)));
    ASSERT_TRUE(results.ok()) << toString(results.cause);
    ASSERT_EQ(results.value.size(), 2U);
    EXPECT_EQ(results.value[0].status, Status::Ok) << results.value[0].reason;
    EXPECT_EQ(results.value[0].outcome, ItemOutcome::Deleted);
    EXPECT_EQ(results.value[1].status, Status::Ok) << results.value[1].reason;
    EXPECT_EQ(results.value[1].outcome, ItemOutcome::NotFound);
    EXPECT_EQ(results.value[1].httpStatus, 404);
    EXPECT_FALSE(getSource(m_index, "present", nullptr).has_value());
}
