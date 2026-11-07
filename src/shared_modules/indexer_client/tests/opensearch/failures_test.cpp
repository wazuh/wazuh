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

// D108 (plan 18, E11d): the failures of the old connector's qa (test_efficacy_log.py) against a real OpenSearch, end to
// end through the public API: a document the strict mapping rejects, the shard limit and a missing index with
// auto-creation disabled; then (issues 26 and 27) a bulk over the node's http.max_content_length, split until
// everything lands, and a node that is stopped and started again. Each case that changes a cluster setting does it
// through ClusterSettingGuard, which puts the setting back (to the value it had, or its default) when the guard dies,
// so the fixture's TearDown restores the cluster even when an ASSERT aborts the body.

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "openSearchSupport.hpp"

using namespace indexer_client;
using namespace indexer_client::opensearch;
using namespace std::chrono_literals;

namespace
{
    /// The persistent value of one cluster setting as the cluster reports it (flat settings, so always a string), or
    /// nullopt when the setting is not set persistently (the cluster runs on its default).
    std::optional<std::string> persistentSetting(const std::string& key)
    {
        const auto response = raw("GET", "/_cluster/settings?flat_settings=true&include_defaults=true");
        EXPECT_EQ(response.status, 200) << "GET _cluster/settings: " << response.body;
        const auto parsed = nlohmann::json::parse(response.body, nullptr, false);
        if (!parsed.is_object() || !parsed.contains("persistent") || !parsed["persistent"].contains(key))
        {
            return std::nullopt;
        }
        return parsed["persistent"][key].get<std::string>();
    }

    /// Sets one persistent cluster setting and, on destruction, puts back the value it had before (the persistent one
    /// read at construction), or resets it to null (the default) when there was none.
    class ClusterSettingGuard final
    {
    public:
        ClusterSettingGuard(std::string key, const nlohmann::json& value)
            : m_key(std::move(key))
            , m_previous(persistentSetting(m_key))
        {
            const auto response =
                raw("PUT", "/_cluster/settings", nlohmann::json {{"persistent", {{m_key, value}}}}.dump());
            m_applied = response.status == 200;
            EXPECT_TRUE(m_applied) << "PUT _cluster/settings " << m_key << ": " << response.status << " "
                                   << response.body;
        }

        ~ClusterSettingGuard()
        {
            // Restore even when the apply reported a failure: writing the previous value back is harmless.
            const nlohmann::json previous = m_previous ? nlohmann::json(*m_previous) : nlohmann::json(nullptr);
            const auto response =
                raw("PUT", "/_cluster/settings", nlohmann::json {{"persistent", {{m_key, previous}}}}.dump());
            EXPECT_EQ(response.status, 200) << "restoring " << m_key << ": " << response.body;
            EXPECT_EQ(persistentSetting(m_key), m_previous) << "the cluster setting " << m_key << " was not restored";
        }

        ClusterSettingGuard(const ClusterSettingGuard&) = delete;
        ClusterSettingGuard& operator=(const ClusterSettingGuard&) = delete;

        bool applied() const
        {
            return m_applied;
        }

    private:
        std::string m_key;
        std::optional<std::string> m_previous;
        bool m_applied {false};
    };

    Op indexOp(const std::string& index, const std::string& id, const nlohmann::json& doc)
    {
        Op op;
        op.kind = Op::Kind::Index;
        op.index = index;
        op.id = id;
        op.body = doc.dump();
        return op;
    }

    bool indexExists(const std::string& index)
    {
        return raw("GET", "/" + index).status == 200;
    }
} // namespace

class OpenSearchFailures : public OpenSearchTest
{
protected:
    void TearDown() override
    {
        // First the cluster settings (the guards), then the library and the index.
        m_guards.clear();
        OpenSearchTest::TearDown();
    }

    void setting(const std::string& key, const nlohmann::json& value)
    {
        m_guards.push_back(std::make_unique<ClusterSettingGuard>(key, value));
    }

    std::vector<std::unique_ptr<ClusterSettingGuard>> m_guards;
};

TEST_F(OpenSearchFailures, StrictMappingRejectsThenAccepts)
{
    const auto created = raw(
        "PUT",
        "/" + m_index,
        R"({"settings":{"number_of_shards":1,"number_of_replicas":0},"mappings":{"dynamic":"strict","properties":{"known":{"type":"keyword"}}}})");
    ASSERT_EQ(created.status, 200) << created.body;

    auto client = makeClient("os-strict", {quickBucket("events")});
    ASSERT_NE(client, nullptr);
    auto writer = client->writer("events");

    // A field the mapping does not know: the item is refused for good (loudly, with its type and reason).
    const auto rejected = submitAndWait(*writer, indexOp(m_index, "a", {{"known", "x"}, {"unknown", "y"}}));
    EXPECT_EQ(rejected.status, Status::Failed);
    EXPECT_EQ(rejected.cause, Cause::ItemPermanent) << rejected.itemErrorType << ": " << rejected.reason;
    EXPECT_EQ(rejected.httpStatus, 400);
    EXPECT_TRUE(rejected.itemErrorType == "strict_dynamic_mapping_exception" ||
                rejected.itemErrorType == "mapper_parsing_exception")
        << rejected.itemErrorType;
    EXPECT_NE(rejected.reason.find("unknown"), std::string::npos) << rejected.reason;
    EXPECT_FALSE(getSource(m_index, "a", nullptr).has_value()) << "a rejected document must not be indexed";

    // The queue is not blocked by it: a document that fits the mapping still lands.
    const auto fine = submitAndWait(*writer, indexOp(m_index, "b", {{"known", "x"}}));
    EXPECT_EQ(fine.status, Status::Ok) << fine.reason;
    EXPECT_EQ(fine.outcome, ItemOutcome::Created);

    // Once the mapping allows the field, the same document goes in.
    const auto widened = raw("PUT", "/" + m_index + "/_mapping", R"({"properties":{"unknown":{"type":"keyword"}}})");
    ASSERT_EQ(widened.status, 200) << widened.body;
    const auto accepted = submitAndWait(*writer, indexOp(m_index, "a", {{"known", "x"}, {"unknown", "y"}}));
    EXPECT_EQ(accepted.status, Status::Ok) << accepted.reason;
    EXPECT_EQ(accepted.outcome, ItemOutcome::Created);
    EXPECT_TRUE(getSource(m_index, "a", nullptr).has_value());
}

TEST_F(OpenSearchFailures, ShardLimitIsReported)
{
    // The single node already holds more than one shard (system indices, other suites' leftovers), so a limit of one
    // refuses the creation of any index the bulk would auto-create (OpenSearch 3.x words it "maximum LOCAL_ONLY shards
    // open").
    setting("cluster.max_shards_per_node", 1);

    auto client = makeClient("os-shards", {quickBucket("events")});
    ASSERT_NE(client, nullptr);
    auto writer = client->writer("events");

    const auto result = submitAndWait(*writer, indexOp(m_index, "a", {{"v", 1}}));
    EXPECT_EQ(result.status, Status::Failed);
    EXPECT_EQ(result.cause, Cause::ItemPermanent) << result.itemErrorType << ": " << result.reason;
    EXPECT_EQ(result.httpStatus, 400);
    EXPECT_NE(result.reason.find("shards open"), std::string::npos) << result.reason;
    EXPECT_FALSE(indexExists(m_index)) << "the refused creation must leave no index";
}

TEST_F(OpenSearchFailures, MissingIndexWithoutAutoCreateIsReported)
{
    setting("action.auto_create_index", false);

    auto client = makeClient("os-noauto", {quickBucket("events")});
    ASSERT_NE(client, nullptr);
    auto writer = client->writer("events");

    const auto result = submitAndWait(*writer, indexOp(m_index, "a", {{"v", 1}}));
    EXPECT_EQ(result.status, Status::Failed);
    EXPECT_EQ(result.cause, Cause::ItemPermanent) << result.itemErrorType << ": " << result.reason;
    EXPECT_EQ(result.httpStatus, 404);
    EXPECT_EQ(result.itemErrorType, "index_not_found_exception") << result.reason;
    EXPECT_FALSE(indexExists(m_index)) << "the index must still not exist";
}

class OpenSearchSettingGuard : public OpenSearchTest
{
};

TEST_F(OpenSearchSettingGuard, RestoresThePreviousValueOrTheDefault)
{
    // A benign setting: raising it never refuses anything. It is the cluster's own value that must come back.
    const std::string key = "cluster.max_shards_per_node";
    const auto before = persistentSetting(key);
    ASSERT_FALSE(before.has_value()) << "the cluster already has a persistent " << key << ": " << *before;

    {
        // No previous value: the guard puts the setting back to its default (absent).
        ClusterSettingGuard guard(key, 2000);
        ASSERT_TRUE(guard.applied());
        EXPECT_EQ(persistentSetting(key), std::optional<std::string>("2000"));
    }
    EXPECT_FALSE(persistentSetting(key).has_value());

    // A previous persistent value: the guard puts back that value, not the default.
    ASSERT_EQ(raw("PUT", "/_cluster/settings", nlohmann::json {{"persistent", {{key, 1500}}}}.dump()).status, 200);
    {
        ClusterSettingGuard guard(key, 2000);
        ASSERT_TRUE(guard.applied());
        EXPECT_EQ(persistentSetting(key), std::optional<std::string>("2000"));
    }
    EXPECT_EQ(persistentSetting(key), std::optional<std::string>("1500"));

    // Leave the cluster as the test found it.
    EXPECT_EQ(raw("PUT", "/_cluster/settings", nlohmann::json {{"persistent", {{key, nullptr}}}}.dump()).status, 200);
    EXPECT_FALSE(persistentSetting(key).has_value());
}

namespace
{
    /// `http.max_content_length` of the node at `url` in bytes, as it was set at its start (a static node setting); 0
    /// when the node does not set it or does not answer. OpenSearch's byte units are binary (kb = 1024).
    std::uint64_t maxContentLength(const std::string& url)
    {
        const auto response =
            rawAt(url, "GET", "/_nodes/settings?flat_settings=true&filter_path=nodes.*.settings.http*");
        const auto parsed = nlohmann::json::parse(response.body, nullptr, false);
        if (response.status != 200 || !parsed.is_object() || !parsed.contains("nodes"))
        {
            return 0;
        }
        for (const auto& [id, node] : parsed["nodes"].items())
        {
            // A dotted filter_path would look for nested keys: the flat key is read here.
            const auto& settings = node.at("settings");
            if (!settings.contains("http.max_content_length"))
            {
                return 0;
            }
            const auto value = settings["http.max_content_length"].get<std::string>();
            std::size_t digits = 0;
            while (digits < value.size() && std::isdigit(static_cast<unsigned char>(value[digits])) != 0)
            {
                ++digits;
            }
            if (digits == 0)
            {
                return 0;
            }
            const std::uint64_t number = std::stoull(value.substr(0, digits));
            const auto unit = value.substr(digits);
            if (unit.empty() || unit == "b")
            {
                return number;
            }
            if (unit == "kb")
            {
                return number << 10;
            }
            if (unit == "mb")
            {
                return number << 20;
            }
            return 0; // Larger units: not a limit this case can work with.
        }
        return 0;
    }

    /// A document of `bytes` bytes of padding (plus its key).
    nlohmann::json padded(std::size_t bytes)
    {
        return {{"pad", std::string(bytes, 'x')}};
    }
} // namespace

// Issue 26: a node started with a low `http.max_content_length` (SMALL_URL_ENV) answers 413 to a bulk over it before
// reading its body. The client splits the batch in halves until each fits, so every operation of a group three times
// the limit ends Ok, the index holds every document once, and more than one bulk went out; a single document over the
// limit is never split: Failed(PayloadTooLarge), with the node's 413, and not indexed.
class OpenSearchPayloadLimit : public OpenSearchTest
{
protected:
    const char* urlVariable() const override
    {
        return SMALL_URL_ENV;
    }
};

TEST_F(OpenSearchPayloadLimit, BulkOverTheLimitIsSplitUntilEverythingLands)
{
    const auto limit = maxContentLength(m_url);
    ASSERT_GT(limit, 0U) << SMALL_URL_ENV << " must name a node started with http.max_content_length";
    ASSERT_LE(limit, 1024U * 1024U) << "the case sizes its documents for a limit of a few KiB (the CI uses 16kb)";

    // Every document far under the limit, the group three times over it, and one batch for the whole group: it leaves
    // when its last operation is queued (maxDocs), long before its age (maxAge).
    const std::size_t count = 48;
    const std::size_t docBytes = limit / 16;
    auto spec = quickBucket("events");
    spec.bulk.maxDocs = count;
    spec.bulk.maxAge = Duration {60000};
    // The single oversized document goes through a bucket of its own, with the suite's short maxAge.
    auto client = makeClient("os-413", {spec, quickBucket("alone")});
    ASSERT_NE(client, nullptr);
    auto writer = client->writer("events");

    std::vector<Ticket> tickets;
    for (std::size_t k = 0; k < count; ++k)
    {
        Op op;
        op.kind = Op::Kind::Index;
        op.index = m_index;
        op.id = "doc-" + std::to_string(k);
        op.body = padded(docBytes).dump();
        auto submit = writer->submit(std::move(op));
        ASSERT_TRUE(submit.accepted) << toString(submit.cause) << ": " << submit.reason;
        tickets.push_back(submit.ticket);
    }
    for (std::size_t k = 0; k < count; ++k)
    {
        const auto result = tickets[k].wait(after(indexer_client::testing::scaled(60s)));
        ASSERT_TRUE(result.ok()) << "doc-" << k << ": " << toString(result.cause) << ": " << result.reason;
        EXPECT_EQ(result.value.status, Status::Ok)
            << "doc-" << k << ": " << toString(result.value.cause) << ": " << result.value.reason;
    }
    EXPECT_EQ(countDocuments(m_url, m_index), static_cast<std::int64_t>(count));
    std::uint64_t bulks = 0;
    for (const auto& bucket : client->metrics().buckets)
    {
        bulks += bucket.bucket == "events" ? bucket.bulkRequests : 0;
    }
    // The refused bulk and at least the two halves that replaced it (the group is three times the limit: more).
    EXPECT_GE(bulks, 3U) << "the group went out in " << bulks << " bulk(s)";
    std::cout << MEASURE << "case=413-split limit=" << limit << " docs=" << count << " doc_bytes=" << docBytes
              << " bulk_requests=" << bulks << "\n";

    Op alone;
    alone.kind = Op::Kind::Index;
    alone.index = m_index;
    alone.id = "too-large";
    alone.body = padded(limit + 1024).dump();
    const auto result = submitAndWait(*client->writer("alone"), std::move(alone));
    EXPECT_EQ(result.status, Status::Failed);
    EXPECT_EQ(result.cause, Cause::PayloadTooLarge) << result.reason;
    EXPECT_EQ(result.httpStatus, 413);
    EXPECT_EQ(countDocuments(m_url, m_index), static_cast<std::int64_t>(count)) << "the oversized one is not indexed";
}

namespace
{
    /// `docker stop` / `docker start` of the URL_ENV node (issue 27). Only a container name or id ([A-Za-z0-9_.-])
    /// and never the e2e `wazuh-indexer`. Whatever the case does, the destructor leaves the node started and waits
    /// until it answers.
    class NodeControl final
    {
    public:
        NodeControl(std::string container, std::string url)
            : m_container(std::move(container))
            , m_url(std::move(url))
        {
        }

        ~NodeControl()
        {
            if (m_stopped)
            {
                EXPECT_TRUE(start()) << "the node could not be started again";
            }
        }

        NodeControl(const NodeControl&) = delete;
        NodeControl& operator=(const NodeControl&) = delete;

        bool valid() const
        {
            if (m_container.empty() || m_container == "wazuh-indexer")
            {
                return false;
            }
            for (const char c : m_container)
            {
                if (std::isalnum(static_cast<unsigned char>(c)) == 0 && c != '_' && c != '.' && c != '-')
                {
                    return false;
                }
            }
            return true;
        }

        /// Stops the container gracefully (its data stays in it).
        bool stop()
        {
            m_stopped = true; // Even a failed stop is undone by the destructor.
            return docker("stop -t 30");
        }

        /// Starts the container and waits for the node to answer /_cluster/health.
        bool start()
        {
            if (!docker("start"))
            {
                return false;
            }
            m_stopped = false;
            const auto last = waitForCluster(m_url, indexer_client::testing::scaled(180s));
            EXPECT_TRUE(last.empty()) << "the node did not answer after its start: " << last;
            return last.empty();
        }

    private:
        bool docker(const std::string& verb) const
        {
            const auto command = "docker " + verb + " " + m_container + " >/dev/null";
            const int rc = std::system(command.c_str());
            EXPECT_EQ(rc, 0) << command;
            return rc == 0;
        }

        std::string m_container;
        std::string m_url;
        bool m_stopped {false};
    };

    Op roundOp(const std::string& index, const std::string& id, int round)
    {
        Op op;
        op.kind = Op::Kind::Index;
        op.index = index;
        op.id = id;
        op.body = nlohmann::json {{"id", id}, {"round", round}}.dump();
        return op;
    }
} // namespace

// Issue 27: the node of the suite (CONTAINER_ENV) is stopped and started again. While it is down, a submit returns at
// once and nothing reports success; operations of a client closed during the outage end Dropped(ClientClosed) without
// waiting for the node; the ones still queued land once it is back. What was indexed before the outage is still there,
// and resending every id leaves one document per id. The node is started again whatever happens (NodeControl, before
// the fixture's TearDown).
class OpenSearchOutage : public OpenSearchTest
{
protected:
    void SetUp() override
    {
        requireVariable(CONTAINER_ENV);
        if (HasFatalFailure() || IsSkipped())
        {
            return;
        }
        m_node = std::make_unique<NodeControl>(variable(CONTAINER_ENV), clusterUrl());
        ASSERT_TRUE(m_node->valid()) << CONTAINER_ENV << " is not a container this suite may stop";
        OpenSearchTest::SetUp();
    }

    void TearDown() override
    {
        m_node.reset(); // Started again (and answering) before the library closes and the index is deleted.
        OpenSearchTest::TearDown();
    }

    std::unique_ptr<NodeControl> m_node;
};

TEST_F(OpenSearchOutage, StoppedNodeLosesNothingAndDuplicatesNothing)
{
    constexpr int COUNT = 20;
    auto client = makeClient("os-outage", {quickBucket("events")});
    ASSERT_NE(client, nullptr);
    auto writer = client->writer("events");
    auto id = [](const char* prefix, int k)
    {
        return std::string(prefix) + std::to_string(k);
    };

    for (int k = 0; k < COUNT; ++k)
    {
        const auto result = submitAndWait(*writer, roundOp(m_index, id("pre-", k), 0));
        ASSERT_EQ(result.status, Status::Ok) << toString(result.cause) << ": " << result.reason;
    }
    ASSERT_EQ(countDocuments(m_url, m_index), COUNT);

    // The node stops, and the client sees it Down (its probe).
    ASSERT_TRUE(m_node->stop());
    const auto downBy = after(indexer_client::testing::scaled(30s));
    while (client->health().anyUsable() && std::chrono::steady_clock::now() < downBy)
    {
        std::this_thread::sleep_for(50ms);
    }
    ASSERT_FALSE(client->health().anyUsable()) << "the client never saw the stopped node Down";

    // During the outage a submit returns at once, accepted.
    std::vector<Ticket> queued;
    for (int k = 0; k < COUNT; ++k)
    {
        const auto started = std::chrono::steady_clock::now();
        auto submit = writer->submit(roundOp(m_index, id("out-", k), 1));
        EXPECT_LT(std::chrono::steady_clock::now() - started, 1s) << "a submit must not wait for the node";
        ASSERT_TRUE(submit.accepted) << toString(submit.cause) << ": " << submit.reason;
        queued.push_back(submit.ticket);
    }

    // A client closed during the outage: every operation ends Dropped(ClientClosed) by its close deadline, without the
    // node.
    {
        auto created = m_ref.client("os-outage-closed", {quickBucket("events")});
        ASSERT_TRUE(created.ok()) << created.reason;
        auto other = created.value->writer("events");
        std::vector<Ticket> closed;
        for (int k = 0; k < COUNT; ++k)
        {
            auto submit = other->submit(roundOp(m_index, id("gone-", k), 1));
            ASSERT_TRUE(submit.accepted) << toString(submit.cause) << ": " << submit.reason;
            closed.push_back(submit.ticket);
        }
        const auto started = std::chrono::steady_clock::now();
        created.value->requestClose();
        const auto report = created.value->awaitClosed(after(indexer_client::testing::scaled(2s)));
        EXPECT_TRUE(report.ok()) << toString(report.cause) << ": " << report.reason;
        for (const auto& ticket : closed)
        {
            const auto result = ticket.wait(after(indexer_client::testing::scaled(5s)));
            ASSERT_TRUE(result.ok()) << toString(result.cause) << ": " << result.reason;
            EXPECT_EQ(result.value.status, Status::Dropped);
            EXPECT_EQ(result.value.cause, Cause::ClientClosed) << result.value.reason;
        }
        EXPECT_LT(std::chrono::steady_clock::now() - started, indexer_client::testing::scaled(10s));
    }

    // Still down: nothing of the open client reported anything, success included.
    std::this_thread::sleep_for(indexer_client::testing::scaled(1s));
    for (const auto& ticket : queued)
    {
        EXPECT_FALSE(ticket.ready()) << "an operation resolved while its only node was down";
    }

    // The node is back: what was queued lands, and what was there before the outage still is.
    ASSERT_TRUE(m_node->start());
    for (int k = 0; k < COUNT; ++k)
    {
        const auto result = queued[k].wait(after(indexer_client::testing::scaled(120s)));
        ASSERT_TRUE(result.ok()) << id("out-", k) << ": " << toString(result.cause) << ": " << result.reason;
        EXPECT_EQ(result.value.status, Status::Ok)
            << id("out-", k) << ": " << toString(result.value.cause) << ": " << result.value.reason;
    }
    for (int k = 0; k < COUNT; ++k)
    {
        const auto source = getSource(m_index, id("pre-", k), nullptr);
        ASSERT_TRUE(source.has_value()) << id("pre-", k) << " was lost in the outage";
        EXPECT_EQ(source->at("round"), 0);
        EXPECT_FALSE(getSource(m_index, id("gone-", k), nullptr).has_value()) << "a dropped operation was indexed";
    }

    // Every id again: one document per id, nothing duplicated.
    for (const char* prefix : {"pre-", "out-"})
    {
        for (int k = 0; k < COUNT; ++k)
        {
            const auto result = submitAndWait(*writer, roundOp(m_index, id(prefix, k), 2));
            EXPECT_EQ(result.status, Status::Ok) << toString(result.cause) << ": " << result.reason;
            EXPECT_EQ(result.outcome, ItemOutcome::Updated) << id(prefix, k);
        }
    }
    EXPECT_EQ(countDocuments(m_url, m_index), 2 * COUNT);
}
