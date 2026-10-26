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
// auto-creation disabled. Each case that changes a cluster setting does it through ClusterSettingGuard, which puts the
// setting back (to the value it had, or its default) when the guard dies, so the fixture's TearDown restores the
// cluster even when an ASSERT aborts the body.

#include <memory>
#include <optional>
#include <string>
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
