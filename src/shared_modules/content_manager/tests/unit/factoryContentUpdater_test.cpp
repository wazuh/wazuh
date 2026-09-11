/*
 * Wazuh content manager - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "components/factoryContentUpdater.hpp"
#include "fakes/fakeIndexerQueryPort.hpp"
#include "gtest/gtest.h"
#include <memory>

using fakes::FakeIndexerQueryPort;
using fakes::MemoryTokenStore;
using fakes::RecordingSink;

namespace
{

/// Drive one cycle and hand back the sort array the fetch actually sent.
nlohmann::json capturedSort(const nlohmann::json& configData)
{
    auto port = std::make_shared<FakeIndexerQueryPort>();
    port->state()->onSearchIndex = [](std::string_view, const nlohmann::json&)
    {
        return nlohmann::json {
            {"hits",
             {{"hits",
               nlohmann::json::array({nlohmann::json {{"_id", "consumer:1"}, {"_source", {{"status", "ready"}}}}})}}}};
    };
    port->state()->onSearch = [](const auto&, std::size_t ordinal) -> nlohmann::json
    {
        if (ordinal == 0)
        {
            return nlohmann::json {
                {"hits",
                 nlohmann::json::array({nlohmann::json {{"_id", "consumer:1"}, {"_source", {{"status", "ready"}}}}})}};
        }
        return FakeIndexerQueryPort::emptyHits();
    };

    ConsumerGate::resetCache();

    auto cycle = FactoryContentUpdater::create(configData,
                                               "topic",
                                               std::make_shared<RecordingSink>(),
                                               std::make_shared<MemoryTokenStore>(),
                                               std::make_shared<ConditionSync>(false),
                                               port);
    cycle->run({});

    // Search 0 is the readiness probe; search 1 is the data fetch.
    EXPECT_GE(port->state()->searches.size(), 2U);
    return port->state()->searches.size() >= 2 ? port->state()->searches[1].sort : nlohmann::json {};
}

nlohmann::json cursorConfig()
{
    return nlohmann::json {{"consumerName", "Test Consumer"},
                           {"changeDetection", "cursor"},
                           {"indexer",
                            {{"index", "data-index"},
                             {"consumerStatusIndex", ".consumers"},
                             {"consumerStatusId", "consumer:1"},
                             {"cursorField", "offset"}}}};
}

} // namespace

TEST(FactoryContentUpdaterTest, InjectsUnmappedTypeOnNonMetafieldSortKeys)
{
    const auto sort = capturedSort(cursorConfig());

    // The whole reason this exists: with the consumer index inside the PIT, sorting on a field that
    // index does not map makes OpenSearch reject the SEARCH, not just skip the document. VD sorts
    // on `offset`; `.wazuh-cti-consumers` has `local_offset`.
    ASSERT_TRUE(sort.is_array());
    ASSERT_FALSE(sort.empty());
    EXPECT_EQ(sort[0].at("offset").at("order"), "asc");
    EXPECT_EQ(sort[0].at("offset").at("unmapped_type"), "long");

    // Metafields are mapped everywhere and are left exactly as configured.
    ASSERT_EQ(sort.size(), 2U);
    EXPECT_EQ(sort[1], (nlohmann::json {{"_id", "asc"}}));
}

TEST(FactoryContentUpdaterTest, LeavesTheSortAloneWithoutAConsumerIndex)
{
    auto config = cursorConfig();
    config["indexer"].erase("consumerStatusIndex");
    config["indexer"].erase("consumerStatusId");

    const auto sort = capturedSort(config);

    ASSERT_TRUE(sort.is_array());
    EXPECT_EQ(sort[0], (nlohmann::json {{"offset", "asc"}}));
}

TEST(FactoryContentUpdaterTest, HonoursAConfiguredUnmappedType)
{
    auto config = cursorConfig();
    config["indexer"]["sortUnmappedType"] = "keyword";

    const auto sort = capturedSort(config);
    EXPECT_EQ(sort[0].at("offset").at("unmapped_type"), "keyword");
}

TEST(FactoryContentUpdaterTest, EngineStyleMetafieldSortIsUnaffected)
{
    auto config = cursorConfig();
    config["indexer"]["sortKeys"] = nlohmann::json::array({nlohmann::json {{"_shard_doc", "asc"}}});

    const auto sort = capturedSort(config);
    EXPECT_EQ(sort, nlohmann::json::array({nlohmann::json {{"_shard_doc", "asc"}}}));
}

TEST(FactoryContentUpdaterTest, ScopesTheDataQueryAwayFromTheConsumerIndex)
{
    auto port = std::make_shared<FakeIndexerQueryPort>();
    port->state()->onSearchIndex = [](std::string_view, const nlohmann::json&)
    {
        return nlohmann::json {
            {"hits",
             {{"hits",
               nlohmann::json::array({nlohmann::json {{"_id", "consumer:1"}, {"_source", {{"status", "ready"}}}}})}}}};
    };
    port->state()->onSearch = [](const auto&, std::size_t ordinal) -> nlohmann::json
    {
        if (ordinal == 0)
        {
            return nlohmann::json {
                {"hits",
                 nlohmann::json::array({nlohmann::json {{"_id", "consumer:1"}, {"_source", {{"status", "ready"}}}}})}};
        }
        return FakeIndexerQueryPort::emptyHits();
    };

    ConsumerGate::resetCache();
    auto cycle = FactoryContentUpdater::create(cursorConfig(),
                                               "topic",
                                               std::make_shared<RecordingSink>(),
                                               std::make_shared<MemoryTokenStore>(),
                                               std::make_shared<ConditionSync>(false),
                                               port);
    cycle->run({});

    ASSERT_GE(port->state()->searches.size(), 2U);
    const auto& query = port->state()->searches[1].query;
    EXPECT_EQ(query.at("bool").at("must").front(), (nlohmann::json {{"match_all", nlohmann::json::object()}}));
    EXPECT_EQ(query.at("bool").at("must_not").front().at("terms").at("_index"),
              nlohmann::json::array({".consumers"}));
}

TEST(FactoryContentUpdaterTest, RejectsAnInvalidConfiguration)
{
    nlohmann::json config {{"consumerName", "Test"}, {"changeDetection", "hash"}, {"indexer", {{"index", "x"}}}};

    EXPECT_THROW(ExecutionContext::validate(config), std::invalid_argument);
}
