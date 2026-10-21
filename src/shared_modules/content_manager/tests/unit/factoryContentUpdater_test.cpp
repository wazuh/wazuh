/*
 * Wazuh content manager - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
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
    nlohmann::json capturedSort(const content_manager::TopicSpec& spec)
    {
        auto port = std::make_shared<FakeIndexerQueryPort>();
        port->state()->onSearchIndex = [](std::string_view, const nlohmann::json&)
        {
            return nlohmann::json {{"hits",
                                    {{"hits",
                                      nlohmann::json::array({nlohmann::json {{"_id", "consumer:1"},
                                                                             {"_source", {{"status", "ready"}}}}})}}}};
        };
        port->state()->onSearch = [](const auto&, std::size_t ordinal) -> nlohmann::json
        {
            if (ordinal == 0)
            {
                return nlohmann::json {{"hits",
                                        nlohmann::json::array({nlohmann::json {{"_id", "consumer:1"},
                                                                               {"_source", {{"status", "ready"}}}}})}};
            }
            return FakeIndexerQueryPort::emptyHits();
        };

        ConsumerGate::resetCache();

        auto cycle = FactoryContentUpdater::create(spec,
                                                   "topic",
                                                   std::make_shared<RecordingSink>(),
                                                   std::make_shared<MemoryTokenStore>(),
                                                   fakes::NEVER_STOP,
                                                   port);
        cycle->run({});

        // The data fetch is the LAST search, not a fixed index. How many precede it depends on the
        // configuration: with a consumer index there is an in-PIT readiness probe first, and without
        // one there is not — `PitSession::validateConsumerReady` returns Ready without querying
        // anything when validation is disabled. Indexing [1] therefore read past the end of the
        // very case this helper exists to cover.
        EXPECT_FALSE(port->state()->searches.empty());
        return port->state()->searches.empty() ? nlohmann::json {} : port->state()->searches.back().sort;
    }

    content_manager::TopicSpec cursorSpec()
    {
        content_manager::TopicSpec spec;
        spec.source.indices = {"data-index"};
        spec.readiness = content_manager::Readiness {".consumers", "consumer:1"};
        spec.detection = content_manager::CursorDetection {};
        return spec;
    }

} // namespace

TEST(FactoryContentUpdaterTest, InjectsUnmappedTypeOnNonMetafieldSortKeys)
{
    const auto sort = capturedSort(cursorSpec());

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

TEST(FactoryContentUpdaterTest, InjectsUnmappedTypeWithoutAConsumerIndexToo)
{
    // A cold start leaves the cursor field unmapped in the data index itself, so the injection is
    // needed whether or not a consumer index joins the PIT.
    auto spec = cursorSpec();
    spec.readiness.reset();

    const auto sort = capturedSort(spec);

    ASSERT_TRUE(sort.is_array());
    EXPECT_EQ(sort[0], (nlohmann::json {{"offset", {{"order", "asc"}, {"unmapped_type", "long"}}}}));
}

TEST(FactoryContentUpdaterTest, HonoursAConfiguredUnmappedType)
{
    auto spec = cursorSpec();
    spec.detection = content_manager::CursorDetection {"offset", "keyword"};

    const auto sort = capturedSort(spec);
    EXPECT_EQ(sort[0].at("offset").at("unmapped_type"), "keyword");
}

TEST(FactoryContentUpdaterTest, HashDetectionSortsOnDocThenId)
{
    // The sort is implied by the strategy (D2): a hash topic always reloads in full, and
    // `_doc` and `_id` are metafields every index has, so they need no unmapped_type even with a
    // consumer index.
    content_manager::TopicSpec spec;
    spec.source.indices = {"data-index"};
    content_manager::HashDetection hash;
    hash.probe = content_manager::QueryProbe {nlohmann::json {{"term", {{"space.name", "standard"}}}}};
    hash.tokenPointers = {"/space/hash/sha256"};
    spec.detection = hash;

    auto port = std::make_shared<FakeIndexerQueryPort>();
    port->state()->onSearch = [](const auto&, std::size_t ordinal) -> nlohmann::json
    {
        if (ordinal == 0)
        {
            // The probe finds a hash, so the cycle goes on to a full fetch.
            return FakeIndexerQueryPort::hitsOf(nlohmann::json::array(
                {nlohmann::json {{"_id", "policy"}, {"_source", {{"space", {{"hash", {{"sha256", "h1"}}}}}}}}}));
        }
        return FakeIndexerQueryPort::emptyHits();
    };

    ConsumerGate::resetCache();
    auto cycle = FactoryContentUpdater::create(spec,
                                               "topic",
                                               std::make_shared<RecordingSink>(),
                                               std::make_shared<MemoryTokenStore>(),
                                               fakes::NEVER_STOP,
                                               port);
    cycle->run({});

    ASSERT_GE(port->state()->searches.size(), 2U);
    EXPECT_EQ(port->state()->searches.back().sort,
              nlohmann::json::array({nlohmann::json {{"_doc", "asc"}}, nlohmann::json {{"_id", "asc"}}}));
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
    auto cycle = FactoryContentUpdater::create(cursorSpec(),
                                               "topic",
                                               std::make_shared<RecordingSink>(),
                                               std::make_shared<MemoryTokenStore>(),
                                               fakes::NEVER_STOP,
                                               port);
    cycle->run({});

    // Last, not [1], for the same reason capturedSort() uses back(): how many searches precede the
    // data fetch is a property of the configuration, not a constant.
    ASSERT_FALSE(port->state()->searches.empty());
    const auto& query = port->state()->searches.back().query;
    EXPECT_EQ(query.at("bool").at("must").front(), (nlohmann::json {{"match_all", nlohmann::json::object()}}));
    EXPECT_EQ(query.at("bool").at("must_not").front().at("terms").at("_index"), nlohmann::json::array({".consumers"}));
}

TEST(FactoryContentUpdaterTest, ATopicWithoutReadinessSnapshotsTheDataIndicesOnly)
{
    // No readiness block means no gate (D2): the PIT must not pull the consumer index in, and no
    // pre-flight probe may run.
    auto spec = cursorSpec();
    spec.readiness.reset();

    auto port = std::make_shared<FakeIndexerQueryPort>();
    ConsumerGate::resetCache();
    auto cycle = FactoryContentUpdater::create(spec,
                                               "topic",
                                               std::make_shared<RecordingSink>(),
                                               std::make_shared<MemoryTokenStore>(),
                                               fakes::NEVER_STOP,
                                               port);
    cycle->run({});

    ASSERT_FALSE(port->state()->openedIndices.empty());
    EXPECT_EQ(port->state()->openedIndices.front(), (std::vector<std::string> {"data-index"}));
    EXPECT_TRUE(port->state()->indexSearches.empty());
}
