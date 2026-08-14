/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 4, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "indexer/IIndexerConnectorSync.hpp"
#include "testIndexerConnectorFakes.hpp"

#include <json.hpp>

#include <gtest/gtest.h>

#include <memory>
#include <tuple>

/*
 * Pins the expanded IIndexerConnectorSync seam: every method the sync pipeline will use (F2) is
 * callable through the interface and observable on the fake's shared event record. The production
 * adapter is a 1:1 forward covered by compilation plus the facade gating tests, which construct it
 * against a real IndexerSession; what needs pinning here is the seam's shape and the fake's
 * bookkeeping, because the pipeline tests will be built on top of both.
 */

using invsync::indexer::IIndexerConnectorSync;
using invsync::test::ConnectorEvents;
using invsync::test::FakeIndexerConnectorSync;

TEST(IndexerSyncSeamTest, EverySeamMethodIsObservableThroughTheInterface)
{
    auto events = std::make_shared<ConnectorEvents>();
    events->m_searchResponse = nlohmann::json {{"hits", {{"total", {{"value", 1}}}}}};
    FakeIndexerConnectorSync fake {events, "sync"};
    IIndexerConnectorSync& seam = fake;

    seam.bulkIndex("id-1", "idx-a", R"({"k":1})");
    seam.bulkIndex("id-2", "idx-a", "{}", "7");
    seam.bulkDelete("id-3", "idx-b");
    seam.deleteByQuery("idx-b", "001", "cluster01");
    seam.executeUpdateByQuery({"idx-a", "idx-b"}, nlohmann::json {{"query", "q"}});
    const auto response = seam.executeSearchQuery("idx-a", nlohmann::json {{"size", 0}});
    seam.flush();

    EXPECT_EQ(events->searchResponse(), response);
    EXPECT_EQ(1, events->m_syncFlushes.load());

    const auto ops = events->syncOps();
    ASSERT_EQ(6U, ops.size());
    EXPECT_EQ(std::make_tuple(std::string {"bulkIndex"},
                              std::string {"id-1"},
                              std::string {"idx-a"},
                              std::string {R"({"k":1})"},
                              std::string {}),
              ops[0]);
    // The versioned overload lands with its version in the last column.
    EXPECT_EQ(std::make_tuple(std::string {"bulkIndex"},
                              std::string {"id-2"},
                              std::string {"idx-a"},
                              std::string {"{}"},
                              std::string {"7"}),
              ops[1]);
    EXPECT_EQ("bulkDelete", std::get<0>(ops[2]));
    EXPECT_EQ("id-3", std::get<1>(ops[2]));
    EXPECT_EQ("idx-b", std::get<2>(ops[2]));
    EXPECT_EQ(std::make_tuple(std::string {"deleteByQuery"},
                              std::string {"001"},
                              std::string {"idx-b"},
                              std::string {"cluster01"},
                              std::string {}),
              ops[3]);
    EXPECT_EQ("executeUpdateByQuery", std::get<0>(ops[4]));
    EXPECT_EQ("idx-a,idx-b", std::get<2>(ops[4]));
    EXPECT_EQ("executeSearchQuery", std::get<0>(ops[5]));
    EXPECT_EQ("idx-a", std::get<2>(ops[5]));
}

TEST(IndexerSyncSeamTest, AvailabilityFollowsTheSharedFlag)
{
    auto events = std::make_shared<ConnectorEvents>();
    FakeIndexerConnectorSync fake {events, "sync"};
    const IIndexerConnectorSync& seam = fake;

    EXPECT_TRUE(seam.isAvailable());
    events->m_syncAvailable.store(false);
    EXPECT_FALSE(seam.isAvailable());
}

TEST(IndexerSyncSeamTest, DestructionIsRecordedForTeardownOrdering)
{
    auto events = std::make_shared<ConnectorEvents>();
    {
        FakeIndexerConnectorSync fake {events, "sync"};
    }
    EXPECT_EQ(std::vector<std::string> {"sync"}, events->destroyed());
}
