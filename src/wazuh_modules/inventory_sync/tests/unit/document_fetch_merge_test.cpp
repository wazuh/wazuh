/*
 * Wazuh inventory sync - fetch-merge-reindex POC tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 23, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "inventorySyncQueryBuilder.hpp"
#include <gtest/gtest.h>

TEST(InventorySyncFetchMergeTest, BuildsDocumentIdQuery)
{
    const auto query = InventorySyncQueryBuilder::buildDocumentByIdQuery("cluster_001_package");

    EXPECT_EQ(query["size"], 1);
    ASSERT_TRUE(query["query"]["ids"]["values"].is_array());
    ASSERT_EQ(query["query"]["ids"]["values"].size(), 1U);
    EXPECT_EQ(query["query"]["ids"]["values"][0], "cluster_001_package");
}

TEST(InventorySyncFetchMergeTest, PreservesStoredTopLevelFieldsMissingFromIncomingDocument)
{
    nlohmann::json incoming {{"package", {{"name", "openssl"}, {"version", "3.0.2"}}},
                             {"state", {{"document_version", 11}}}};
    const nlohmann::json stored {{"package", {{"name", "openssl"}, {"version", "3.0.1"}, {"description", "old"}}},
                                 {"state", {{"document_version", 10}}},
                                 {"user", {{"classification", "false_positive"}, {"notes", "Reviewed"}}}};

    InventorySyncQueryBuilder::preserveUnknownTopLevelFields(incoming, stored);

    EXPECT_EQ(incoming["package"]["version"], "3.0.2");
    EXPECT_FALSE(incoming["package"].contains("description"));
    EXPECT_EQ(incoming["state"]["document_version"], 11);
    EXPECT_EQ(incoming["user"], stored["user"]);
}

TEST(InventorySyncFetchMergeTest, LeavesIncomingDocumentUnchangedWhenStoredSourceIsNotAnObject)
{
    nlohmann::json incoming {{"field", "new"}};
    const auto expected = incoming;

    InventorySyncQueryBuilder::preserveUnknownTopLevelFields(incoming, nlohmann::json::array({"old"}));

    EXPECT_EQ(incoming, expected);
}
