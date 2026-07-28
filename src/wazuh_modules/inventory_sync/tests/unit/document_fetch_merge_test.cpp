/*
 * Wazuh inventory sync - fetch-merge-reindex tests
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

TEST(InventorySyncFetchMergeTest, ParsesStoredDocumentsAndConcurrencyMetadata)
{
    const auto response = nlohmann::json::parse(R"({
        "docs": [{
            "_id": "cluster_001_package",
            "found": true,
            "_seq_no": 7,
            "_primary_term": 3,
            "_source": {
                "package": {"name": "openssl"},
                "user": {"notes": "Reviewed"}
            }
        }]
    })");

    const auto documents = InventorySyncQueryBuilder::parseStoredDocuments(response);

    ASSERT_EQ(documents.size(), 1U);
    const auto& document = documents.at("cluster_001_package");
    EXPECT_EQ(document.sequenceNumber, 7);
    EXPECT_EQ(document.primaryTerm, 3);
    EXPECT_EQ(document.source["user"]["notes"], "Reviewed");
}

TEST(InventorySyncFetchMergeTest, RejectsStoredDocumentWithoutConcurrencyMetadata)
{
    const auto response = nlohmann::json::parse(R"({
        "docs": [{
            "_id": "cluster_001_package",
            "found": true,
            "_source": {"package": {"name": "openssl"}}
        }]
    })");

    EXPECT_THROW(InventorySyncQueryBuilder::parseStoredDocuments(response), nlohmann::json::exception);
}

TEST(InventorySyncFetchMergeTest, IgnoresMissingDocumentsAndMissingIndex)
{
    const auto response = nlohmann::json::parse(R"({
        "docs": [
            {"_id": "missing-document", "found": false},
            {
                "_id": "missing-index-document",
                "error": {
                    "type": "index_not_found_exception",
                    "reason": "no such index [wazuh-states-missing]"
                }
            }
        ]
    })");

    EXPECT_TRUE(InventorySyncQueryBuilder::parseStoredDocuments(response).empty());
}

TEST(InventorySyncFetchMergeTest, RejectsUnexpectedMultiGetErrors)
{
    const auto response = nlohmann::json::parse(R"({
        "docs": [{
            "_id": "unavailable-document",
            "error": {
                "type": "unavailable_shards_exception",
                "reason": "shard unavailable"
            }
        }]
    })");

    EXPECT_THROW(InventorySyncQueryBuilder::parseStoredDocuments(response), std::runtime_error);
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

TEST(InventorySyncFetchMergeTest, DetectsOnlyNewerStoredDocumentVersions)
{
    const nlohmann::json newer {{"state", {{"document_version", 12}}}};
    const nlohmann::json same {{"state", {{"document_version", 11}}}};
    const nlohmann::json missingState {{"package", {{"name", "openssl"}}}};

    EXPECT_TRUE(InventorySyncQueryBuilder::hasNewerDocumentVersion(newer, 11));
    EXPECT_FALSE(InventorySyncQueryBuilder::hasNewerDocumentVersion(same, 11));
    EXPECT_FALSE(InventorySyncQueryBuilder::hasNewerDocumentVersion(missingState, 11));
    EXPECT_FALSE(InventorySyncQueryBuilder::hasNewerDocumentVersion(newer, 0));
}
