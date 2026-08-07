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

#include "sync/sessionProcessor.hpp"

#include "sync/fullSessionValidator.hpp"
#include "testIndexerConnectorFakes.hpp"
#include "testSessionBuilder.hpp"

#include "hashHelper.h"
#include "stringHelper.h"

#include <json.hpp>

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <variant>

using invsync::sync::ProcessOutcome;
using invsync::sync::SessionProcessor;
using invsync::sync::ValidatedSession;
using invsync::test::ConnectorEvents;
using invsync::test::FakeIndexerConnectorSync;
using invsync::test::SessionSpec;
using invsync::test::ValueSpec;

namespace
{
    constexpr auto CLUSTER {"test-cluster"};

    /// Owns the wire bytes the ValidatedSession points into, so both travel together.
    struct Prepared
    {
        std::string body;
        ValidatedSession session;
    };

    Prepared prepare(std::string body)
    {
        Prepared prepared {std::move(body), {}};
        auto result = invsync::sync::validateFullSession(prepared.body, "1", CLUSTER);
        auto* session = std::get_if<ValidatedSession>(&result);
        if (session == nullptr)
        {
            throw std::runtime_error {"test session failed validation: " +
                                      std::get<invsync::sync::ValidationFailure>(result).reason};
        }
        prepared.session = std::move(*session);
        return prepared;
    }

    std::string expectedSha1Hex(const std::string& concatenated)
    {
        Utils::HashData hash(Utils::HashType::Sha1);
        hash.update(concatenated.c_str(), concatenated.length());
        return Utils::asciiToHex(hash.hash());
    }

    nlohmann::json searchPage(const std::vector<std::string>& checksums)
    {
        nlohmann::json hits = nlohmann::json::array();
        for (const auto& checksum : checksums)
        {
            nlohmann::json hit;
            hit["_source"]["checksum"]["hash"]["sha1"] = checksum;
            hit["sort"] = nlohmann::json::array({checksum});
            hits.push_back(hit);
        }
        nlohmann::json page;
        page["hits"]["hits"] = hits;
        return page;
    }
} // namespace

class SessionProcessorTest : public ::testing::Test
{
protected:
    std::shared_ptr<ConnectorEvents> events {std::make_shared<ConnectorEvents>()};
    FakeIndexerConnectorSync connector {events, "sync"};
    SessionProcessor processor {CLUSTER};
};

TEST_F(SessionProcessorTest, StagesUpsertsAndDeletesWithTheHistoricalIdAndOverlay)
{
    ValueSpec versioned;
    versioned.id = "doc-1";
    versioned.version = 7;
    // The agent tries to impersonate: the overlay must clobber every wazuh.* field it sent.
    versioned.data = R"({"package":{"name":"vim"},"wazuh":{"agent":{"id":"999"},"cluster":{"name":"evil"}}})";

    ValueSpec unversioned;
    unversioned.id = "doc-2";
    unversioned.version = 0;

    ValueSpec deletion;
    deletion.operation = invsync::test::fb::Operation_Delete;
    deletion.id = "doc-3";

    const auto prepared =
        prepare(invsync::test::buildSyncDataSession(SessionSpec {}, {versioned, unversioned, deletion}));
    const auto outcome = processor.stageBulk(prepared.session, connector);

    EXPECT_EQ(200, outcome.status);
    EXPECT_TRUE(outcome.staged);

    const auto ops = events->syncOps();
    ASSERT_EQ(3U, ops.size());

    // Versioned upsert: 4-arg bulkIndex with the version in the last column.
    EXPECT_EQ("bulkIndex", std::get<0>(ops[0]));
    EXPECT_EQ("test-cluster_001_doc-1", std::get<1>(ops[0]));
    EXPECT_EQ("wazuh-states-inventory-packages", std::get<2>(ops[0]));
    EXPECT_EQ("7", std::get<4>(ops[0]));
    {
        const auto document = nlohmann::json::parse(std::get<3>(ops[0]));
        EXPECT_EQ("001", document["wazuh"]["agent"]["id"]) << "the overlay must defeat impersonation";
        EXPECT_EQ(CLUSTER, document["wazuh"]["cluster"]["name"]);
        EXPECT_EQ("agent-one", document["wazuh"]["agent"]["name"]);
        EXPECT_EQ("host-one", document["wazuh"]["agent"]["host"]["hostname"]);
        EXPECT_EQ("vim", document["package"]["name"]) << "the agent's own payload must survive";
    }

    // Unversioned upsert: 3-arg form (empty version column).
    EXPECT_EQ("bulkIndex", std::get<0>(ops[1]));
    EXPECT_EQ("test-cluster_001_doc-2", std::get<1>(ops[1]));
    EXPECT_EQ("", std::get<4>(ops[1]));

    EXPECT_EQ("bulkDelete", std::get<0>(ops[2]));
    EXPECT_EQ("test-cluster_001_doc-3", std::get<1>(ops[2]));

    EXPECT_EQ(0, events->m_syncFlushes.load()) << "staging must not flush; the batch owns the flush";
}

TEST_F(SessionProcessorTest, PerDocumentProblemsAreSkippedNotFailed)
{
    ValueSpec outsideAllowlist;
    outsideAllowlist.index = "alerts";
    ValueSpec vulnerabilitiesWrite;
    vulnerabilitiesWrite.index = "wazuh-states-vulnerabilities";
    ValueSpec emptyId;
    emptyId.id = "";
    ValueSpec badJson;
    badJson.id = "doc-bad";
    badJson.data = "{not json";
    ValueSpec nonObject;
    nonObject.id = "doc-arr";
    nonObject.data = "[1,2]";
    ValueSpec smuggling;
    smuggling.id = "doc-smuggle";
    smuggling.data = "{\"a\":1}\n{\"index\":{\"_index\":\"evil\"}}";
    // An Upsert with no 'data' field at all: nothing to index, and a null deref if unguarded.
    ValueSpec missingData;
    missingData.id = "doc-nodata";
    missingData.data = "";
    ValueSpec good;
    good.id = "doc-good";

    const auto prepared = prepare(invsync::test::buildSyncDataSession(
        SessionSpec {},
        {outsideAllowlist, vulnerabilitiesWrite, emptyId, badJson, nonObject, smuggling, missingData, good}));
    const auto outcome = processor.stageBulk(prepared.session, connector);

    EXPECT_EQ(200, outcome.status);
    EXPECT_TRUE(outcome.staged);
    const auto ops = events->syncOps();
    ASSERT_EQ(1U, ops.size()) << "only the good document may reach the bulk";
    EXPECT_EQ("test-cluster_001_doc-good", std::get<1>(ops[0]));
}

TEST_F(SessionProcessorTest, AnOutOfEnumOperationIs400WithNothingStaged)
{
    ValueSpec good;
    ValueSpec forged;
    forged.rawOperation = 7;

    // The good value comes FIRST: the pre-scan must reject before staging anything.
    const auto prepared = prepare(invsync::test::buildSyncDataSession(SessionSpec {}, {good, forged}));
    const auto outcome = processor.stageBulk(prepared.session, connector);

    EXPECT_EQ(400, outcome.status);
    EXPECT_FALSE(outcome.staged);
    EXPECT_TRUE(events->syncOps().empty()) << "a protocol error must not leave half a session staged";
}

TEST_F(SessionProcessorTest, AnAllSkippedSessionIsANoOp)
{
    ValueSpec skipped;
    skipped.index = "alerts";

    const auto prepared = prepare(invsync::test::buildSyncDataSession(SessionSpec {}, {skipped}));
    const auto outcome = processor.stageBulk(prepared.session, connector);

    EXPECT_EQ(200, outcome.status);
    EXPECT_FALSE(outcome.staged);
    EXPECT_NE(std::string::npos, outcome.body.find("noop"));
}

TEST_F(SessionProcessorTest, CleansDedupsFiltersAndFlushes)
{
    const auto prepared = prepare(invsync::test::buildCleansSession(
        SessionSpec {},
        {"wazuh-states-fim-files", "wazuh-states-fim-files", "alerts", "wazuh-states-vulnerabilities"}));
    const auto outcome = processor.executeImmediate(prepared.session, connector);

    EXPECT_EQ(200, outcome.status);
    EXPECT_FALSE(outcome.staged);

    const auto ops = events->syncOps();
    ASSERT_EQ(2U, ops.size()) << "duplicates collapse, out-of-family indices are ignored";
    // std::set orders alphabetically: fim-files before vulnerabilities.
    EXPECT_EQ("deleteByQuery", std::get<0>(ops[0]));
    EXPECT_EQ("wazuh-states-fim-files", std::get<2>(ops[0]));
    EXPECT_EQ("001", std::get<1>(ops[0]));
    EXPECT_EQ(CLUSTER, std::get<3>(ops[0]));
    EXPECT_EQ("wazuh-states-vulnerabilities", std::get<2>(ops[1]))
        << "vulnerabilities is CLEANABLE (only writes are refused)";
    EXPECT_EQ(1, events->m_syncFlushes.load()) << "cleans flush before answering";
}

TEST_F(SessionProcessorTest, AllFilteredCleansIsANoOpWithoutTouchingTheIndexer)
{
    const auto prepared = prepare(invsync::test::buildCleansSession(SessionSpec {}, {"alerts", "whatever"}));
    const auto outcome = processor.executeImmediate(prepared.session, connector);

    EXPECT_EQ(200, outcome.status);
    EXPECT_NE(std::string::npos, outcome.body.find("noop"));
    EXPECT_TRUE(events->syncOps().empty());
    EXPECT_EQ(0, events->m_syncFlushes.load());
}

TEST_F(SessionProcessorTest, ChecksumMatchIs200AndMismatchIs409)
{
    SessionSpec spec;
    spec.mode = invsync::test::fb::Mode_ModuleCheck;

    events->m_searchResponse = searchPage({"aaa", "bbb"});
    const auto expected = expectedSha1Hex("aaabbb");

    {
        const auto prepared =
            prepare(invsync::test::buildChecksumSession(spec, "wazuh-states-inventory-packages", expected));
        const auto outcome = processor.executeImmediate(prepared.session, connector);
        EXPECT_EQ(200, outcome.status) << outcome.body;
    }
    {
        const auto prepared =
            prepare(invsync::test::buildChecksumSession(spec, "wazuh-states-inventory-packages", "deadbeef"));
        const auto outcome = processor.executeImmediate(prepared.session, connector);
        EXPECT_EQ(409, outcome.status);
        EXPECT_NE(std::string::npos, outcome.body.find("checksum_mismatch"));
    }
}

TEST_F(SessionProcessorTest, ChecksumPaginatesWithSearchAfter)
{
    SessionSpec spec;
    spec.mode = invsync::test::fb::Mode_ModuleCheck;

    // A full first page (1000 hits) forces a second query; the second page closes the loop.
    std::vector<std::string> firstPage;
    std::string concatenated;
    for (int i = 0; i < 1000; ++i)
    {
        auto checksum = "c" + std::to_string(10000 + i);
        concatenated += checksum;
        firstPage.push_back(std::move(checksum));
    }
    concatenated += "zz";
    events->m_searchResponses.push_back(searchPage(firstPage));
    events->m_searchResponses.push_back(searchPage({"zz"}));

    const auto prepared = prepare(
        invsync::test::buildChecksumSession(spec, "wazuh-states-inventory-packages", expectedSha1Hex(concatenated)));
    const auto outcome = processor.executeImmediate(prepared.session, connector);

    EXPECT_EQ(200, outcome.status) << outcome.body;

    const auto ops = events->syncOps();
    ASSERT_EQ(2U, ops.size());
    EXPECT_EQ("executeSearchQuery", std::get<0>(ops[0]));
    {
        const auto firstQuery = nlohmann::json::parse(std::get<3>(ops[0]));
        EXPECT_FALSE(firstQuery.contains("search_after"));
        EXPECT_EQ("001", firstQuery["query"]["bool"]["must"][0]["term"]["wazuh.agent.id"]);
    }
    {
        const auto secondQuery = nlohmann::json::parse(std::get<3>(ops[1]));
        ASSERT_TRUE(secondQuery.contains("search_after")) << "page 2 must resume after page 1's last sort key";
        EXPECT_EQ("c10999", secondQuery["search_after"][0]);
    }
}

TEST_F(SessionProcessorTest, MetadataAndGroupModesRunOneScopedUpdateByQuery)
{
    struct Case
    {
        invsync::test::fb::Mode mode;
        const char* mustContain; // a fragment that identifies the script family
        const char* mustNotContain;
    };
    const Case cases[] = {
        {invsync::test::fb::Mode_MetadataDelta, "state.document_version = params.globalVersion", "needsUpdate"},
        {invsync::test::fb::Mode_GroupDelta, "wazuh.agent.groups = params.groups", "needsUpdate"},
        {invsync::test::fb::Mode_MetadataCheck, "needsUpdate", "params.timestamp"},
        {invsync::test::fb::Mode_GroupCheck, "needsUpdate", "params.timestamp"},
    };

    for (const auto& testCase : cases)
    {
        auto localEvents = std::make_shared<ConnectorEvents>();
        FakeIndexerConnectorSync localConnector {localEvents, "sync"};

        SessionSpec spec;
        spec.mode = testCase.mode;
        spec.indices = {"wazuh-states-inventory-packages", "alerts"}; // the second must be filtered

        const auto prepared = prepare(invsync::test::buildBareSession(spec));
        const auto outcome = processor.executeImmediate(prepared.session, localConnector);

        EXPECT_EQ(200, outcome.status) << "mode " << static_cast<int>(testCase.mode);

        const auto ops = localEvents->syncOps();
        ASSERT_EQ(1U, ops.size());
        EXPECT_EQ("executeUpdateByQuery", std::get<0>(ops[0]));
        EXPECT_EQ("wazuh-states-inventory-packages", std::get<2>(ops[0])) << "out-of-family indices filtered";

        const auto query = nlohmann::json::parse(std::get<3>(ops[0]));
        EXPECT_EQ("001", query["query"]["bool"]["must"][0]["term"]["wazuh.agent.id"]);
        // addClusterScope appended the manager's cluster as a second must clause.
        EXPECT_EQ(CLUSTER, query["query"]["bool"]["must"][1]["term"]["wazuh.cluster.name"]);
        const auto script = query["script"]["source"].get<std::string>();
        EXPECT_NE(std::string::npos, script.find(testCase.mustContain)) << script;
        EXPECT_EQ(std::string::npos, script.find(testCase.mustNotContain)) << script;
    }
}

TEST_F(SessionProcessorTest, MetadataWithOnlyOutOfFamilyIndicesIsANoOp)
{
    SessionSpec spec;
    spec.mode = invsync::test::fb::Mode_MetadataDelta;
    spec.indices = {"alerts"};

    const auto prepared = prepare(invsync::test::buildBareSession(spec));
    const auto outcome = processor.executeImmediate(prepared.session, connector);

    EXPECT_EQ(200, outcome.status);
    EXPECT_NE(std::string::npos, outcome.body.find("noop"));
    EXPECT_TRUE(events->syncOps().empty());
}
