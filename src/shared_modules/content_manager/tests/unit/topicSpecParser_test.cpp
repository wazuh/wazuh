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

#include "components/executionContext.hpp"
#include "components/topicSpecParser.hpp"
#include "contentTopicSpec.hpp"
#include "gtest/gtest.h"
#include <cstdint>
#include <string>
#include <variant>

using content_manager::CursorDetection;
using content_manager::DocumentProbe;
using content_manager::HashDetection;
using content_manager::QueryProbe;
using content_manager::Readiness;
using content_manager::TopicSpec;

namespace
{

    TopicSpec cursorSpec()
    {
        TopicSpec spec;
        spec.schedule.intervalSeconds = 3600;
        spec.schedule.onDemand = true;
        spec.source.indices = {".wazuh-threatintel-vulnerabilities"};
        spec.source.sourceFilter = nlohmann::json {{"includes", {"offset"}}, {"excludes", nlohmann::json::array()}};
        spec.source.pageSize = 250;
        spec.source.slices = 2;
        spec.readiness = Readiness {".wazuh-cti-consumers", "cti:catalog:consumer:vulnerabilities", 30, 7};
        spec.detection = CursorDetection {"offset", "long"};
        spec.fullLoad.requiredDocumentIds = {"FEED-GLOBAL"};
        spec.state.databasePath = "queue/vd/vd_updater/rocksdb";
        spec.state.resetOnRegister = true;
        return spec;
    }

    TopicSpec hashSpec()
    {
        TopicSpec spec;
        spec.schedule.onDemand = true;
        spec.source.indices = {"wazuh-threatintel-policies", "wazuh-threatintel-decoders"};
        spec.source.expandWildcards = true;
        spec.source.query = nlohmann::json {{"term", {{"space.name", "standard"}}}};
        HashDetection hash;
        hash.probe = QueryProbe {nlohmann::json {{"wildcard", {{"_index", {{"value", "*policies*"}}}}}}};
        hash.tokenPointers = {"/space/hash/sha256"};
        hash.metadata = {{"enabled", "/document/enabled"}};
        spec.detection = hash;
        return spec;
    }

    /// Asserts @p parameters is rejected and the message names what is wrong.
    void expectRejected(const nlohmann::json& parameters, const std::string& mentions)
    {
        try
        {
            TopicSpecParser::parse(parameters);
            ADD_FAILURE() << "accepted: " << parameters.dump();
        }
        catch (const std::invalid_argument& e)
        {
            EXPECT_NE(std::string {e.what()}.find(mentions), std::string::npos)
                << "message '" << e.what() << "' does not mention '" << mentions << "'";
        }
    }

} // namespace

TEST(TopicSpecParserTest, ACursorSpecRoundTrips)
{
    const auto parsed = TopicSpecParser::parse(content_manager::toParameters(cursorSpec()));

    EXPECT_EQ(parsed.schedule.intervalSeconds, 3600U);
    EXPECT_TRUE(parsed.schedule.onDemand);
    EXPECT_EQ(parsed.source.indices, cursorSpec().source.indices);
    EXPECT_EQ(parsed.source.sourceFilter, cursorSpec().source.sourceFilter);
    EXPECT_EQ(parsed.source.pageSize, 250U);
    EXPECT_EQ(parsed.source.slices, 2U);
    ASSERT_TRUE(parsed.readiness.has_value());
    EXPECT_EQ(parsed.readiness->consumerIndex, ".wazuh-cti-consumers");
    EXPECT_EQ(parsed.readiness->consumerId, "cti:catalog:consumer:vulnerabilities");
    EXPECT_EQ(parsed.readiness->retrySeconds, 30U);
    EXPECT_EQ(parsed.readiness->cacheSeconds, 7U);
    ASSERT_TRUE(std::holds_alternative<CursorDetection>(parsed.detection));
    EXPECT_EQ(std::get<CursorDetection>(parsed.detection).field, "offset");
    EXPECT_EQ(parsed.fullLoad.requiredDocumentIds, (std::vector<std::string> {"FEED-GLOBAL"}));
    EXPECT_EQ(parsed.state.databasePath, "queue/vd/vd_updater/rocksdb");
    EXPECT_TRUE(parsed.state.resetOnRegister);
}

TEST(TopicSpecParserTest, AHashSpecRoundTripsWithEitherProbe)
{
    const auto byQuery = TopicSpecParser::parse(content_manager::toParameters(hashSpec()));
    ASSERT_TRUE(std::holds_alternative<HashDetection>(byQuery.detection));
    const auto& hash = std::get<HashDetection>(byQuery.detection);
    ASSERT_TRUE(std::holds_alternative<QueryProbe>(hash.probe));
    EXPECT_EQ(std::get<QueryProbe>(hash.probe).query,
              std::get<QueryProbe>(std::get<HashDetection>(hashSpec().detection).probe).query);
    EXPECT_EQ(hash.tokenPointers, (std::vector<std::string> {"/space/hash/sha256"}));
    EXPECT_EQ(hash.metadata.at("enabled"), "/document/enabled");
    EXPECT_EQ(byQuery.source.query, hashSpec().source.query);
    EXPECT_TRUE(byQuery.source.expandWildcards);
    EXPECT_FALSE(byQuery.schedule.intervalSeconds.has_value()) << "no interval means the host drives the cycle";

    auto manifest = hashSpec();
    std::get<HashDetection>(manifest.detection).probe = DocumentProbe {"__ioc_type_hashes__"};
    const auto byDocument = TopicSpecParser::parse(content_manager::toParameters(manifest));
    EXPECT_EQ(std::get<DocumentProbe>(std::get<HashDetection>(byDocument.detection).probe).id, "__ioc_type_hashes__");
}

TEST(TopicSpecParserTest, NoReadinessBlockMeansTheTopicIsNeverGated)
{
    auto spec = hashSpec();
    spec.readiness.reset();

    EXPECT_FALSE(TopicSpecParser::parse(content_manager::toParameters(spec)).readiness.has_value());
}

TEST(TopicSpecParserTest, SourceAndDetectionAreRequired)
{
    auto parameters = content_manager::toParameters(cursorSpec());
    auto noSource = parameters;
    noSource.erase("source");
    expectRejected(noSource, "'source' is required");

    auto noDetection = parameters;
    noDetection.erase("detection");
    expectRejected(noDetection, "'detection' is required");

    auto noIndices = parameters;
    noIndices["source"]["indices"] = nlohmann::json::array();
    expectRejected(noIndices, "source.indices");
}

TEST(TopicSpecParserTest, EveryBlockRejectsAKeyItDoesNotKnow)
{
    const auto parameters = content_manager::toParameters(cursorSpec());

    auto top = parameters;
    top["topicName"] = "duplicate";
    expectRejected(top, "parameters: unknown key 'topicName'");

    for (const auto* block : {"schedule", "source", "readiness", "detection", "fullLoad", "state"})
    {
        auto broken = parameters;
        broken[block]["bogus"] = 1;
        expectRejected(broken, std::string {block} + ": unknown key 'bogus'");
    }
}

TEST(TopicSpecParserTest, ConnectionKeysAreRejectedNotIgnored)
{
    // The connection is the host's indexer (D1). A host still copying its <indexer> section here
    // must find out at registration, not by noticing the settings never took effect.
    auto parameters = content_manager::toParameters(cursorSpec());
    parameters["source"]["hosts"] = nlohmann::json::array({"https://127.0.0.1:9200"});
    expectRejected(parameters, "source: unknown key 'hosts'");
}

TEST(TopicSpecParserTest, AKeyOfTheOtherStrategyIsUnknown)
{
    auto cursor = content_manager::toParameters(cursorSpec());
    cursor["detection"]["tokenPointers"] = nlohmann::json::array({"/hash"});
    expectRejected(cursor, "detection: unknown key 'tokenPointers'");

    auto hash = content_manager::toParameters(hashSpec());
    hash["detection"]["field"] = "offset";
    expectRejected(hash, "detection: unknown key 'field'");
}

TEST(TopicSpecParserTest, RejectsUnknownStrategiesAndProbes)
{
    auto strategy = content_manager::toParameters(cursorSpec());
    strategy["detection"] = nlohmann::json {{"type", "timestamp"}};
    expectRejected(strategy, "detection.type");

    auto probe = content_manager::toParameters(hashSpec());
    probe["detection"]["probe"] = nlohmann::json {{"type", "alias"}};
    expectRejected(probe, "detection.probe.type");

    auto noQuery = content_manager::toParameters(hashSpec());
    noQuery["detection"]["probe"] = nlohmann::json {{"type", "query"}};
    expectRejected(noQuery, "detection.probe");

    auto noProbe = content_manager::toParameters(hashSpec());
    noProbe["detection"].erase("probe");
    expectRejected(noProbe, "'probe' is required");
}

TEST(TopicSpecParserTest, HashDetectionNeedsUsablePointers)
{
    auto empty = content_manager::toParameters(hashSpec());
    empty["detection"]["tokenPointers"] = nlohmann::json::array();
    expectRejected(empty, "detection.tokenPointers");

    auto notAPointer = content_manager::toParameters(hashSpec());
    notAPointer["detection"]["tokenPointers"] = nlohmann::json::array({"space.hash"});
    expectRejected(notAPointer, "detection.tokenPointers");

    auto badMetadata = content_manager::toParameters(hashSpec());
    badMetadata["detection"]["metadata"] = nlohmann::json {{"enabled", "document.enabled"}};
    expectRejected(badMetadata, "detection.metadata");
}

TEST(TopicSpecParserTest, AReadinessBlockNeedsAConcreteIndexAndAnId)
{
    auto noId = content_manager::toParameters(cursorSpec());
    noId["readiness"].erase("consumerId");
    expectRejected(noId, "readiness.consumerId");

    // Both consumer-document defences compare against `_index`, which reports concrete names; a
    // pattern would never match and the leak would be silent.
    for (const auto* bad : {".consumers-*", "a,b", "-excluded"})
    {
        auto pattern = content_manager::toParameters(cursorSpec());
        pattern["readiness"]["consumerIndex"] = bad;
        expectRejected(pattern, "readiness.consumerIndex");
    }
}

TEST(TopicSpecParserTest, RejectsMistypedAndZeroSizes)
{
    auto zeroSlices = content_manager::toParameters(cursorSpec());
    zeroSlices["source"]["slices"] = 0;
    expectRejected(zeroSlices, "source.slices");

    auto zeroPage = content_manager::toParameters(cursorSpec());
    zeroPage["source"]["pageSize"] = 0;
    expectRejected(zeroPage, "source.pageSize");

    auto textual = content_manager::toParameters(cursorSpec());
    textual["source"]["pageSize"] = "100";
    expectRejected(textual, "source.pageSize");

    auto filter = content_manager::toParameters(cursorSpec());
    filter["source"]["sourceFilter"] = nlohmann::json::array({"offset"});
    expectRejected(filter, "source.sourceFilter");

    auto flag = content_manager::toParameters(cursorSpec());
    flag["schedule"]["onDemand"] = "yes";
    expectRejected(flag, "schedule.onDemand");
}

TEST(TopicSpecParserTest, AcceptsNumbersHoweverTheHostHappenedToStoreThem)
{
    // nlohmann records how a number was stored, not what it means: `= 2` is signed, a parsed or
    // unsigned-typed value is unsigned. Both must mean the same thing.
    auto signedLiterals = content_manager::toParameters(cursorSpec());
    signedLiterals["source"]["slices"] = 2;
    signedLiterals["source"]["pageSize"] = 100;
    EXPECT_NO_THROW(TopicSpecParser::parse(signedLiterals));

    auto unsignedValues = signedLiterals;
    unsignedValues["source"]["slices"] = std::uint32_t {2};
    EXPECT_NO_THROW(TopicSpecParser::parse(unsignedValues));

    EXPECT_NO_THROW(TopicSpecParser::parse(nlohmann::json::parse(signedLiterals.dump())));
}

TEST(TopicSpecParserTest, DefaultsAreTheLibrarys)
{
    nlohmann::json minimal {{"source", {{"indices", {"data-index"}}}}, {"detection", {{"type", "cursor"}}}};
    const auto spec = TopicSpecParser::parse(minimal);

    EXPECT_EQ(spec.source.pageSize, 100U);
    EXPECT_EQ(spec.source.slices, 1U);
    EXPECT_EQ(spec.source.pitKeepAlive, "5m");
    EXPECT_FALSE(spec.source.query.has_value());
    EXPECT_FALSE(spec.schedule.onDemand);
    EXPECT_FALSE(spec.readiness.has_value());
    EXPECT_EQ(std::get<CursorDetection>(spec.detection).field, "offset");
    EXPECT_TRUE(spec.state.databasePath.empty());
}

TEST(ExecutionContextTest, PrepareOpensNoDatabaseWithoutAPath)
{
    auto spec = cursorSpec();
    spec.state.databasePath.clear();

    // A host that owns its own state (the engine keeps tokens in its store) sets no databasePath,
    // and then no RocksDB is opened at all.
    EXPECT_EQ(ExecutionContext::prepare(spec, "topic").database, nullptr);
}
