/*
 * Wazuh content manager - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "components/changeDetector.hpp"
#include "fakes/fakeIndexerQueryPort.hpp"
#include "gtest/gtest.h"

using fakes::FakeIndexerQueryPort;

namespace
{

PitSession::Config pitConfig()
{
    PitSession::Config config;
    config.dataIndices = {"data-index"};
    config.consumerStatusIndex = ".consumers";
    config.consumerStatusId = "consumer:1";
    return config;
}

} // namespace

/**************************
 * OffsetCursorDetector
 **************************/

TEST(OffsetCursorDetectorTest, ProbeIsANoOp)
{
    OffsetCursorDetector detector {"offset"};

    FakeIndexerQueryPort port;
    PitSession session {port, pitConfig()};

    const auto probe = detector.probe(session, port);
    EXPECT_TRUE(probe.remoteToken.empty());
    EXPECT_FALSE(probe.sourceMissing);
    // The cursor is carried by the documents, so probing costs nothing.
    EXPECT_TRUE(port.state()->searches.empty());
}

TEST(OffsetCursorDetectorTest, PlanMatrix)
{
    OffsetCursorDetector detector {"offset"};

    struct Case
    {
        std::string localToken;
        FetchPlan::Mode expected;
        const char* what;
    };

    // Absent, zeroed and corrupt all mean the same thing: there is no safe lower bound, so the only
    // correct fetch is everything. A range query built from a garbage bound would either throw on
    // every cycle or silently skip documents.
    const std::vector<Case> cases {{"", FetchPlan::Mode::Full, "no cursor"},
                                   {"0", FetchPlan::Mode::Full, "zeroed cursor"},
                                   {"not-a-number", FetchPlan::Mode::Full, "corrupt cursor"},
                                   {"12-34", FetchPlan::Mode::Full, "partially numeric cursor"},
                                   {"1042", FetchPlan::Mode::Incremental, "valid cursor"}};

    for (const auto& testCase : cases)
    {
        const auto plan = detector.plan(ProbeResult {}, testCase.localToken);
        EXPECT_EQ(plan.mode, testCase.expected) << testCase.what;

        if (testCase.expected == FetchPlan::Mode::Full)
        {
            EXPECT_EQ(plan.query, (nlohmann::json {{"match_all", nlohmann::json::object()}})) << testCase.what;
            EXPECT_TRUE(plan.startToken.empty()) << testCase.what;
        }
        else
        {
            EXPECT_EQ(plan.query, (nlohmann::json {{"range", {{"offset", {{"gt", 1042}}}}}})) << testCase.what;
            EXPECT_EQ(plan.startToken, "1042") << testCase.what;
        }
    }
}

TEST(OffsetCursorDetectorTest, HonoursTheConfiguredCursorField)
{
    OffsetCursorDetector detector {"local_offset"};

    const auto plan = detector.plan(ProbeResult {}, "7");
    EXPECT_EQ(plan.query, (nlohmann::json {{"range", {{"local_offset", {{"gt", 7}}}}}}));
    EXPECT_EQ(detector.pageTokenPointer(), "/_source/local_offset");
}

TEST(OffsetCursorDetectorTest, FinalTokenIsTheHighestPageToken)
{
    OffsetCursorDetector detector {"offset"};
    EXPECT_EQ(detector.finalToken(ProbeResult {}, "2048"), "2048");
}

/**************************
 * ContentHashDetector
 **************************/

TEST(ContentHashDetectorTest, DocProbeReadsTheManifestById)
{
    ContentHashDetector::Config config;
    config.hashDocId = "__ioc_type_hashes__";
    config.hashPointers = {"/type_hashes/url_domain/hash/sha256", "/url_domain/hash/sha256"};
    config.dataQuery = nlohmann::json {{"term", {{"document.type", "url_domain"}}}};

    ContentHashDetector detector {config};

    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const auto&, std::size_t)
    {
        return nlohmann::json {
            {"hits",
             nlohmann::json::array({nlohmann::json {
                 {"_id", "__ioc_type_hashes__"},
                 {"_source", {{"type_hashes", {{"url_domain", {{"hash", {{"sha256", "abc"}}}}}}}}}}})}};
    };

    PitSession session {port, pitConfig()};
    const auto probe = detector.probe(session, port);

    EXPECT_EQ(probe.remoteToken, "abc");
    EXPECT_FALSE(probe.sourceMissing);

    ASSERT_FALSE(port.state()->searches.empty());
    EXPECT_EQ(port.state()->searches.front().query.at("bool").at("must").front().at("ids").at("values").front(),
              "__ioc_type_hashes__");
}

TEST(ContentHashDetectorTest, DocProbeFallsBackToTheFlatManifestShape)
{
    ContentHashDetector::Config config;
    config.hashDocId = "__ioc_type_hashes__";
    config.hashPointers = {"/type_hashes/url_domain/hash/sha256", "/url_domain/hash/sha256"};
    config.dataQuery = nlohmann::json::object();

    ContentHashDetector detector {config};

    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const auto&, std::size_t)
    {
        return nlohmann::json {{"hits",
                                nlohmann::json::array({nlohmann::json {
                                    {"_source", {{"url_domain", {{"hash", {{"sha256", "flat-hash"}}}}}}}}})}};
    };

    PitSession session {port, pitConfig()};
    // First pointer that resolves wins, which is what lets both manifest shapes work without a
    // migration.
    EXPECT_EQ(detector.probe(session, port).remoteToken, "flat-hash");
}

TEST(ContentHashDetectorTest, QueryProbeReadsMetadataAlongsideTheHash)
{
    ContentHashDetector::Config config;
    config.hashIndex = "wazuh-threatintel-policies";
    config.hashQuery = nlohmann::json {{"term", {{"space.name", "standard"}}}};
    config.hashPointers = {"/space/hash/sha256"};
    config.metadataPointers = {{"enabled", "/document/enabled"}, {"integrations", "/document/integrations"}};
    config.dataQuery = nlohmann::json {{"term", {{"space.name", "standard"}}}};

    ContentHashDetector detector {config};

    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const auto&, std::size_t)
    {
        return nlohmann::json {
            {"hits",
             nlohmann::json::array({nlohmann::json {
                 {"_source",
                  {{"space", {{"hash", {{"sha256", "policy-hash"}}}}},
                   {"document", {{"enabled", false}, {"integrations", nlohmann::json::array({"int1"})}}}}}}})}};
    };

    PitSession session {port, pitConfig()};
    const auto probe = detector.probe(session, port);

    EXPECT_EQ(probe.remoteToken, "policy-hash");
    EXPECT_EQ(probe.metadata.at("enabled"), false);
    EXPECT_EQ(probe.metadata.at("integrations"), nlohmann::json::array({"int1"}));
}

TEST(ContentHashDetectorTest, AQueryProbeMatchingTwoDocumentsIsAConfigurationError)
{
    ContentHashDetector::Config config;
    config.hashIndex = "wazuh-threatintel-policies";
    config.hashQuery = nlohmann::json {{"term", {{"space.name", "standard"}}}};
    config.hashPointers = {"/space/hash/sha256"};
    config.dataQuery = nlohmann::json {{"term", {{"space.name", "standard"}}}};

    ContentHashDetector detector {config};

    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const auto&, std::size_t)
    {
        const auto policy = [](const char* hash)
        { return nlohmann::json {{"_source", {{"space", {{"hash", {{"sha256", hash}}}}}}}}; };
        return nlohmann::json {{"hits", nlohmann::json::array({policy("hash-a"), policy("hash-b")})}};
    };

    PitSession session {port, pitConfig()};
    const auto probe = detector.probe(session, port);

    // Taking front() here would pick one of the two by shard order, which is not stable across
    // cycles: the topic would alternate between two hashes and reload on every single cycle, with
    // nothing anywhere reporting a fault. Naming the offending key is the whole point.
    EXPECT_FALSE(probe.configError.empty());
    EXPECT_NE(probe.configError.find("hashQuery"), std::string::npos);
    EXPECT_TRUE(probe.remoteToken.empty());
}

TEST(ContentHashDetectorTest, AQueryProbeAsksForOneMoreHitThanItNeeds)
{
    ContentHashDetector::Config config;
    config.hashIndex = "wazuh-threatintel-policies";
    config.hashQuery = nlohmann::json {{"term", {{"space.name", "standard"}}}};
    config.hashPointers = {"/space/hash/sha256"};
    config.dataQuery = nlohmann::json::object();

    ContentHashDetector detector {config};

    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const auto&, std::size_t) { return FakeIndexerQueryPort::emptyHits(); };

    PitSession session {port, pitConfig()};
    detector.probe(session, port);

    // Ambiguity is invisible at size 1: the server would truncate the second hit and the probe
    // could never tell an exact match from an accidental one.
    ASSERT_FALSE(port.state()->searches.empty());
    EXPECT_EQ(port.state()->searches.back().size, 2U);
}

TEST(ContentHashDetectorTest, ADocProbeAsksForASingleHit)
{
    ContentHashDetector::Config config;
    config.hashDocId = "manifest";
    config.hashPointers = {"/hash"};
    config.dataQuery = nlohmann::json::object();

    ContentHashDetector detector {config};

    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const auto&, std::size_t) { return FakeIndexerQueryPort::emptyHits(); };

    PitSession session {port, pitConfig()};
    detector.probe(session, port);

    // `_id` is unique, so there is no ambiguity to detect and no reason to pay for a second hit.
    ASSERT_FALSE(port.state()->searches.empty());
    EXPECT_EQ(port.state()->searches.back().size, 1U);
}

TEST(ContentHashDetectorTest, MissingSourceIsNotAnError)
{
    ContentHashDetector::Config config;
    config.hashDocId = "__ioc_type_hashes__";
    config.hashPointers = {"/type_hashes/url_domain/hash/sha256"};
    config.dataQuery = nlohmann::json::object();

    ContentHashDetector detector {config};

    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const auto&, std::size_t) { return FakeIndexerQueryPort::emptyHits(); };

    PitSession session {port, pitConfig()};
    const auto probe = detector.probe(session, port);

    // A space that does not exist remotely yet, or an install whose manifest has not been written,
    // simply has nothing to sync — that is a skip, not a failure.
    EXPECT_TRUE(probe.sourceMissing);
    EXPECT_EQ(detector.plan(probe, "whatever").mode, FetchPlan::Mode::NoChange);
}

TEST(ContentHashDetectorTest, PlanMatrix)
{
    ContentHashDetector::Config config;
    config.hashDocId = "manifest";
    config.hashPointers = {"/hash"};
    config.dataQuery = nlohmann::json {{"term", {{"document.type", "ip"}}}};

    ContentHashDetector detector {config};

    ProbeResult remote;
    remote.remoteToken = "hash-1";

    EXPECT_EQ(detector.plan(remote, "hash-1").mode, FetchPlan::Mode::NoChange);

    const auto changed = detector.plan(remote, "hash-0");
    EXPECT_EQ(changed.mode, FetchPlan::Mode::Full);
    EXPECT_EQ(changed.query, config.dataQuery);

    // No local token at all: a hash says "the content as a whole is at version X", so the only
    // possible fetch is everything.
    EXPECT_EQ(detector.plan(remote, "").mode, FetchPlan::Mode::Full);

    EXPECT_EQ(detector.finalToken(remote, "ignored"), "hash-1");
    EXPECT_TRUE(detector.pageTokenPointer().empty());
}
