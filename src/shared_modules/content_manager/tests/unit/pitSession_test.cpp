/*
 * Wazuh content manager - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "components/pitSession.hpp"
#include "fakes/fakeIndexerQueryPort.hpp"
#include "gtest/gtest.h"

using fakes::FakeIndexerQueryPort;

namespace
{

PitSession::Config validatingConfig()
{
    PitSession::Config config;
    config.dataIndices = {"data-index"};
    config.consumerStatusIndex = ".consumers";
    config.consumerStatusId = "consumer:1";
    return config;
}

nlohmann::json consumerHit(const std::string& status)
{
    return nlohmann::json {
        {"hits", nlohmann::json::array({nlohmann::json {{"_id", "consumer:1"}, {"_source", {{"status", status}}}}})}};
}

} // namespace

TEST(PitSessionTest, OpensThePitOverDataAndConsumerIndices)
{
    FakeIndexerQueryPort port;
    {
        PitSession session {port, validatingConfig()};
        EXPECT_EQ(port.state()->openedPits, 1U);
        ASSERT_EQ(port.state()->openedIndices.size(), 1U);
        EXPECT_EQ(port.state()->openedIndices.front(), (std::vector<std::string> {"data-index", ".consumers"}));
    }
    // The lease is always released, including on the exception paths a test cannot easily reach.
    EXPECT_EQ(port.state()->closedPits, 1U);
}

TEST(PitSessionTest, OmitsTheConsumerIndexWhenValidationIsDisabled)
{
    PitSession::Config config;
    config.dataIndices = {"a", "b"};

    FakeIndexerQueryPort port;
    PitSession session {port, config};

    EXPECT_FALSE(session.validationEnabled());
    EXPECT_EQ(port.state()->openedIndices.front(), (std::vector<std::string> {"a", "b"}));
    // With no consumer to validate, readiness is not something this session can be wrong about.
    EXPECT_EQ(session.validateConsumerReady(), PitSession::Readiness::Ready);
}

TEST(PitSessionTest, ReadinessTaxonomy)
{
    struct Case
    {
        nlohmann::json response;
        PitSession::Readiness expected;
        const char* what;
    };

    const std::vector<Case> cases {
        {consumerHit("ready"), PitSession::Readiness::Ready, "ready"},
        {consumerHit("running"), PitSession::Readiness::NotReady, "running"},
        {consumerHit("failed"), PitSession::Readiness::NotReady, "failed"},
        {consumerHit("something-new"), PitSession::Readiness::NotReady, "unrecognised status"},
        {consumerHit(""), PitSession::Readiness::Unusable, "empty status"},
        {nlohmann::json {{"hits", nlohmann::json::array()}}, PitSession::Readiness::Missing, "no document"},
        {nlohmann::json {{"hits", nlohmann::json::array({nlohmann::json {{"_id", "consumer:1"}}})}},
         PitSession::Readiness::Unusable,
         "hit without _source"}};

    for (const auto& testCase : cases)
    {
        FakeIndexerQueryPort port;
        port.state()->onSearch = [&testCase](const auto&, std::size_t) { return testCase.response; };

        PitSession session {port, validatingConfig()};
        EXPECT_EQ(session.validateConsumerReady(), testCase.expected) << testCase.what;
    }
}

TEST(PitSessionTest, ReadinessProbeRequestsOnlyTheStatusField)
{
    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const auto&, std::size_t) { return consumerHit("ready"); };

    PitSession session {port, validatingConfig()};
    session.validateConsumerReady();

    ASSERT_EQ(port.state()->searches.size(), 1U);
    const auto& call = port.state()->searches.front();
    EXPECT_EQ(call.size, 1U);
    EXPECT_EQ(call.query.at("ids").at("values").front(), "consumer:1");
    ASSERT_TRUE(call.source.has_value());
    EXPECT_EQ(call.source->at("includes"), nlohmann::json::array({"status"}));
}

TEST(PitSessionTest, ScopeToDataExcludesTheConsumerIndex)
{
    FakeIndexerQueryPort port;
    PitSession session {port, validatingConfig()};

    const nlohmann::json userQuery {{"match_all", nlohmann::json::object()}};
    const auto scoped = session.scopeToData(userQuery);

    ASSERT_TRUE(scoped.contains("bool"));
    EXPECT_EQ(scoped.at("bool").at("must").front(), userQuery);
    EXPECT_EQ(scoped.at("bool").at("must_not").front().at("terms").at("_index"),
              nlohmann::json::array({".consumers"}));
}

TEST(PitSessionTest, ScopeToDataIsAPassThroughWithoutAConsumerIndex)
{
    PitSession::Config config;
    config.dataIndices = {"data-index"};

    FakeIndexerQueryPort port;
    PitSession session {port, config};

    const nlohmann::json userQuery {{"match_all", nlohmann::json::object()}};
    EXPECT_EQ(session.scopeToData(userQuery), userQuery);
}

TEST(PitSessionTest, IsConsumerDocIdentifiesHitsByIndex)
{
    FakeIndexerQueryPort port;
    PitSession session {port, validatingConfig()};

    EXPECT_TRUE(session.isConsumerDoc(nlohmann::json {{"_index", ".consumers"}}));
    EXPECT_FALSE(session.isConsumerDoc(nlohmann::json {{"_index", "data-index"}}));
    EXPECT_FALSE(session.isConsumerDoc(nlohmann::json::object()));
}

TEST(PitSessionTest, CountDocumentsReportsHowManyRequiredIdsArePresent)
{
    FakeIndexerQueryPort port;
    port.state()->onSearch = [](const auto&, std::size_t)
    {
        return nlohmann::json {{"hits",
                                nlohmann::json::array({nlohmann::json {{"_id", "FEED-GLOBAL"}},
                                                       nlohmann::json {{"_id", "OSCPE-GLOBAL"}}})}};
    };

    PitSession session {port, validatingConfig()};
    const auto ids = nlohmann::json::array({"FEED-GLOBAL", "OSCPE-GLOBAL", "CNA-MAPPING-GLOBAL"});
    EXPECT_EQ(session.countDocuments(ids), 2U);
}
