/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "common/agentMetadataLimits.hpp"
#include "endpoints/reportedAgentMetadata.hpp"

#include <gtest/gtest.h>

#include <json.hpp>
#include <string>
#include <vector>

using invsync::endpoints::stampReportedAgentMetadata;

namespace
{
    constexpr auto kFullAgent {R"({"agent":{"name":"web-01","version":"v5.0.0","groups":["default","linux"],)"
                               R"("host":{"architecture":"x86_64","hostname":"web-01","ip":"10.0.0.1",)"
                               R"("os":{"name":"Ubuntu","platform":"ubuntu","type":"linux","version":"24.04"}}}})"};

    /// The empty `wazuh.agent.host` written when the agent reports no host strings.
    nlohmann::json emptyHost()
    {
        return nlohmann::json::parse(
            R"({"architecture":"","hostname":"","os":{"name":"","platform":"","type":"","version":""}})");
    }

    struct Stamped
    {
        nlohmann::json document;
        std::size_t dropped;
    };

    Stamped stamp(const nlohmann::json& payload)
    {
        Stamped result {nlohmann::json::object(), 0};
        result.dropped = stampReportedAgentMetadata(payload, result.document);
        return result;
    }

    Stamped stamp(const char* payload)
    {
        return stamp(nlohmann::json::parse(payload));
    }

    nlohmann::json withAgent(nlohmann::json agent)
    {
        return nlohmann::json {{"agent", std::move(agent)}};
    }
} // namespace

TEST(ReportedAgentMetadataTest, CopiesGroupsAndHostUnderWazuhAgent)
{
    const auto [document, dropped] = stamp(kFullAgent);

    EXPECT_EQ(0U, dropped);
    EXPECT_EQ(nlohmann::json::parse(R"(["default","linux"])"), document["/wazuh/agent/groups"_json_pointer]);
    EXPECT_EQ(nlohmann::json::parse(R"({"architecture":"x86_64","hostname":"web-01",)"
                                    R"("os":{"name":"Ubuntu","platform":"ubuntu","type":"linux","version":"24.04"}})"),
              document["/wazuh/agent/host"_json_pointer]);
}

TEST(ReportedAgentMetadataTest, OnlyGroupsAndHostAreWritten)
{
    const auto [document, dropped] = stamp(
        R"({"agent":{"id":"999","name":"n","version":"v","extra":1,"groups":[],"host":{"ip":"10.0.0.1","x":"y"}},)"
        R"("wazuh":{"agent":{"id":"999"}}})");

    EXPECT_EQ(0U, dropped);
    ASSERT_EQ(1U, document.size());
    const auto& agent = document["/wazuh/agent"_json_pointer];
    ASSERT_EQ(2U, agent.size()) << agent.dump();
    EXPECT_TRUE(agent.contains("groups"));
    EXPECT_EQ(emptyHost(), agent.at("host")) << "ip and unknown host keys are not copied";
}

TEST(ReportedAgentMetadataTest, NoAgentObjectWritesNothing)
{
    const auto [document, dropped] = stamp(R"({"modules":{"agent":{}}})");

    EXPECT_EQ(0U, dropped);
    EXPECT_EQ(nlohmann::json::object(), document);
}

TEST(ReportedAgentMetadataTest, AnAgentThatIsNotAnObjectWritesNothingAndCounts)
{
    for (const auto* body : {R"({"agent":"x"})", R"({"agent":[]})", R"({"agent":null})", R"({"agent":1})"})
    {
        const auto [document, dropped] = stamp(body);
        EXPECT_EQ(1U, dropped) << body;
        EXPECT_EQ(nlohmann::json::object(), document) << body;
    }
}

TEST(ReportedAgentMetadataTest, AnEmptyAgentWritesTheFullShapeEmpty)
{
    const auto [document, dropped] = stamp(R"({"agent":{}})");

    EXPECT_EQ(0U, dropped) << "a missing field is not a bad one";
    EXPECT_EQ(nlohmann::json::array(), document["/wazuh/agent/groups"_json_pointer]);
    EXPECT_EQ(emptyHost(), document["/wazuh/agent/host"_json_pointer]);
}

TEST(ReportedAgentMetadataTest, GroupsAtTheLimitsAreKept)
{
    auto groups = nlohmann::json::array();
    for (std::size_t i = 0; i < invsync::common::MAX_AGENT_GROUPS; ++i)
    {
        auto name = std::to_string(i);
        name.resize(invsync::common::MAX_AGENT_GROUP_NAME_BYTES, 'g');
        groups.push_back(name);
    }

    const auto [document, dropped] = stamp(withAgent({{"groups", groups}}));

    EXPECT_EQ(0U, dropped);
    EXPECT_EQ(groups, document["/wazuh/agent/groups"_json_pointer]);
}

TEST(ReportedAgentMetadataTest, TooManyGroupsEmptiesTheList)
{
    const auto groups = nlohmann::json(std::vector<std::string>(invsync::common::MAX_AGENT_GROUPS + 1, "g"));

    const auto [document, dropped] = stamp(withAgent({{"groups", groups}}));

    EXPECT_EQ(1U, dropped);
    EXPECT_EQ(nlohmann::json::array(), document["/wazuh/agent/groups"_json_pointer]);
}

TEST(ReportedAgentMetadataTest, OneBadGroupEmptiesTheWholeList)
{
    const std::string tooLong(invsync::common::MAX_AGENT_GROUP_NAME_BYTES + 1, 'g');

    for (const auto& groups : {nlohmann::json {"default", tooLong},
                               nlohmann::json::parse(R"(["default",1])"),
                               nlohmann::json::parse(R"(["default",null])"),
                               nlohmann::json::parse(R"(["default",["nested"]])"),
                               nlohmann::json::parse(R"("default")"),
                               nlohmann::json::parse(R"({"0":"default"})")})
    {
        const auto [document, dropped] = stamp(withAgent({{"groups", groups}}));
        EXPECT_EQ(1U, dropped) << groups.dump();
        EXPECT_EQ(nlohmann::json::array(), document["/wazuh/agent/groups"_json_pointer]) << groups.dump();
        EXPECT_EQ(emptyHost(), document["/wazuh/agent/host"_json_pointer]);
    }
}

TEST(ReportedAgentMetadataTest, AnEmptyGroupNameIsKeptLikeTheStatefulPath)
{
    const auto [document, dropped] = stamp(R"({"agent":{"groups":["default",""]}})");

    EXPECT_EQ(0U, dropped);
    EXPECT_EQ(nlohmann::json::parse(R"(["default",""])"), document["/wazuh/agent/groups"_json_pointer]);
}

TEST(ReportedAgentMetadataTest, EachBadHostStringIsEmptiedOnItsOwn)
{
    const std::string tooLong(invsync::common::MAX_AGENT_HOST_FIELD_BYTES + 1, 'h');
    const std::string atLimit(invsync::common::MAX_AGENT_HOST_FIELD_BYTES, 'h');

    auto payload = nlohmann::json::parse(kFullAgent);
    payload["/agent/host/hostname"_json_pointer] = tooLong;
    payload["/agent/host/architecture"_json_pointer] = atLimit;
    payload["/agent/host/os/version"_json_pointer] = 24.04;
    payload["/agent/host/os/type"_json_pointer] = nullptr;

    const auto [document, dropped] = stamp(payload);

    EXPECT_EQ(3U, dropped);
    const auto& host = document["/wazuh/agent/host"_json_pointer];
    EXPECT_EQ("", host.at("hostname"));
    EXPECT_EQ(atLimit, host.at("architecture").get<std::string>());
    EXPECT_EQ("", host.at("os").at("version"));
    EXPECT_EQ("", host.at("os").at("type"));
    EXPECT_EQ("Ubuntu", host.at("os").at("name"));
    EXPECT_EQ("ubuntu", host.at("os").at("platform"));
    EXPECT_EQ(nlohmann::json::parse(R"(["default","linux"])"), document["/wazuh/agent/groups"_json_pointer]);
}

TEST(ReportedAgentMetadataTest, AHostOrOsThatIsNotAnObjectIsEmptied)
{
    {
        const auto [document, dropped] = stamp(R"({"agent":{"groups":["g"],"host":"web-01"}})");
        EXPECT_EQ(1U, dropped);
        EXPECT_EQ(emptyHost(), document["/wazuh/agent/host"_json_pointer]);
        EXPECT_EQ(nlohmann::json::parse(R"(["g"])"), document["/wazuh/agent/groups"_json_pointer]);
    }
    {
        const auto [document, dropped] = stamp(R"({"agent":{"host":{"hostname":"web-01","os":["linux"]}}})");
        EXPECT_EQ(1U, dropped);
        auto expected = emptyHost();
        expected["hostname"] = "web-01";
        EXPECT_EQ(expected, document["/wazuh/agent/host"_json_pointer]);
    }
}

TEST(ReportedAgentMetadataTest, LeavesTheRestOfTheDocumentAlone)
{
    nlohmann::json document;
    document["/wazuh/agent/id"_json_pointer] = "001";
    document["/wazuh/cluster/name"_json_pointer] = "c";

    EXPECT_EQ(0U, stampReportedAgentMetadata(nlohmann::json::parse(kFullAgent), document));
    EXPECT_EQ("001", document["/wazuh/agent/id"_json_pointer]);
    EXPECT_EQ("c", document["/wazuh/cluster/name"_json_pointer]);
}
