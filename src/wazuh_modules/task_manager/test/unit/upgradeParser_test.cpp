/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "upgrade/requestParser.hpp"
#include "upgrade/responseBuilder.hpp"

#include <gtest/gtest.h>

#include <json.hpp>

#include <string>
#include <vector>

using namespace task_manager;
using namespace task_manager::upgrade;

namespace
{
    /// @brief A fixed "now" so the request_time window is exercised without depending on the clock.
    constexpr Timestamp NOW {1756800000};

    nlohmann::json minimalUpgradeBody()
    {
        return nlohmann::json {{"agents", {4, 5}}, {"request_time", NOW}};
    }

    nlohmann::json minimalCustomBody()
    {
        return nlohmann::json {
            {"agents", {4}}, {"request_time", NOW}, {"file_path", "/var/upgrade/wazuh_agent_v5.0.0_linux_x86_64.wpk"}};
    }
} // namespace

// ---- agents ------------------------------------------------------------------------------------

TEST(UpgradeParser, ReadsTheAgentList)
{
    const auto result {parseAgentIds(nlohmann::json {{"agents", {4, 5, 6}}})};

    ASSERT_TRUE(result.ok());
    EXPECT_EQ(*result.value, (std::vector<int> {4, 5, 6}));
}

TEST(UpgradeParser, AMissingOrEmptyAgentListIsARequiredParameterFailure)
{
    for (const auto& body : {nlohmann::json::object(),
                             nlohmann::json {{"agents", nlohmann::json::array()}},
                             nlohmann::json {{"agents", "not-an-array"}},
                             nlohmann::json {{"agents", 5}}})
    {
        const auto result {parseAgentIds(body)};
        EXPECT_FALSE(result.ok());
        EXPECT_EQ(result.failure.error, UpgradeError::ParsingRequiredParameter);
        // No custom message: the code's own text is what the caller sees.
        EXPECT_TRUE(result.failure.message.empty());
    }
}

TEST(UpgradeParser, ABadAgentIdRejectsTheWholeList)
{
    // Wire-format string, reproduced exactly. One unusable id fails the request rather than being
    // quietly dropped -- the caller asked for a specific set and gets told it was not understood.
    for (const auto& agents : {nlohmann::json::array({0}),
                               nlohmann::json::array({-1}),
                               nlohmann::json::array({"5"}),
                               nlohmann::json::array({5.5}),
                               nlohmann::json::array({4, 0})})
    {
        const auto result {parseAgentIds(nlohmann::json {{"agents", agents}})};
        EXPECT_FALSE(result.ok());
        EXPECT_EQ(result.failure.error, UpgradeError::TaskConfigurations);
        EXPECT_EQ(result.failure.message, "Agent id not recognized");
    }
}

// ---- upgrade body ---------------------------------------------------------------------------------

TEST(UpgradeParser, ReadsEveryRecognisedUpgradeParameter)
{
    auto body = minimalUpgradeBody();
    body["wpk_repo"] = "repo.example/wpk/";
    body["version"] = "v5.0.0";
    body["use_http"] = true;
    body["force_upgrade"] = true;
    body["package_type"] = "deb";

    const auto result {parseUpgradeRequest(body, NOW)};

    ASSERT_TRUE(result.ok());
    EXPECT_EQ(result.value->agentIds, (std::vector<int> {4, 5}));
    EXPECT_EQ(result.value->requestTime, NOW);
    EXPECT_EQ(result.value->wpkRepository, "repo.example/wpk/");
    EXPECT_EQ(result.value->customVersion, "v5.0.0");
    EXPECT_TRUE(result.value->useHttp);
    EXPECT_TRUE(result.value->forceUpgrade);
    EXPECT_EQ(result.value->packageType, "deb");
}

TEST(UpgradeParser, OmittedOptionalParametersTakeTheirDefaults)
{
    const auto result {parseUpgradeRequest(minimalUpgradeBody(), NOW)};

    ASSERT_TRUE(result.ok());
    EXPECT_TRUE(result.value->wpkRepository.empty());
    EXPECT_TRUE(result.value->customVersion.empty());
    EXPECT_TRUE(result.value->packageType.empty());
    EXPECT_FALSE(result.value->useHttp);
    EXPECT_FALSE(result.value->forceUpgrade);
}

TEST(UpgradeParser, IgnoresUnrecognisedParameters)
{
    // PRESERVED, NOT A BUG TO FIX. A misspelled "forse_upgrade" is accepted and the upgrade proceeds
    // unforced. Rejecting unknown keys would break a newer Server API talking to an older manager,
    // which is the direction that actually happens during a rolling upgrade.
    auto body = minimalUpgradeBody();
    body["forse_upgrade"] = true;
    body["origin"] = nlohmann::json {{"module", "api"}};

    const auto result {parseUpgradeRequest(body, NOW)};

    ASSERT_TRUE(result.ok());
    EXPECT_FALSE(result.value->forceUpgrade);
}

TEST(UpgradeParser, ReportsWrongTypesWithTheWireFormatStrings)
{
    struct TypeCase
    {
        const char* key;
        nlohmann::json value;
        const char* expected;
    };

    // Parenthesised, not braced: nlohmann::json{7} builds the ARRAY [7], which would exercise a
    // different branch than the scalar these cases mean to test.
    const std::vector<TypeCase> cases {
        {"request_time", nlohmann::json("soon"), "Parameter \"request_time\" should be a number"},
        {"wpk_repo", nlohmann::json(7), "Parameter \"wpk_repo\" should be a string"},
        {"version", nlohmann::json(true), "Parameter \"version\" should be a string"},
        {"use_http", nlohmann::json("yes"), "Parameter \"use_http\" should be true or false"},
        {"force_upgrade", nlohmann::json(1), "Parameter \"force_upgrade\" should be true or false"},
        {"package_type", nlohmann::json(7), "Parameter \"package_type\" should be a string"},
    };

    for (const auto& testCase : cases)
    {
        SCOPED_TRACE(testCase.key);

        auto body = minimalUpgradeBody();
        body[testCase.key] = testCase.value;

        const auto result {parseUpgradeRequest(body, NOW)};
        EXPECT_FALSE(result.ok());
        EXPECT_EQ(result.failure.error, UpgradeError::TaskConfigurations);
        EXPECT_EQ(result.failure.message, testCase.expected);
    }
}

TEST(UpgradeParser, PackageTypeAcceptsOnlyRpmAndDeb)
{
    for (const char* accepted : {"rpm", "deb"})
    {
        auto body = minimalUpgradeBody();
        body["package_type"] = accepted;
        EXPECT_TRUE(parseUpgradeRequest(body, NOW).ok()) << accepted;
    }

    auto body = minimalUpgradeBody();
    body["package_type"] = "msi";

    const auto result {parseUpgradeRequest(body, NOW)};
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.failure.message, "Invalid parameter \"package_type\", value should be \"rpm\" or \"deb\"");
}

TEST(UpgradeParser, RequestTimeIsMandatory)
{
    // It is the only source of the deterministic task id, which is what makes the same request
    // idempotent when every cluster node runs it.
    auto missing = minimalUpgradeBody();
    missing.erase("request_time");

    auto result {parseUpgradeRequest(missing, NOW)};
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.failure.error, UpgradeError::TaskConfigurations);
    EXPECT_EQ(result.failure.message, "Missing required parameter: request_time");

    // Zero was how the retired parser spelled "absent", so it keeps that message rather than the
    // window one it would otherwise get.
    auto zero = minimalUpgradeBody();
    zero["request_time"] = 0;

    result = parseUpgradeRequest(zero, NOW);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.failure.message, "Missing required parameter: request_time");
}

TEST(UpgradeParser, RequestTimeMustFallInTheSameWindowTheCreateRouteEnforces)
{
    // Without this, the same request would be admitted here and refused by /v1/tasks having already
    // resolved to the same deterministic id.
    auto future = minimalUpgradeBody();
    future["request_time"] = NOW + MAX_FUTURE_SKEW + 1;

    auto result {parseUpgradeRequest(future, NOW)};
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.failure.error, UpgradeError::ParsingRequiredParameter);
    EXPECT_EQ(result.failure.message, "Parameter \"request_time\" is in the future");

    auto old = minimalUpgradeBody();
    old["request_time"] = NOW - MAX_AGE - 1;

    result = parseUpgradeRequest(old, NOW);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.failure.message, "Parameter \"request_time\" is too old (>1 year)");

    // Both edges are inclusive.
    auto edge = minimalUpgradeBody();
    edge["request_time"] = NOW + MAX_FUTURE_SKEW;
    EXPECT_TRUE(parseUpgradeRequest(edge, NOW).ok());

    edge["request_time"] = NOW - MAX_AGE;
    EXPECT_TRUE(parseUpgradeRequest(edge, NOW).ok());
}

TEST(UpgradeParser, ANonObjectBodyIsARequiredParameterFailure)
{
    EXPECT_EQ(parseUpgradeRequest(nlohmann::json::array(), NOW).failure.error,
              UpgradeError::ParsingRequiredParameter);
    EXPECT_EQ(parseUpgradeCustomRequest(nlohmann::json {"nope"}, NOW).failure.error,
              UpgradeError::ParsingRequiredParameter);
}

// ---- upgrade-custom body --------------------------------------------------------------------------

TEST(UpgradeParser, ReadsTheCustomParameters)
{
    auto body = minimalCustomBody();
    body["installer"] = "custom.sh";

    const auto result {parseUpgradeCustomRequest(body, NOW)};

    ASSERT_TRUE(result.ok());
    EXPECT_EQ(result.value->agentIds, (std::vector<int> {4}));
    EXPECT_EQ(result.value->filePath, "/var/upgrade/wazuh_agent_v5.0.0_linux_x86_64.wpk");
    EXPECT_EQ(result.value->installer, "custom.sh");
}

TEST(UpgradeParser, TheCustomBodyHasNoForceOrVersion)
{
    // Both are silently ignored, like any other unrecognised key -- there is no `force` parameter on
    // /agents/upgrade_custom, which is why its https gate has no override.
    auto body = minimalCustomBody();
    body["force_upgrade"] = true;
    body["version"] = "v5.0.0";

    EXPECT_TRUE(parseUpgradeCustomRequest(body, NOW).ok());
}

// ---- the response envelope ------------------------------------------------------------------------

TEST(UpgradeResponse, MatchesTheRetiredEnvelopeByteForByte)
{
    // THE CONTRACT TEST. framework/wazuh/agent.py turns each data entry into `1810 + error` and
    // lifts `message` verbatim, because none of 1810..1828 exists in exception.py. Key names, key
    // ORDER and the redundant top-level `message` are all part of what the existing tavern suites
    // assert, and they must keep passing unmodified.
    const std::vector<AgentOutcome> outcomes {{4, UpgradeError::Success, ""}, {5, UpgradeError::UrlNotFound, ""}};

    EXPECT_EQ(buildResponse(UpgradeError::Success, outcomes),
              R"({"error":0,"data":[{"error":0,"message":"Success","agent":4},)"
              R"({"error":12,"message":"The repository is not reachable","agent":5}],"message":"Success"})");
}

TEST(UpgradeResponse, AParseFailureCarriesItsCustomTextOnlyInTheDataEntry)
{
    // Two levels, and they differ on purpose: the data entry carries the specific complaint, the
    // envelope carries the code's generic text.
    EXPECT_EQ(buildFailureResponse(UpgradeError::TaskConfigurations, "Parameter \"version\" should be a string"),
              R"({"error":3,"data":[{"error":3,"message":"Parameter \"version\" should be a string"}],)"
              R"("message":"JSON parameter not recognized"})");
}

TEST(UpgradeResponse, WithoutACustomTextBothLevelsShowTheCodesOwnMessage)
{
    EXPECT_EQ(buildFailureResponse(UpgradeError::ParsingRequiredParameter, ""),
              R"({"error":2,"data":[{"error":2,)"
              R"("message":"Required parameters in json message where not found"}],)"
              R"("message":"Required parameters in json message where not found"})");
}

TEST(UpgradeResponse, AUniformFailureStillReportsOneEntryPerAgent)
{
    // A store rollback or a shutdown affects the whole batch, but the caller still needs to reconcile
    // against what it sent. Note the envelope stays Success: the retired code reported the top-level
    // code as Success for anything it answered per agent, and the Server API only reads the entries.
    EXPECT_EQ(buildUniformResponse(UpgradeError::TaskManagerCommunication, {4, 5}),
              R"({"error":0,"data":[{"error":4,"message":"Task manager communication error","agent":4},)"
              R"({"error":4,"message":"Task manager communication error","agent":5}],"message":"Success"})");
}

TEST(UpgradeResponse, TaskManagerFailureHasADeliberatelyEmptyMessage)
{
    // Code 5 reserved a slot for text the task manager would supply. Nothing ever supplied any; it
    // is kept only so the numbering above it does not shift.
    EXPECT_STREQ(errorMessage(UpgradeError::TaskManagerFailure), "");
    EXPECT_EQ(buildResponse(UpgradeError::Success, {{4, UpgradeError::TaskManagerFailure, ""}}),
              R"({"error":0,"data":[{"error":5,"message":"","agent":4}],"message":"Success"})");
}

TEST(UpgradeResponse, TheNumericValuesAreFrozen)
{
    // These are wire format; the Server API classifies three of them by literal value. Appending is
    // fine, renumbering is not.
    EXPECT_EQ(errorValue(UpgradeError::Success), 0);
    EXPECT_EQ(errorValue(UpgradeError::TaskManagerCommunication), 4);
    EXPECT_EQ(errorValue(UpgradeError::GlobalDbFailure), 6);
    EXPECT_EQ(errorValue(UpgradeError::UnknownError), 17);
    // Appended AFTER UnknownError precisely so that value never moved.
    EXPECT_EQ(errorValue(UpgradeError::LegacyDeliveryDisabled), 18);
}
