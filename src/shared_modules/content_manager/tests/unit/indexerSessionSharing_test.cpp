/*
 * Wazuh content manager - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Connector and thread multiplication was the cost that made linking this library into the Engine a
 * scaling problem rather than a non-event: a connector's constructor resolves credentials, merges CA
 * bundles, runs a synchronous health check against every host and starts its own health-monitor
 * thread — and the previous code built a fresh one per PIT operation. What keeps that bounded is the
 * rule asserted here: registrations that talk to the same indexer with the same credentials share
 * one session, and registrations that do not are kept apart.
 */

#include "contentModuleFacade.hpp"
#include "gtest/gtest.h"

#include <json.hpp>
#include <string>
#include <vector>

namespace
{

nlohmann::json baseConfig()
{
    return nlohmann::json {{"hosts", nlohmann::json::array({"https://a:9200", "https://b:9200"})},
                           {"username", "wazuh"},
                           {"password", "secret"},
                           {"ssl", {{"certificate_authorities", nlohmann::json::array({"/etc/ca.pem"})}}},
                           {"monitoring_interval_seconds", 10}};
}

std::string fingerprintOf(const nlohmann::json& config)
{
    return ContentModuleFacade::fingerprint(config);
}

} // namespace

TEST(IndexerSessionSharingTest, IdenticalConnectionSettingsShareASession)
{
    EXPECT_EQ(fingerprintOf(baseConfig()), fingerprintOf(baseConfig()));
}

TEST(IndexerSessionSharingTest, PerTopicQuerySettingsDoNotSplitTheSession)
{
    auto ruleset = baseConfig();
    ruleset["indices"] = nlohmann::json::array({"wazuh-threatintel-policies"});
    ruleset["pageSize"] = 100;
    ruleset["hashDocId"] = "__ioc_type_hashes__";

    auto ioc = baseConfig();
    ioc["index"] = "wazuh-threatintel-enrichments";
    ioc["pageSize"] = 1000;
    ioc["numSlices"] = 1;

    // The Engine's eight topics differ in what they query but not in where they query it. Splitting
    // the session on those would give each topic its own health monitor, which is the whole problem.
    EXPECT_EQ(fingerprintOf(ruleset), fingerprintOf(ioc));
}

TEST(IndexerSessionSharingTest, KeyOrderDoesNotMatter)
{
    nlohmann::json reordered;
    reordered["monitoring_interval_seconds"] = 10;
    reordered["ssl"] = nlohmann::json {{"certificate_authorities", nlohmann::json::array({"/etc/ca.pem"})}};
    reordered["password"] = "secret";
    reordered["username"] = "wazuh";
    reordered["hosts"] = nlohmann::json::array({"https://a:9200", "https://b:9200"});

    // Two equivalent configurations assembled differently must not end up with two sessions.
    EXPECT_EQ(fingerprintOf(reordered), fingerprintOf(baseConfig()));
}

TEST(IndexerSessionSharingTest, DifferentConnectionsAreKeptApart)
{
    struct Case
    {
        const char* what;
        nlohmann::json config;
    };

    auto otherHosts = baseConfig();
    otherHosts["hosts"] = nlohmann::json::array({"https://c:9200"});

    auto hostOrder = baseConfig();
    hostOrder["hosts"] = nlohmann::json::array({"https://b:9200", "https://a:9200"});

    auto otherUser = baseConfig();
    otherUser["username"] = "other";

    auto otherPassword = baseConfig();
    otherPassword["password"] = "rotated";

    auto otherCa = baseConfig();
    otherCa["ssl"]["certificate_authorities"] = nlohmann::json::array({"/etc/other-ca.pem"});

    auto otherMonitoring = baseConfig();
    otherMonitoring["monitoring_interval_seconds"] = 30;

    const std::vector<Case> cases {{"different hosts", otherHosts},
                                   // A session's monitor only knows the hosts it was built with, and
                                   // it is keyed by the list as given.
                                   {"different host order", hostOrder},
                                   {"different username", otherUser},
                                   {"rotated password", otherPassword},
                                   {"different CA bundle", otherCa},
                                   // Every connector on a session inherits that session's monitoring
                                   // period, so two registrations asking for different periods must
                                   // not be merged.
                                   {"different monitoring interval", otherMonitoring}};

    const auto base = fingerprintOf(baseConfig());
    for (const auto& testCase : cases)
    {
        EXPECT_NE(fingerprintOf(testCase.config), base) << testCase.what;
    }
}

TEST(IndexerSessionSharingTest, AbsentCredentialsAreNotTheSameAsEmptyOnes)
{
    auto withoutCredentials = baseConfig();
    withoutCredentials.erase("username");
    withoutCredentials.erase("password");

    auto withEmptyCredentials = baseConfig();
    withEmptyCredentials["username"] = "";
    withEmptyCredentials["password"] = "";

    EXPECT_NE(fingerprintOf(withoutCredentials), fingerprintOf(withEmptyCredentials));
    EXPECT_NE(fingerprintOf(withoutCredentials), fingerprintOf(baseConfig()));
}

TEST(IndexerSessionSharingTest, AServiceAccountTokenIsPartOfTheIdentity)
{
    auto tokenAuth = baseConfig();
    tokenAuth["service_account_token"] = "abc";

    auto otherToken = tokenAuth;
    otherToken["service_account_token"] = "def";

    EXPECT_NE(fingerprintOf(tokenAuth), fingerprintOf(baseConfig()));
    EXPECT_NE(fingerprintOf(tokenAuth), fingerprintOf(otherToken));
}
