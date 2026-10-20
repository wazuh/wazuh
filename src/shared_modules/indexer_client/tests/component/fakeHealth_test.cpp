/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

// Self-tests of the fake's health helpers (plan 18, E2b step 4): each healthRules.hpp helper answers the probe path
// with the exact status and body, rules swap while serving, a held probe waits for releaseHeld() and the probe
// counters see only `GET /_cluster/health`. Driven by cpp-httplib's own client; no runtime involved.

#include "fakeIndexer.hpp"
#include "healthRules.hpp"

#include "httplib.h"
#include "json.hpp"
#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <string>

using indexer_client::testing::Durability;
using indexer_client::testing::FakeIndexer;
using indexer_client::testing::healthBody;
using indexer_client::testing::healthErrorBody;
using indexer_client::testing::healthRule;
using indexer_client::testing::healthRuleInvalidJson;
using indexer_client::testing::healthRuleNonStringStatus;
using indexer_client::testing::healthRuleWithoutStatus;
using indexer_client::testing::healthStatusRule;
using indexer_client::testing::heldHealthRule;
using indexer_client::testing::lastProbeQuery;
using indexer_client::testing::probeCount;
using indexer_client::testing::Rule;
using indexer_client::testing::throttledBody;
using indexer_client::testing::throttledRule;
using indexer_client::testing::waitForProbes;
using namespace std::chrono_literals;

namespace
{
    constexpr const char* PROBE {"/_cluster/health?local=true"};

    class FakeHealthTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            m_fake.start();
        }

        httplib::Client client() const
        {
            httplib::Client c("127.0.0.1", m_fake.port());
            c.set_connection_timeout(5s);
            c.set_read_timeout(5s);
            return c;
        }

        /// GETs @p target and returns the response (fails the test on a transport error).
        httplib::Response get(const std::string& target = PROBE) const
        {
            auto c = client();
            auto result = c.Get(target);
            EXPECT_TRUE(result) << "transport error " << static_cast<int>(result.error());
            return result ? *result : httplib::Response {};
        }

        FakeIndexer m_fake;
    };

    TEST_F(FakeHealthTest, StatusStringsServedVerbatim)
    {
        for (const char* status : {"green", "yellow", "red", "unknown"})
        {
            m_fake.clearRules();
            m_fake.addRule(healthRule(status));
            const auto res = get();
            EXPECT_EQ(res.status, 200) << status;
            EXPECT_EQ(res.body, healthBody(status));
            const auto body = nlohmann::json::parse(res.body);
            ASSERT_TRUE(body.at("status").is_string());
            EXPECT_EQ(body.at("status").get<std::string>(), status);
            EXPECT_EQ(body.at("cluster_name"), "wazuh-cluster");
            EXPECT_EQ(body.at("timed_out"), false);
            EXPECT_EQ(body.at("number_of_nodes"), 1);
        }
    }

    TEST_F(FakeHealthTest, StatusIsJsonEscaped)
    {
        m_fake.addRule(healthRule("we\"ird\\"));
        const auto body = nlohmann::json::parse(get().body);
        EXPECT_EQ(body.at("status").get<std::string>(), "we\"ird\\");
    }

    TEST_F(FakeHealthTest, BadBodies)
    {
        m_fake.addRule(healthRuleWithoutStatus());
        auto res = get();
        EXPECT_EQ(res.status, 200);
        auto body = nlohmann::json::parse(res.body);
        EXPECT_FALSE(body.contains("status"));
        EXPECT_EQ(body.at("cluster_name"), "wazuh-cluster");

        m_fake.clearRules();
        m_fake.addRule(healthRuleNonStringStatus());
        res = get();
        EXPECT_EQ(res.status, 200);
        body = nlohmann::json::parse(res.body);
        ASSERT_TRUE(body.contains("status"));
        EXPECT_TRUE(body.at("status").is_number_integer());
        EXPECT_EQ(body.at("status"), 1);

        m_fake.clearRules();
        m_fake.addRule(healthRuleInvalidJson());
        res = get();
        EXPECT_EQ(res.status, 200);
        EXPECT_FALSE(nlohmann::json::accept(res.body));
    }

    TEST_F(FakeHealthTest, ErrorStatuses)
    {
        m_fake.addRule(healthStatusRule(401));
        auto res = get();
        EXPECT_EQ(res.status, 401);
        EXPECT_EQ(res.body, "Unauthorized");

        for (const int status : {403, 503, 404, 500})
        {
            m_fake.clearRules();
            m_fake.addRule(healthStatusRule(status));
            res = get();
            EXPECT_EQ(res.status, status);
            EXPECT_EQ(res.body, healthErrorBody(status));
            const auto body = nlohmann::json::parse(res.body);
            EXPECT_EQ(body.at("status"), status);
            EXPECT_TRUE(body.at("error").at("type").is_string());
        }
        EXPECT_EQ(nlohmann::json::parse(healthErrorBody(403)).at("error").at("type"), "security_exception");

        m_fake.clearRules();
        m_fake.addRule(healthStatusRule(502, "bad gateway"));
        res = get();
        EXPECT_EQ(res.status, 502);
        EXPECT_EQ(res.body, "bad gateway");
    }

    TEST_F(FakeHealthTest, Throttled429Shapes)
    {
        for (const auto durability : {Durability::Transient, Durability::Permanent})
        {
            const std::string expected = durability == Durability::Permanent ? "PERMANENT" : "TRANSIENT";
            for (const bool inRootCause : {false, true})
            {
                m_fake.clearRules();
                m_fake.addRule(throttledRule(durability, inRootCause));
                const auto res = get();
                EXPECT_EQ(res.status, 429);
                EXPECT_EQ(res.body, throttledBody(durability, inRootCause));
                const auto body = nlohmann::json::parse(res.body);
                ASSERT_TRUE(body.at("status").is_number_integer());
                EXPECT_EQ(body.at("status"), 429);
                const auto& error = body.at("error");
                EXPECT_EQ(error.at("type"), "circuit_breaking_exception");
                ASSERT_EQ(error.at("root_cause").size(), 1U);
                EXPECT_EQ(error.at("root_cause").at(0).at("durability"), expected);
                if (inRootCause)
                {
                    EXPECT_FALSE(error.contains("durability")) << "durability must be only in root_cause[0]";
                }
                else
                {
                    EXPECT_EQ(error.at("durability"), expected);
                }
            }
        }
    }

    TEST_F(FakeHealthTest, HotSwapGreenRedGreen)
    {
        for (const char* status : {"green", "red", "green"})
        {
            m_fake.clearRules();
            m_fake.addRule(healthRule(status));
            EXPECT_EQ(nlohmann::json::parse(get().body).at("status"), status);
        }
        EXPECT_EQ(probeCount(m_fake), 3U);
    }

    TEST_F(FakeHealthTest, HeldProbeWaitsForRelease)
    {
        m_fake.addRule(heldHealthRule("yellow"));
        auto pending = std::async(std::launch::async, [this] { return get(); });
        ASSERT_TRUE(m_fake.waitHeld(1, 5s));
        EXPECT_TRUE(waitForProbes(m_fake, 1, 5s)); // recorded on arrival, before the hold
        EXPECT_EQ(pending.wait_for(100ms), std::future_status::timeout);
        m_fake.releaseHeld();
        ASSERT_EQ(pending.wait_for(5s), std::future_status::ready);
        const auto res = pending.get();
        EXPECT_EQ(res.status, 200);
        EXPECT_EQ(nlohmann::json::parse(res.body).at("status"), "yellow");
        EXPECT_EQ(m_fake.heldNow(), 0U);
    }

    TEST_F(FakeHealthTest, ProbeCountAndQuery)
    {
        m_fake.addRule(healthRule("green"));
        EXPECT_EQ(probeCount(m_fake), 0U);
        EXPECT_FALSE(lastProbeQuery(m_fake).has_value());

        get(PROBE);
        get("/_cluster/health");
        get("/_cluster/health/wazuh-states"); // another path
        get("/_bulk");
        {
            auto c = client();
            c.Post("/_cluster/health", "{}", "application/json"); // another method
        }
        EXPECT_EQ(probeCount(m_fake), 2U);
        EXPECT_EQ(lastProbeQuery(m_fake), std::string {});

        get(PROBE);
        EXPECT_EQ(probeCount(m_fake), 3U);
        EXPECT_EQ(lastProbeQuery(m_fake), std::string("local=true"));
        EXPECT_TRUE(waitForProbes(m_fake, 3, 1s));
        EXPECT_FALSE(waitForProbes(m_fake, 4, 20ms));
    }

    TEST_F(FakeHealthTest, RuleMatchesOnlyGetOnProbePath)
    {
        const Rule rule = healthRule("green");
        EXPECT_EQ(rule.method, "GET");
        m_fake.addRule(rule);
        EXPECT_EQ(get("/_cluster/health/x").body, "{}"); // fallback 200 {}
        EXPECT_EQ(nlohmann::json::parse(get().body).at("status"), "green");
    }
} // namespace
