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

#include "fakeIndexer.hpp"

#include "httplib.h"
#include <gtest/gtest.h>

#include <chrono>
#include <string>

using indexer_client::testing::FakeIndexer;
using indexer_client::testing::Rule;

namespace
{
    httplib::Client makeClient(const FakeIndexer& fake)
    {
        httplib::Client client("127.0.0.1", fake.port());
        client.set_connection_timeout(std::chrono::seconds(5));
        client.set_read_timeout(std::chrono::seconds(5));
        client.set_keep_alive(true);
        return client;
    }

    std::string headerValue(const httplib::Headers& headers, const std::string& key)
    {
        const auto it = headers.find(key); // case-insensitive comparator
        return it == headers.end() ? std::string {} : it->second;
    }
} // namespace

TEST(FakeIndexerTest, RulesApply)
{
    FakeIndexer fake;

    Rule throttle;
    throttle.method = "POST";
    throttle.pathRegex = "/_bulk";
    throttle.status = 429;
    throttle.body = R"({"error":"too many requests"})";
    throttle.retryAfter = "3";
    fake.addRule(throttle);

    Rule slow;
    slow.method = "GET";
    slow.pathRegex = "/slow/.*";
    slow.latency = std::chrono::milliseconds(50);
    slow.body = R"({"slow":true})";
    fake.addRule(slow);

    ASSERT_GT(fake.start(), 0);
    auto client = makeClient(fake);

    const auto throttled = client.Post("/_bulk", "{}\n", "application/x-ndjson");
    ASSERT_TRUE(throttled);
    EXPECT_EQ(throttled->status, 429);
    EXPECT_EQ(throttled->get_header_value("Retry-After"), "3");
    EXPECT_EQ(throttled->body, R"({"error":"too many requests"})");

    const auto begin = std::chrono::steady_clock::now();
    const auto delayed = client.Get("/slow/x");
    const auto elapsed = std::chrono::steady_clock::now() - begin;
    ASSERT_TRUE(delayed);
    EXPECT_EQ(delayed->status, 200);
    EXPECT_FALSE(delayed->has_header("Retry-After"));
    EXPECT_EQ(delayed->body, R"({"slow":true})");
    EXPECT_GE(elapsed, std::chrono::milliseconds(50));

    // No rule matches: default 200 {}.
    const auto fallback = client.Get("/_cat/health");
    ASSERT_TRUE(fallback);
    EXPECT_EQ(fallback->status, 200);
    EXPECT_EQ(fallback->body, "{}");
    EXPECT_FALSE(fallback->has_header("Retry-After"));

    // Method mismatch falls through too.
    const auto wrongMethod = client.Get("/_bulk");
    ASSERT_TRUE(wrongMethod);
    EXPECT_EQ(wrongMethod->status, 200);
}

TEST(FakeIndexerTest, TimesLimitsRule)
{
    FakeIndexer fake;

    Rule twice;
    twice.pathRegex = "/_bulk";
    twice.status = 503;
    twice.times = 2;
    const auto twiceIndex = fake.addRule(twice);

    Rule fallback;
    fallback.pathRegex = "/_bulk";
    fallback.status = 201;
    const auto fallbackIndex = fake.addRule(fallback);

    fake.start();
    auto client = makeClient(fake);

    for (int i = 0; i < 2; ++i)
    {
        const auto res = client.Post("/_bulk", "x", "application/x-ndjson");
        ASSERT_TRUE(res);
        EXPECT_EQ(res->status, 503);
    }
    for (int i = 0; i < 3; ++i)
    {
        const auto res = client.Post("/_bulk", "x", "application/x-ndjson");
        ASSERT_TRUE(res);
        EXPECT_EQ(res->status, 201);
    }
    EXPECT_EQ(fake.hits(twiceIndex), 2U);
    EXPECT_EQ(fake.hits(fallbackIndex), 3U);

    fake.clearRules();
    const auto res = client.Post("/_bulk", "x", "application/x-ndjson");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 200);
    EXPECT_EQ(res->body, "{}");
}

TEST(FakeIndexerTest, RecordsRequests)
{
    FakeIndexer fake;
    fake.start();
    auto client = makeClient(fake);

    ASSERT_TRUE(client.Put("/idx/_doc/1?refresh=true", R"({"a":1})", "application/json"));
    ASSERT_TRUE(client.Delete("/idx/_doc/2"));
    ASSERT_TRUE(client.Get("/_cluster/health", httplib::Headers {{"X-Test", "yes"}}));

    const auto recorded = fake.requests();
    ASSERT_EQ(recorded.size(), 3U);
    EXPECT_EQ(fake.requestCount(), 3U);

    EXPECT_EQ(recorded[0].method, "PUT");
    EXPECT_EQ(recorded[0].path, "/idx/_doc/1");
    EXPECT_EQ(recorded[0].target, "/idx/_doc/1?refresh=true");
    EXPECT_EQ(recorded[0].body, R"({"a":1})");
    EXPECT_EQ(headerValue(recorded[0].headers, "Content-Type"), "application/json");

    EXPECT_EQ(recorded[1].method, "DELETE");
    EXPECT_EQ(recorded[1].path, "/idx/_doc/2");
    EXPECT_TRUE(recorded[1].body.empty());

    EXPECT_EQ(recorded[2].method, "GET");
    EXPECT_EQ(recorded[2].path, "/_cluster/health");
    EXPECT_EQ(headerValue(recorded[2].headers, "X-Test"), "yes");

    fake.clearRequests();
    EXPECT_EQ(fake.requestCount(), 0U);

    // stop() is idempotent; the destructor stops again.
    fake.stop();
    fake.stop();
}

TEST(FakeIndexerTest, StopWithoutStart)
{
    FakeIndexer fake;
    fake.stop();
    EXPECT_EQ(fake.port(), 0);
}
