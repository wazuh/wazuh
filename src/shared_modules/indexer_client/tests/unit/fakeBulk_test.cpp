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

// Self-tests of the fake's dynamic `_bulk` responder (plan 18, E3b-1 step 5, FakeBulkResponder): every mode is
// checked by parsing the answer the fake serves over HTTP.

#include "bulkResponder.hpp"
#include "fakeIndexer.hpp"
#include "json.hpp"

#include "httplib.h"
#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <future>
#include <memory>
#include <string>
#include <vector>

using indexer_client::testing::BulkItem;
using indexer_client::testing::BulkMode;
using indexer_client::testing::BulkResponder;
using indexer_client::testing::bulkRule;
using indexer_client::testing::BulkScript;
using indexer_client::testing::FakeIndexer;
using indexer_client::testing::Rule;
using namespace std::chrono_literals;

namespace
{
    // index (with id), create (without id), update, delete: the four actions of encoding.cpp.
    const std::string FOUR_OPS = R"({"index":{"_index":"logs","_id":"a"}})"
                                 "\n"
                                 R"({"x":1})"
                                 "\n"
                                 R"({"create":{"_index":"logs"}})"
                                 "\n"
                                 R"({"y":2})"
                                 "\n"
                                 R"({"update":{"_index":"states","_id":"c"}})"
                                 "\n"
                                 R"({"doc":{"z":3}})"
                                 "\n"
                                 R"({"delete":{"_index":"states","_id":"d"}})"
                                 "\n";

    std::string indexOps(std::size_t count)
    {
        std::string body;
        for (std::size_t i = 0; i < count; ++i)
        {
            body += R"({"index":{"_index":"logs","_id":"id-)" + std::to_string(i) +
                    "\"}}\n{\"n\":" + std::to_string(i) + "}\n";
        }
        return body;
    }

    class FakeBulkResponder : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            m_responder = std::make_shared<BulkResponder>();
            m_rule = m_fake.addRule(bulkRule(m_responder));
            m_fake.start();
        }

        httplib::Result post(const std::string& body, const std::string& path = "/_bulk")
        {
            httplib::Client client("127.0.0.1", m_fake.port());
            client.set_connection_timeout(5s);
            client.set_read_timeout(5s);
            return client.Post(path, body, "application/x-ndjson");
        }

        /// Posts @p body, expects @p status and returns the parsed items body.
        nlohmann::json postItems(const std::string& body, int status = 200)
        {
            const auto res = post(body);
            EXPECT_TRUE(res);
            if (!res)
            {
                return {};
            }
            EXPECT_EQ(res->status, status);
            auto parsed = nlohmann::json::parse(res->body, nullptr, false);
            EXPECT_FALSE(parsed.is_discarded()) << res->body;
            return parsed;
        }

        /// The single member of item @p i (whatever its key).
        static const nlohmann::json& inner(const nlohmann::json& body, std::size_t i)
        {
            return body.at("items").at(i).begin().value();
        }

        static std::string key(const nlohmann::json& body, std::size_t i)
        {
            return body.at("items").at(i).begin().key();
        }

        FakeIndexer m_fake;
        std::shared_ptr<BulkResponder> m_responder;
        std::size_t m_rule {0};
    };
} // namespace

TEST_F(FakeBulkResponder, DefaultIsOneSuccessPerOpWithTheRealShape)
{
    const auto body = postItems(FOUR_OPS);
    ASSERT_TRUE(body.is_object());
    ASSERT_TRUE(body.at("took").is_number_integer());
    EXPECT_EQ(body.at("errors"), false);
    ASSERT_EQ(body.at("items").size(), 4U);

    EXPECT_EQ(key(body, 0), "index");
    EXPECT_EQ(inner(body, 0).at("_index"), "logs");
    EXPECT_EQ(inner(body, 0).at("_id"), "a");
    EXPECT_EQ(inner(body, 0).at("status"), 201);
    EXPECT_EQ(inner(body, 0).at("result"), "created");
    EXPECT_EQ(inner(body, 0).at("_shards").at("successful"), 1);
    EXPECT_TRUE(inner(body, 0).contains("_seq_no"));

    EXPECT_EQ(key(body, 1), "create");
    EXPECT_EQ(inner(body, 1).at("status"), 201);
    EXPECT_EQ(inner(body, 1).at("result"), "created");
    EXPECT_FALSE(inner(body, 1).at("_id").get<std::string>().empty()); // auto id

    EXPECT_EQ(key(body, 2), "update");
    EXPECT_EQ(inner(body, 2).at("_index"), "states");
    EXPECT_EQ(inner(body, 2).at("status"), 200);
    EXPECT_EQ(inner(body, 2).at("result"), "updated");

    EXPECT_EQ(key(body, 3), "delete");
    EXPECT_EQ(inner(body, 3).at("_id"), "d");
    EXPECT_EQ(inner(body, 3).at("status"), 200);
    EXPECT_EQ(inner(body, 3).at("result"), "deleted");
    for (std::size_t i = 0; i < 4; ++i)
    {
        EXPECT_FALSE(inner(body, i).contains("error"));
    }

    const auto received = m_responder->received();
    ASSERT_EQ(received.size(), 1U);
    ASSERT_EQ(received[0].size(), 4U);
    EXPECT_EQ(received[0][0].action, "index");
    EXPECT_EQ(received[0][0].source, R"({"x":1})");
    EXPECT_FALSE(received[0][1].id.has_value());
    EXPECT_EQ(received[0][2].source, R"({"doc":{"z":3}})");
    EXPECT_EQ(received[0][3].action, "delete");
    EXPECT_TRUE(received[0][3].source.empty());
    EXPECT_EQ(m_fake.hits(m_rule), 1U);
}

TEST_F(FakeBulkResponder, IndexFromPathAndNoTrailingNewline)
{
    const auto res = post(R"({"index":{}})"
                          "\n"
                          R"({"a":1})",
                          "/my-index/_bulk");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 200);
    const auto body = nlohmann::json::parse(res->body);
    ASSERT_EQ(body.at("items").size(), 1U);
    EXPECT_EQ(inner(body, 0).at("_index"), "my-index");
}

TEST_F(FakeBulkResponder, ScriptByPositionWithCoherentErrors)
{
    m_responder->setDefault(BulkScript::items({
        {1, BulkItem::rejected()},
        {2,
         BulkItem::failed(400, "mapper_parsing_exception", "failed to parse field [n]")
             .causedBy("json_parse_exception", "Unexpected character")},
        {3, BulkItem::conflict()},
        {4, BulkItem::ok(200, "noop")},
        {5, BulkItem::failed(404, "index_not_found_exception", "no such index [logs]")},
        {6, BulkItem::failed(403, "cluster_block_exception")},
    }));
    const auto body = postItems(indexOps(8));
    ASSERT_EQ(body.at("items").size(), 8U);
    EXPECT_EQ(body.at("errors"), true);

    EXPECT_EQ(inner(body, 0).at("status"), 201);
    EXPECT_FALSE(inner(body, 0).contains("error"));

    EXPECT_EQ(inner(body, 1).at("status"), 429);
    EXPECT_EQ(inner(body, 1).at("error").at("type"), "es_rejected_execution_exception");
    EXPECT_FALSE(inner(body, 1).contains("result"));

    const auto& parsing = inner(body, 2).at("error");
    EXPECT_EQ(inner(body, 2).at("status"), 400);
    EXPECT_EQ(parsing.at("type"), "mapper_parsing_exception");
    EXPECT_EQ(parsing.at("reason"), "failed to parse field [n]");
    EXPECT_EQ(parsing.at("caused_by").at("type"), "json_parse_exception");
    EXPECT_EQ(parsing.at("caused_by").at("reason"), "Unexpected character");

    EXPECT_EQ(inner(body, 3).at("status"), 409);
    EXPECT_EQ(inner(body, 3).at("error").at("type"), "version_conflict_engine_exception");
    EXPECT_EQ(inner(body, 4).at("status"), 200);
    EXPECT_EQ(inner(body, 4).at("result"), "noop");
    EXPECT_EQ(inner(body, 5).at("error").at("type"), "index_not_found_exception");
    EXPECT_EQ(inner(body, 6).at("status"), 403);
    EXPECT_TRUE(inner(body, 6).at("error").contains("reason"));
    EXPECT_EQ(inner(body, 7).at("status"), 201);
    EXPECT_EQ(inner(body, 7).at("_id"), "id-7");
}

TEST_F(FakeBulkResponder, ErrorsFalseWhenNoItemFails)
{
    m_responder->setDefault(BulkScript::items({{0, BulkItem::notFound()}}));
    const auto body = postItems(R"({"delete":{"_index":"states","_id":"gone"}})"
                                "\n");
    ASSERT_EQ(body.at("items").size(), 1U);
    EXPECT_EQ(body.at("errors"), false);
    EXPECT_EQ(key(body, 0), "delete");
    EXPECT_EQ(inner(body, 0).at("status"), 404);
    EXPECT_EQ(inner(body, 0).at("result"), "not_found");
    EXPECT_FALSE(inner(body, 0).contains("error"));
}

TEST_F(FakeBulkResponder, ErrorsOverrideKeyOverrideAndMissingStatus)
{
    BulkItem bogus;
    bogus.key = "bogus";
    BulkItem noStatus;
    noStatus.omitStatus = true;
    auto script = BulkScript::items({{0, BulkItem::rejected()}, {1, bogus}, {2, noStatus}});
    script.errors = false; // an item fails, yet the body says it does not
    m_responder->setDefault(script);

    const auto body = postItems(indexOps(3));
    ASSERT_EQ(body.at("items").size(), 3U);
    EXPECT_EQ(body.at("errors"), false);
    EXPECT_EQ(inner(body, 0).at("status"), 429);
    EXPECT_EQ(key(body, 1), "bogus");
    EXPECT_EQ(inner(body, 1).at("status"), 201);
    EXPECT_EQ(key(body, 2), "index");
    EXPECT_FALSE(inner(body, 2).contains("status"));
}

TEST_F(FakeBulkResponder, AllItemsFromFallback)
{
    m_responder->setDefault(BulkScript::all(BulkItem::rejected()));
    const auto body = postItems(indexOps(3));
    ASSERT_EQ(body.at("items").size(), 3U);
    EXPECT_EQ(body.at("errors"), true);
    for (std::size_t i = 0; i < 3; ++i)
    {
        EXPECT_EQ(inner(body, i).at("status"), 429);
    }
}

TEST_F(FakeBulkResponder, OneItemTooManyOrTooFew)
{
    auto more = BulkScript::items();
    more.itemDelta = 1;
    auto fewer = BulkScript::items();
    fewer.itemDelta = -1;
    auto none = BulkScript::items();
    none.itemDelta = -10;
    m_responder->push(more);
    m_responder->push(fewer);
    m_responder->push(none);

    const auto extra = postItems(indexOps(3));
    ASSERT_EQ(extra.at("items").size(), 4U);
    EXPECT_EQ(inner(extra, 3).at("status"), 201);
    EXPECT_EQ(extra.at("errors"), false);

    const auto missing = postItems(indexOps(3));
    ASSERT_EQ(missing.at("items").size(), 2U);
    EXPECT_EQ(inner(missing, 1).at("_id"), "id-1");

    const auto empty = postItems(indexOps(3));
    EXPECT_TRUE(empty.at("items").empty());
}

TEST_F(FakeBulkResponder, UnreadableBody)
{
    m_responder->setDefault(BulkScript::unreadable());
    const auto res = post(indexOps(2));
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 200);
    EXPECT_FALSE(res->body.empty());
    EXPECT_EQ(res->body.front(), '{');
    EXPECT_TRUE(nlohmann::json::parse(res->body, nullptr, false).is_discarded()) << res->body;
}

TEST_F(FakeBulkResponder, WholeRequestAnswers)
{
    m_responder->push(BulkScript::tooLarge());
    m_responder->push(BulkScript::throttled("7"));
    m_responder->push(BulkScript::throttled());
    m_responder->push(BulkScript::serverError());
    m_responder->push(BulkScript::serverError(502));
    m_responder->push(BulkScript::unauthorized());

    const auto tooLarge = post(indexOps(2));
    ASSERT_TRUE(tooLarge);
    EXPECT_EQ(tooLarge->status, 413);
    EXPECT_TRUE(tooLarge->body.empty());

    const auto throttled = post(indexOps(2));
    ASSERT_TRUE(throttled);
    EXPECT_EQ(throttled->status, 429);
    EXPECT_EQ(throttled->get_header_value("Retry-After"), "7");
    const auto rejected = nlohmann::json::parse(throttled->body);
    EXPECT_EQ(rejected.at("error").at("type"), "es_rejected_execution_exception");
    EXPECT_FALSE(rejected.contains("items"));

    const auto bare = post(indexOps(2));
    ASSERT_TRUE(bare);
    EXPECT_EQ(bare->status, 429);
    EXPECT_FALSE(bare->has_header("Retry-After"));

    const auto unavailable = post(indexOps(2));
    ASSERT_TRUE(unavailable);
    EXPECT_EQ(unavailable->status, 503);
    EXPECT_EQ(nlohmann::json::parse(unavailable->body).at("status"), 503);

    const auto badGateway = post(indexOps(2));
    ASSERT_TRUE(badGateway);
    EXPECT_EQ(badGateway->status, 502);

    const auto unauthorized = post(indexOps(2));
    ASSERT_TRUE(unauthorized);
    EXPECT_EQ(unauthorized->status, 401);
    EXPECT_EQ(unauthorized->body, "Unauthorized");

    EXPECT_EQ(m_responder->queued(), 0U);
    EXPECT_EQ(m_responder->answered(), 6U);
    EXPECT_EQ(m_responder->opCount(), 12U);
}

TEST_F(FakeBulkResponder, QueuedScriptsThenDefault)
{
    m_responder->setDefault(BulkScript::all(BulkItem::conflict()));
    m_responder->push(BulkScript::throttled("1"));
    m_responder->push(BulkScript::items());

    EXPECT_EQ(post(indexOps(4))->status, 429);
    // The split halves of a retried batch: each gets its own items.
    const auto first = postItems(indexOps(2));
    EXPECT_EQ(first.at("items").size(), 2U);
    EXPECT_EQ(first.at("errors"), false);
    const auto second = postItems(indexOps(2));
    EXPECT_EQ(inner(second, 0).at("status"), 409);
    EXPECT_EQ(second.at("errors"), true);

    const auto received = m_responder->received();
    ASSERT_EQ(received.size(), 3U);
    EXPECT_EQ(received[0].size(), 4U);
    EXPECT_EQ(received[1].size(), 2U);
}

TEST_F(FakeBulkResponder, MalformedRequestIs400)
{
    m_responder->push(BulkScript::tooLarge()); // the parse error wins over any script
    const auto res = post(R"({"index":{"_index":"logs"}})"
                          "\n"
                          "not json\n");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 400);
    const auto body = nlohmann::json::parse(res->body);
    EXPECT_EQ(body.at("error").at("type"), "illegal_argument_exception");

    const auto unknown = post(R"({"upsert":{}})"
                              "\n");
    ASSERT_TRUE(unknown);
    EXPECT_EQ(unknown->status, 400);

    const auto missingSource = post(R"({"index":{}})"
                                    "\n");
    ASSERT_TRUE(missingSource);
    EXPECT_EQ(missingSource->status, 400);
}

TEST_F(FakeBulkResponder, HeldScriptWaitsForRelease)
{
    m_responder->push(BulkScript::items().held());
    auto pending = std::async(std::launch::async, [this] { return post(indexOps(1)); });
    ASSERT_TRUE(m_fake.waitHeld(1, 5s));
    EXPECT_EQ(pending.wait_for(50ms), std::future_status::timeout);
    m_fake.releaseHeld();
    const auto res = pending.get();
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 200);
    EXPECT_EQ(nlohmann::json::parse(res->body).at("items").size(), 1U);
}

TEST(FakeBulkResponderRules, CoexistsWithStaticRules)
{
    FakeIndexer fake;
    Rule throttle;
    throttle.method = "POST";
    throttle.pathRegex = "/_bulk";
    throttle.status = 429;
    throttle.retryAfter = "3";
    throttle.times = 1;
    const auto throttleIndex = fake.addRule(throttle);
    auto responder = std::make_shared<BulkResponder>();
    auto heldRule = bulkRule(responder);
    heldRule.times = 1;
    heldRule.hold = true; // the rule's own hold, as with any rule
    const auto heldIndex = fake.addRule(heldRule);
    const auto bulkIndex = fake.addRule(bulkRule(responder));
    Rule health;
    health.method = "GET";
    health.pathRegex = "/_cluster/health";
    health.body = R"({"status":"green"})";
    fake.addRule(health);
    fake.start();

    httplib::Client client("127.0.0.1", fake.port());
    client.set_read_timeout(5s);

    const auto throttled = client.Post("/_bulk", indexOps(1), "application/x-ndjson");
    ASSERT_TRUE(throttled);
    EXPECT_EQ(throttled->status, 429);
    EXPECT_EQ(throttled->get_header_value("Retry-After"), "3");
    EXPECT_EQ(responder->answered(), 0U);

    auto pending = std::async(std::launch::async,
                              [&fake]
                              {
                                  httplib::Client other("127.0.0.1", fake.port());
                                  other.set_read_timeout(5s);
                                  return other.Post("/_bulk", indexOps(2), "application/x-ndjson");
                              });
    ASSERT_TRUE(fake.waitHeld(1, 5s));
    fake.releaseHeld();
    const auto held = pending.get();
    ASSERT_TRUE(held);
    EXPECT_EQ(nlohmann::json::parse(held->body).at("items").size(), 2U);

    const auto plain = client.Post("/logs/_bulk", indexOps(3), "application/x-ndjson");
    ASSERT_TRUE(plain);
    EXPECT_EQ(nlohmann::json::parse(plain->body).at("items").size(), 3U);

    const auto healthRes = client.Get("/_cluster/health?local=true");
    ASSERT_TRUE(healthRes);
    EXPECT_EQ(healthRes->body, R"({"status":"green"})");

    const auto wrongMethod = client.Get("/_bulk");
    ASSERT_TRUE(wrongMethod);
    EXPECT_EQ(wrongMethod->body, "{}");

    EXPECT_EQ(fake.hits(throttleIndex), 1U);
    EXPECT_EQ(fake.hits(heldIndex), 1U);
    EXPECT_EQ(fake.hits(bulkIndex), 1U);
    EXPECT_EQ(responder->answered(), 2U);
}

TEST(FakeBulkResponderRender, ItemsWithoutHttp)
{
    const std::vector<indexer_client::testing::BulkOp> ops {{"index", "logs", std::string("a"), "{}"},
                                                            {"delete", "logs", std::string("b"), ""}};
    const auto body = nlohmann::json::parse(BulkResponder::renderItems(ops, BulkScript::items(), 10));
    ASSERT_EQ(body.at("items").size(), 2U);
    EXPECT_EQ(body.at("items")[0].at("index").at("_seq_no"), 10);
    EXPECT_EQ(body.at("items")[1].at("delete").at("result"), "deleted");
    EXPECT_EQ(BulkScript::unreadable().mode, BulkMode::Unreadable);
}
