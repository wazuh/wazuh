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

// The `_bulk` response classifier: the request table over an
// HttpResult and the item table over the bodies the fake's `_bulk` responder renders the way OpenSearch does, plus the
// transport's padding of a real response body.

#include <chrono>
#include <future>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "bulkResponder.hpp"
#include "componentFixture.hpp"
#include "fakeIndexer.hpp"
#include "testing/hooks.hpp"
#include "write/response.hpp"

using indexer_client::testing::BulkItem;
using indexer_client::testing::BulkResponder;
using indexer_client::testing::bulkRule;
using indexer_client::testing::BulkScript;
using indexer_client::testing::FakeIndexer;
namespace ic = indexer_client;
namespace wr = indexer_client::detail::write;
using ic::detail::HttpResult;
using ic::detail::TransportCause;
using wr::ItemVerdict;
using wr::RequestVerdict;
using namespace std::chrono_literals;

namespace
{
    const char* name(RequestVerdict verdict)
    {
        switch (verdict)
        {
            case RequestVerdict::Items: return "Items";
            case RequestVerdict::Failover: return "Failover";
            case RequestVerdict::Retry: return "Retry";
            case RequestVerdict::Throttled: return "Throttled";
            case RequestVerdict::Split: return "Split";
            case RequestVerdict::FailBatch: return "FailBatch";
            case RequestVerdict::Ignore: return "Ignore";
        }
        return "?";
    }

    const char* name(ItemVerdict verdict)
    {
        switch (verdict)
        {
            case ItemVerdict::Ok: return "Ok";
            case ItemVerdict::NotFound: return "NotFound";
            case ItemVerdict::Retry: return "Retry";
            case ItemVerdict::Conflict: return "Conflict";
            case ItemVerdict::Permanent: return "Permanent";
        }
        return "?";
    }

    /// One op line per action, in order: the NDJSON a client sends (encoding.cpp's four actions).
    std::string ndjson(const std::vector<std::string>& actions)
    {
        std::string body;
        for (std::size_t i = 0; i < actions.size(); ++i)
        {
            const auto& action = actions[i];
            body +=
                "{\"" + action + "\":{\"_index\":\"wazuh-states-test\",\"_id\":\"id-" + std::to_string(i) + "\"}}\n";
            if (action == "update")
            {
                body += "{\"doc\":{\"n\":" + std::to_string(i) + "}}\n";
            }
            else if (action != "delete")
            {
                body += "{\"n\":" + std::to_string(i) + "}\n";
            }
        }
        return body;
    }

    /// The body the fake serves for `script` over these ops (exactly what an OpenSearch 2xx `_bulk` answer holds).
    std::string served(const BulkScript& script, const std::vector<std::string>& actions)
    {
        BulkResponder responder(script);
        auto reply = responder.answer("/_bulk", ndjson(actions));
        EXPECT_EQ(reply.status, script.status);
        return std::move(reply.body);
    }

    /// The fake's whole-request answer as the transport would hand it over.
    HttpResult fromReply(const BulkScript& script)
    {
        BulkResponder responder(script);
        auto reply = responder.answer("/_bulk", ndjson({"index"}));
        HttpResult result;
        result.status = reply.status;
        result.body = std::move(reply.body);
        return result;
    }

    HttpResult status(long code, std::string body = {})
    {
        HttpResult result;
        result.status = code;
        result.body = std::move(body);
        return result;
    }

    HttpResult transport(TransportCause cause, bool attributable, bool mayHaveSent, int curlCode)
    {
        HttpResult result;
        result.cause = cause;
        result.nodeAttributable = attributable;
        result.mayHaveSent = mayHaveSent;
        result.curlCode = curlCode;
        return result;
    }

    struct RequestRow final
    {
        const char* what;
        HttpResult result;
        std::size_t batch;
        RequestVerdict verdict;
        ic::Cause cause;
    };

    struct ItemRow final
    {
        ItemVerdict verdict;
        ic::ItemOutcome outcome;
        int status;
        std::string type;
    };

    void expectItems(const std::optional<std::vector<wr::ItemResult>>& got,
                     const std::vector<ItemRow>& expected,
                     const std::string& body)
    {
        ASSERT_TRUE(got.has_value()) << body;
        ASSERT_EQ(got->size(), expected.size()) << body;
        for (std::size_t i = 0; i < expected.size(); ++i)
        {
            const auto& item = (*got)[i];
            EXPECT_EQ(item.verdict, expected[i].verdict)
                << "item " << i << ": " << name(item.verdict) << " vs " << name(expected[i].verdict) << "\n"
                << body;
            EXPECT_EQ(item.outcome, expected[i].outcome) << "item " << i << "\n" << body;
            EXPECT_EQ(item.httpStatus, expected[i].status) << "item " << i;
            EXPECT_EQ(item.itemErrorType, expected[i].type) << "item " << i;
        }
    }
} // namespace

// Every transport cause and every status of the request table gets its verdict and the op's lastCause;
// retryAfter, mayHaveSent and httpStatus travel unchanged. Includes Ignore, 3xx, 408, a request-level 409, 401/403
// (retried, unlike the other 4xx) and 413 / ResponseTooLarge with one op and with several.
TEST(ClassifyTest, ClassifyRequestMatrix)
{
    using C = ic::Cause;
    using V = RequestVerdict;
    const std::vector<RequestRow> rows {
        {"timeout", transport(TransportCause::Timeout, true, true, 28), 3, V::Failover, C::TransportTimeout},
        {"connect", transport(TransportCause::Connect, true, false, 7), 3, V::Failover, C::TransportConnect},
        {"send", transport(TransportCause::SendError, true, true, 55), 3, V::Failover, C::TransportConnect},
        {"recv", transport(TransportCause::RecvError, true, true, 56), 3, V::Failover, C::TransportConnect},
        {"partial", transport(TransportCause::PartialResponse, true, true, 18), 3, V::Failover, C::TransportConnect},
        {"tls", transport(TransportCause::Tls, true, false, 60), 3, V::Failover, C::TransportTls},
        {"tls config", transport(TransportCause::TlsConfig, false, false, 58), 3, V::Retry, C::TransportTls},
        {"local", transport(TransportCause::LocalError, false, false, 27), 3, V::Retry, C::InvalidState},
        {"cancelled", transport(TransportCause::Cancelled, false, true, 0), 3, V::Ignore, C::Cancelled},
        {"shutdown", transport(TransportCause::Shutdown, false, true, 0), 3, V::Ignore, C::Shutdown},
        {"response too large n",
         transport(TransportCause::ResponseTooLarge, false, true, 23),
         3,
         V::Split,
         C::ItemPermanent},
        {"response too large 1",
         transport(TransportCause::ResponseTooLarge, false, true, 23),
         1,
         V::FailBatch,
         C::ItemPermanent},
        {"200", status(200), 3, V::Items, C::None},
        {"201", status(201), 3, V::Items, C::None},
        {"299", status(299), 3, V::Items, C::None},
        {"429", fromReply(BulkScript::throttled("2")), 3, V::Throttled, C::Throttled},
        {"413 n", fromReply(BulkScript::tooLarge()), 3, V::Split, C::PayloadTooLarge},
        {"413 1", fromReply(BulkScript::tooLarge()), 1, V::FailBatch, C::PayloadTooLarge},
        {"408", status(408), 3, V::Retry, C::TransportTimeout},
        {"500", status(500), 3, V::Retry, C::Server5xx},
        {"502", status(502), 3, V::Retry, C::Server5xx},
        {"503", fromReply(BulkScript::serverError()), 3, V::Retry, C::Server5xx},
        {"504", fromReply(BulkScript::serverError(504)), 3, V::Retry, C::Server5xx},
        {"599", status(599), 3, V::Retry, C::Server5xx},
        {"401", fromReply(BulkScript::unauthorized()), 3, V::Retry, C::Client4xx},
        {"403", status(403, R"({"error":"no permissions"})"), 3, V::Retry, C::Client4xx},
        {"301", status(301), 3, V::FailBatch, C::Client4xx},
        {"302", status(302), 3, V::FailBatch, C::Client4xx},
        {"307", status(307), 3, V::FailBatch, C::Client4xx},
        {"409 request", fromReply(BulkScript::request(409, R"({"error":"conflict"})")), 3, V::FailBatch, C::Client4xx},
        {"400", status(400), 3, V::FailBatch, C::Client4xx},
        {"404", status(404), 3, V::FailBatch, C::Client4xx},
        {"422", status(422), 3, V::FailBatch, C::Client4xx},
    };
    for (const auto& row : rows)
    {
        const auto out = wr::classifyRequest(row.result, row.batch);
        EXPECT_EQ(out.verdict, row.verdict) << row.what << ": " << name(out.verdict) << " vs " << name(row.verdict);
        if (row.verdict != V::Items)
        {
            EXPECT_EQ(out.cause, row.cause) << row.what << ": " << ic::toString(out.cause);
        }
        EXPECT_EQ(out.httpStatus, static_cast<int>(row.result.status)) << row.what;
        EXPECT_EQ(out.mayHaveSent, row.result.mayHaveSent) << row.what;
        EXPECT_LE(out.reason.size(), ic::OpResult::MAX_REASON) << row.what;
    }

    // The exact reasons the sender carries into Failed / lastReason.
    EXPECT_EQ(wr::classifyRequest(status(301), 3).reason, "unexpected 3xx: HTTP 301");
    EXPECT_EQ(wr::classifyRequest(fromReply(BulkScript::unauthorized()), 3).reason, "HTTP 401: Unauthorized");
    EXPECT_EQ(wr::classifyRequest(transport(TransportCause::ResponseTooLarge, false, true, 23), 1).reason,
              "response over maxResponseBytes");
    EXPECT_EQ(wr::classifyRequest(transport(TransportCause::LocalError, false, false, 27), 3).reason,
              "local_error (curl 27)");

    // Retry-After travels with a 429 (parsed by the transport), and is absent when the server sent none.
    auto throttled = fromReply(BulkScript::throttled("2"));
    throttled.retryAfter = ic::Duration {2000};
    EXPECT_EQ(wr::classifyRequest(throttled, 3).retryAfter, ic::Duration {2000});
    EXPECT_FALSE(wr::classifyRequest(fromReply(BulkScript::throttled()), 3).retryAfter.has_value());

    // A status outside the table (1xx as final, >= 600, 0 without a transport cause) is retried, never dropped.
    for (const long code : {100L, 600L, 0L})
    {
        EXPECT_EQ(wr::classifyRequest(status(code), 3).verdict, V::Retry) << code;
    }
}

// Every row of the item table, over the bodies the fake renders as OpenSearch does: the four keys,
// `outcome` from `result`, the retryable errors, the conflict, the permanent ones, and "malformed item" for an item
// without a known key or without `status`. The same verdicts with `"errors":false` (never used to skip items).
TEST(ClassifyTest, ClassifyItemsMatrix)
{
    using O = ic::ItemOutcome;
    using V = ItemVerdict;
    const std::vector<std::string> actions {"index",
                                            "create",
                                            "update",
                                            "update",
                                            "delete",
                                            "index",
                                            "create",
                                            "index",
                                            "update",
                                            "index",
                                            "index",
                                            "delete",
                                            "index",
                                            "index",
                                            "create",
                                            "update"};
    BulkItem bogusKey;
    bogusKey.key = "bogus";
    BulkItem noStatus;
    noStatus.omitStatus = true;
    BulkItem noStatusDelete;
    noStatusDelete.omitStatus = true;
    noStatusDelete.result = "deleted";

    const std::map<std::size_t, BulkItem> positions {
        {0, BulkItem::ok()},                                                      // index 201 created
        {1, BulkItem::ok(201, "created")},                                        // create 201 created
        {2, BulkItem::ok()},                                                      // update 200 updated
        {3, BulkItem::ok(200, "noop")},                                           // update 200 noop
        {4, BulkItem::ok()},                                                      // delete 200 deleted
        {5, BulkItem::ok(200, "updated")},                                        // index over an existing doc
        {6, BulkItem::rejected()},                                                // 429
        {7, BulkItem::failed(503, "unavailable_shards_exception")},               // 5xx
        {8, BulkItem::failed(403, "cluster_block_exception", "index read-only")}, // blocked
        {9,
         BulkItem::failed(400, "mapper_parsing_exception", "failed to parse")
             .causedBy("json_parse_exception", "Unexpected character")}, // 4xx
        {10, BulkItem::conflict()},                                      // 409
        {11, noStatusDelete},                                            // no status
        {12, bogusKey},                                                  // unknown key
        {13, noStatus},                                                  // no status
        {14, BulkItem::failed(404, "index_not_found_exception", "no such index [x]")},
        {15, BulkItem::failed(429, "es_rejected_execution_exception")},
    };
    const std::vector<ItemRow> expected {
        {V::Ok, O::Created, 201, ""},
        {V::Ok, O::Created, 201, ""},
        {V::Ok, O::Updated, 200, ""},
        {V::Ok, O::Noop, 200, ""},
        {V::Ok, O::Deleted, 200, ""},
        {V::Ok, O::Updated, 200, ""},
        {V::Retry, O::None, 429, "es_rejected_execution_exception"},
        {V::Retry, O::None, 503, "unavailable_shards_exception"},
        {V::Retry, O::None, 403, "cluster_block_exception"},
        {V::Permanent, O::None, 400, "mapper_parsing_exception"},
        {V::Conflict, O::None, 409, "version_conflict_engine_exception"},
        {V::Permanent, O::None, 0, ""},
        {V::Permanent, O::None, 0, ""},
        {V::Permanent, O::None, 0, ""},
        {V::Permanent, O::None, 404, "index_not_found_exception"},
        {V::Retry, O::None, 429, "es_rejected_execution_exception"},
    };

    for (const std::optional<bool> errors : {std::optional<bool> {}, std::optional<bool> {false}})
    {
        SCOPED_TRACE(errors ? "errors:false" : "errors coherent (true)");
        auto script = BulkScript::items(positions);
        script.errors = errors;
        auto body = served(script, actions);
        ASSERT_NE(body.find(errors ? R"("errors":false)" : R"("errors":true)"), std::string::npos) << body;
        const auto got = wr::classifyItems(body, actions.size());
        expectItems(got, expected, body);
        if (got && got->size() == expected.size())
        {
            for (const std::size_t i : {11U, 12U, 13U})
            {
                EXPECT_EQ((*got)[i].reason, "malformed item") << "item " << i;
            }
            EXPECT_EQ((*got)[9].reason, "failed to parse; caused by json_parse_exception: Unexpected character");
        }
    }

    // A clean answer (`errors:false`, every item a success) of each key still yields each item's outcome.
    auto body =
        served(BulkScript::items({{3, BulkItem::ok(200, "noop")}}), {"index", "create", "update", "update", "delete"});
    ASSERT_NE(body.find(R"("errors":false)"), std::string::npos) << body;
    expectItems(wr::classifyItems(body, 5),
                {{V::Ok, O::Created, 201, ""},
                 {V::Ok, O::Created, 201, ""},
                 {V::Ok, O::Updated, 200, ""},
                 {V::Ok, O::Noop, 200, ""},
                 {V::Ok, O::Deleted, 200, ""}},
                body);

    // The key does not have to match the op (position rules): an `index` item answering a `create` op is classified.
    BulkItem crossKey = BulkItem::ok(201, "created");
    crossKey.key = "index";
    body = served(BulkScript::items({{0, crossKey}}), {"create"});
    expectItems(wr::classifyItems(body, 1), {{V::Ok, O::Created, 201, ""}}, body);
}

// A delete of a missing document (404 `not_found` without `error`) is NotFound; a 404 with
// `index_not_found_exception` is Permanent, and so is a 404 `not_found` of a non-delete op.
TEST(ClassifyTest, ClassifyDeleteNotFound)
{
    BulkItem indexNotFound = BulkItem::notFound();
    indexNotFound.result = "not_found";
    auto body = served(BulkScript::items({{0, BulkItem::notFound()},
                                          {1, BulkItem::failed(404, "index_not_found_exception", "no such index")},
                                          {2, indexNotFound},
                                          {3, BulkItem::notFound()}}),
                       {"delete", "delete", "index", "delete"});
    ASSERT_NE(body.find(R"("result":"not_found")"), std::string::npos) << body;
    const auto got = wr::classifyItems(body, 4);
    expectItems(got,
                {{ItemVerdict::NotFound, ic::ItemOutcome::NotFound, 404, ""},
                 {ItemVerdict::Permanent, ic::ItemOutcome::None, 404, "index_not_found_exception"},
                 {ItemVerdict::Permanent, ic::ItemOutcome::None, 404, ""},
                 {ItemVerdict::NotFound, ic::ItemOutcome::NotFound, 404, ""}},
                body);
    if (got && got->size() == 4)
    {
        EXPECT_EQ((*got)[1].reason, "no such index");
    }
}

// A 409 with version_conflict_engine_exception is a Conflict that keeps its status, type and reason (the bucket's
// ConflictPolicy decides); a 409 of any other type, or without an error, is Permanent.
TEST(ClassifyTest, ClassifyConflict)
{
    BulkItem bare;
    bare.status = 409;
    auto body = served(BulkScript::items({{0, BulkItem::conflict()},
                                          {1, BulkItem::failed(409, "resource_already_exists_exception", "exists")},
                                          {2, bare},
                                          {3, BulkItem::conflict().causedBy("engine_exception", "seq_no")}}),
                       {"create", "index", "index", "update"});
    const auto got = wr::classifyItems(body, 4);
    expectItems(got,
                {{ItemVerdict::Conflict, ic::ItemOutcome::None, 409, "version_conflict_engine_exception"},
                 {ItemVerdict::Permanent, ic::ItemOutcome::None, 409, "resource_already_exists_exception"},
                 {ItemVerdict::Permanent, ic::ItemOutcome::None, 409, ""},
                 {ItemVerdict::Conflict, ic::ItemOutcome::None, 409, "version_conflict_engine_exception"}},
                body);
    if (got && got->size() == 4)
    {
        EXPECT_EQ((*got)[0].reason, "[1]: version conflict, document already exists (current version [1])");
        EXPECT_EQ((*got)[3].reason,
                  "[1]: version conflict, document already exists (current version [1]); caused by "
                  "engine_exception: seq_no");
    }
}

// An unreadable 2xx body, or one with an item too many or too few, is nullopt (the sender retries it); a body without
// spare capacity (capacity() == size()) is still parsed, and its content is unchanged.
TEST(ClassifyTest, ClassifyUnreadableOrMismatch)
{
    const std::vector<std::string> two {"index", "delete"};
    auto unreadable = served(BulkScript::unreadable(), two);
    EXPECT_FALSE(wr::classifyItems(unreadable, 2).has_value()) << unreadable;

    auto more = BulkScript::items();
    more.itemDelta = 1;
    auto moreBody = served(more, two);
    EXPECT_FALSE(wr::classifyItems(moreBody, 2).has_value()) << "one item too many: " << moreBody;

    auto fewer = BulkScript::items();
    fewer.itemDelta = -1;
    auto fewerBody = served(fewer, two);
    EXPECT_FALSE(wr::classifyItems(fewerBody, 2).has_value()) << "one item too few: " << fewerBody;
    auto none = BulkScript::items();
    none.itemDelta = -2;
    auto noneBody = served(none, two);
    EXPECT_FALSE(wr::classifyItems(noneBody, 2).has_value()) << "no item: " << noneBody;

    for (std::string broken : {std::string(),
                               std::string("{"),
                               std::string("[]"),
                               std::string(R"({"items":5})"),
                               std::string(R"({"errors":true})"),
                               std::string(R"({"items":[{"index":{"status":201}},{"index":{"status":201}})"),
                               std::string(R"({"items":[{"index":{"status":201}},{"index":{"status":201}}]} x)"),
                               std::string(R"({"items":[{"index":{"status":201,}},{"index":{"status":201}}]})")})
    {
        EXPECT_FALSE(wr::classifyItems(broken, 2).has_value()) << broken;
    }

    // No spare capacity: the classifier adds the padding itself and leaves the content as it was.
    const auto text = served(BulkScript::items(), two);
    std::string tight(text.data(), text.size());
    ASSERT_EQ(tight.capacity(), tight.size()) << "precondition: a body without spare capacity";
    const auto got = wr::classifyItems(tight, 2);
    expectItems(
        got,
        {{ItemVerdict::Ok, ic::ItemOutcome::Created, 201, ""}, {ItemVerdict::Ok, ic::ItemOutcome::Deleted, 200, ""}},
        tight);
    EXPECT_EQ(tight, text);
}

// `reason` stays within 512 bytes with `caused_by` appended (cut on a UTF-8 boundary), `itemErrorType` within
// 64; the request reason is bounded too.
TEST(ClassifyTest, ClassifyReasonBounded)
{
    const std::string longType(200, 't');
    const std::string longReason(2000, 'r');
    const std::string utf8Reason = std::string(511, 'a') + "\xc3\xa9"; // 513 bytes: the cut must not split the é.
    auto body = served(BulkScript::items({{0, BulkItem::failed(400, longType, longReason).causedBy("c", "d")},
                                          {1, BulkItem::failed(400, "x", std::string(500, 'a')).causedBy("t", "r2")},
                                          {2, BulkItem::failed(400, "x", utf8Reason)},
                                          {3, BulkItem::failed(400, "x", "R").causedBy("T", "R2")}}),
                       {"index", "index", "index", "index"});
    const auto got = wr::classifyItems(body, 4);
    ASSERT_TRUE(got.has_value()) << body;
    ASSERT_EQ(got->size(), 4U);
    EXPECT_EQ((*got)[0].itemErrorType, longType.substr(0, ic::OpResult::MAX_ITEM_ERROR_TYPE));
    EXPECT_EQ((*got)[0].reason, longReason.substr(0, ic::OpResult::MAX_REASON));
    EXPECT_EQ((*got)[1].reason.size(), ic::OpResult::MAX_REASON);
    EXPECT_EQ((*got)[1].reason, (std::string(500, 'a') + "; caused by t: r2").substr(0, ic::OpResult::MAX_REASON));
    EXPECT_EQ((*got)[2].reason, std::string(511, 'a')) << "cut before the 2-byte sequence";
    EXPECT_EQ((*got)[3].reason, "R; caused by T: R2");
    for (const auto& item : *got)
    {
        EXPECT_LE(item.reason.size(), ic::OpResult::MAX_REASON);
        EXPECT_LE(item.itemErrorType.size(), ic::OpResult::MAX_ITEM_ERROR_TYPE);
    }

    const auto request = wr::classifyRequest(status(409, std::string(4000, 'b')), 3);
    EXPECT_EQ(request.reason.size(), ic::OpResult::MAX_REASON);
    EXPECT_EQ(request.reason.rfind("HTTP 409: bbb", 0), 0U) << request.reason;
}

// After an 8 MiB body the thread's parser is rebuilt (capacity <= 4 MiB); a small body leaves it alive.
TEST(ClassifyTest, ParserMemoryBounded)
{
    std::string body = R"({"took":3,"errors":false,"items":[)";
    const std::string item = R"({"index":{"_index":"i","_id":"x","status":201,"result":"created"}},)";
    std::size_t count = 0;
    while (body.size() < 8U * 1024 * 1024)
    {
        body += item;
        ++count;
    }
    body.back() = ']';
    body += "}";
    const auto got = wr::classifyItems(body, count);
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got->size(), count);
    EXPECT_EQ(got->back().outcome, ic::ItemOutcome::Created);
    EXPECT_LE(ic::testing_hooks::parserCapacity(), 4U * 1024 * 1024);

    std::string small = R"({"items":[{"index":{"status":201,"result":"created"}}]})";
    ASSERT_TRUE(wr::classifyItems(small, 1).has_value());
    EXPECT_GT(ic::testing_hooks::parserCapacity(), 0U);
    EXPECT_LE(ic::testing_hooks::parserCapacity(), 4U * 1024 * 1024);
}

namespace
{
    class ClassifyTransportTest : public TransportTest
    {
    };
} // namespace

// A response body handed over by the real transport carries RESPONSE_PADDING (>= 64) bytes of spare capacity,
// small or large, so the classifier parses it in place; and it classifies.
TEST_F(ClassifyTransportTest, TransportBodyPadded)
{
    auto responder = std::make_shared<BulkResponder>();
    FakeIndexer fake;
    fake.addRule(bulkRule(responder));
    fake.start();
    auto transportPtr = startRuntime(1, 2);
    ASSERT_NE(transportPtr, nullptr);

    for (const std::size_t ops : {std::size_t {2}, std::size_t {3000}})
    {
        std::vector<std::string> actions(ops, "index");
        actions[0] = "delete";
        auto req = component::request(ic::detail::HttpMethod::Post,
                                      fake.baseUrl() + "/_bulk",
                                      std::make_shared<const std::string>(ndjson(actions)));
        req.contentType = "application/x-ndjson";
        auto promise = std::make_shared<std::promise<std::pair<std::size_t, HttpResult>>>();
        auto future = promise->get_future();
        const auto admission = transportPtr->submit(std::move(req),
                                                    [promise](HttpResult&& result)
                                                    {
                                                        // Read in the callback: a copy would not keep the capacity.
                                                        const auto spare = result.body.capacity() - result.body.size();
                                                        promise->set_value({spare, std::move(result)});
                                                    });
        ASSERT_TRUE(admission.admitted);
        ASSERT_EQ(future.wait_for(10s), std::future_status::ready);
        auto [spare, result] = future.get();
        EXPECT_EQ(result.cause, TransportCause::None);
        EXPECT_EQ(result.status, 200);
        EXPECT_GE(spare, ic::detail::RESPONSE_PADDING) << ops << " ops, body " << result.body.size() << " bytes";
        EXPECT_GE(spare, 64U);
        const auto outcome = wr::classifyRequest(result, ops);
        EXPECT_EQ(outcome.verdict, RequestVerdict::Items);
        const auto items = wr::classifyItems(result.body, ops);
        ASSERT_TRUE(items.has_value());
        EXPECT_EQ(items->front().outcome, ic::ItemOutcome::Deleted);
        EXPECT_EQ(items->back().outcome, ic::ItemOutcome::Created);
    }
}

// A rejected body says why, so the sender can keep it as the ops' last error.
TEST(ClassifyTest, ClassifyItemsReason)
{
    std::string reason;
    auto two = served(BulkScript::items(), {"index", "index"});
    EXPECT_FALSE(wr::classifyItems(two, 3, &reason).has_value());
    EXPECT_EQ(reason, "items: got 2, expected 3");
    reason.clear();
    EXPECT_FALSE(wr::classifyItems(two, 1, &reason).has_value());
    EXPECT_EQ(reason, "items: more than the 1 expected");
    reason.clear();
    std::string html = "<html><body>502 Bad Gateway</body></html>";
    EXPECT_FALSE(wr::classifyItems(html, 1, &reason).has_value());
    EXPECT_EQ(reason.rfind("unreadable body: ", 0), 0U) << reason;
    reason = "untouched";
    std::string good = served(BulkScript::items(), {"index"});
    EXPECT_TRUE(wr::classifyItems(good, 1, &reason).has_value());
    EXPECT_EQ(reason, "untouched") << "the reason is only written on failure";
}
