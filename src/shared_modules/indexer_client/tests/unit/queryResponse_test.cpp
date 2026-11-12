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

// E4a 03 §4.16 / I84-I86: the pure query-response classifiers, without network; E4b (pit.hpp CREATE, EXPIRY): the
// PIT creation and PIT search classifiers.

#include <cstdint>
#include <string>

#include <gtest/gtest.h>

#include "query/query.hpp"
#include "query/queryResponse.hpp"

namespace
{
    using indexer_client::Cause;
    using indexer_client::OpResult;
    using indexer_client::detail::HttpResult;
    using indexer_client::detail::query::classifyByQuery;
    using indexer_client::detail::query::classifyExists;
    using indexer_client::detail::query::classifyPitCreate;
    using indexer_client::detail::query::classifyPitSearch;
    using indexer_client::detail::query::classifySearch;
    using indexer_client::detail::query::errorReason;
    using indexer_client::detail::query::errorType;
    using indexer_client::detail::query::QUERY_DOM_FACTOR;
    using indexer_client::detail::query::QueryVerdict;
    using indexer_client::detail::query::REASON_BODY_BYTES;

    constexpr std::uint64_t MAX_BYTES = 1024 * 1024;
    constexpr bool DBQ = true;
    constexpr bool UBQ = false;

    constexpr const char* NOT_FOUND_BODY =
        R"({"error":{"root_cause":[{"type":"index_not_found_exception","reason":"no such index [x]"}],)"
        R"("type":"index_not_found_exception","reason":"no such index [x]","index":"x"},"status":404})";
    constexpr const char* OTHER_404_BODY = R"({"error":{"type":"resource_not_found_exception"},"status":404})";
    constexpr const char* CLEAN_BY_QUERY =
        R"({"took":5,"timed_out":false,"total":3,"deleted":3,"updated":0,"version_conflicts":0,"failures":[]})";

    HttpResult http(long status, std::string body = {})
    {
        HttpResult result;
        result.status = status;
        result.body = std::move(body);
        return result;
    }

    std::string conflictFailure()
    {
        return R"({"index":"x","id":"1","cause":{"type":"version_conflict_engine_exception","reason":"conflict"},)"
               R"("status":409})";
    }

    std::string mapperFailure()
    {
        return R"({"index":"x","id":"2","cause":{"type":"mapper_parsing_exception","reason":"bad field"},"status":400})";
    }

    std::string withFailures(const std::string& failures, std::uint64_t conflicts = 0)
    {
        return R"({"took":5,"timed_out":false,"total":2,"version_conflicts":)" + std::to_string(conflicts) +
               R"(,"failures":[)" + failures + "]}";
    }
} // namespace

// ----------------------------------------------------------------------------------------------------------------
// search

TEST(QueryResponseTest, Search200IsOkWithTheParsedBody)
{
    const auto response = classifySearch(http(200, R"({"hits":{"hits":[{"_id":"a"}]}})"), MAX_BYTES);
    EXPECT_EQ(response.verdict, QueryVerdict::Ok);
    EXPECT_EQ(response.cause, Cause::None);
    EXPECT_EQ(response.httpStatus, 200);
    EXPECT_EQ(response.body.at("hits").at("hits").at(0).at("_id"), "a");
}

TEST(QueryResponseTest, Search200UnparsableIsItemPermanent)
{
    for (const char* body : {"{not json", "", "[1,2]", "42"})
    {
        const auto response = classifySearch(http(200, body), MAX_BYTES);
        EXPECT_EQ(response.verdict, QueryVerdict::Fail) << body;
        EXPECT_EQ(response.cause, Cause::ItemPermanent) << body;
        EXPECT_EQ(response.httpStatus, 200) << body;
        EXPECT_FALSE(response.reason.empty()) << body;
    }
}

TEST(QueryResponseTest, ResponseCapIsBodyTimesDomFactor)
{
    // I84: size * QUERY_DOM_FACTOR > max ⇒ ItemPermanent without parsing (the body below is not even JSON).
    const std::uint64_t cap = 4096;
    const std::uint64_t fits = cap / QUERY_DOM_FACTOR;

    const std::string padded = "{\"a\":\"" + std::string(fits - 8, 'x') + "\"}";
    ASSERT_EQ(padded.size(), fits);
    EXPECT_EQ(classifySearch(http(200, padded), cap).verdict, QueryVerdict::Ok);
    EXPECT_FALSE(classifySearch(http(200, padded), cap).tooLarge);
    EXPECT_FALSE(classifySearch(http(200, "not json"), cap).tooLarge) << "unparsable is not too large";

    const std::string over(fits + 1, '{');
    for (const auto& response : {classifySearch(http(200, over), cap),
                                 classifyByQuery(http(200, over), DBQ, cap),
                                 classifyByQuery(http(200, over), UBQ, cap)})
    {
        EXPECT_EQ(response.verdict, QueryVerdict::Fail);
        EXPECT_EQ(response.cause, Cause::ItemPermanent);
        EXPECT_NE(response.reason.find("too large"), std::string::npos) << response.reason;
        EXPECT_TRUE(response.tooLarge);
    }
}

TEST(QueryResponseTest, Search404IndexNotFoundIsNotFoundWithTheType)
{
    const auto response = classifySearch(http(404, NOT_FOUND_BODY), MAX_BYTES);
    EXPECT_EQ(response.verdict, QueryVerdict::Fail);
    EXPECT_EQ(response.cause, Cause::NotFound);
    EXPECT_EQ(response.httpStatus, 404);
    EXPECT_EQ(response.reason.rfind("404 index_not_found_exception: ", 0), 0U) << response.reason;
}

TEST(QueryResponseTest, Search404WithoutTheTypeIsClient4xx)
{
    for (const char* body : {OTHER_404_BODY, "", "<html>not found</html>"})
    {
        const auto response = classifySearch(http(404, body), MAX_BYTES);
        EXPECT_EQ(response.verdict, QueryVerdict::Fail) << body;
        EXPECT_EQ(response.cause, Cause::Client4xx) << body;
        EXPECT_EQ(response.httpStatus, 404) << body;
    }
}

// ---------------------------------------------------------------------------------------------- deleteByQuery / update

TEST(QueryResponseTest, ByQuery200CleanIsOk)
{
    for (const bool isDelete : {DBQ, UBQ})
    {
        const auto response = classifyByQuery(http(200, CLEAN_BY_QUERY), isDelete, MAX_BYTES);
        EXPECT_EQ(response.verdict, QueryVerdict::Ok) << isDelete;
        EXPECT_EQ(response.cause, Cause::None) << isDelete;
        EXPECT_EQ(response.versionConflicts, 0U) << isDelete;
        EXPECT_EQ(response.body.at("deleted"), 3) << isDelete;
    }
}

TEST(QueryResponseTest, ByQueryFailuresAreItemPermanent)
{
    // Also an update with conflicts=proceed (obj. 13(f)); the first failure is in the reason.
    for (const bool isDelete : {DBQ, UBQ})
    {
        for (const auto& failures :
             {mapperFailure(), mapperFailure() + "," + conflictFailure(), conflictFailure() + "," + mapperFailure()})
        {
            const auto response = classifyByQuery(http(200, withFailures(failures, 1)), isDelete, MAX_BYTES);
            EXPECT_EQ(response.verdict, QueryVerdict::Fail) << failures;
            EXPECT_EQ(response.cause, Cause::ItemPermanent) << failures;
            EXPECT_EQ(response.httpStatus, 200) << failures;
            EXPECT_LE(response.reason.size(), OpResult::MAX_REASON);
        }
        const auto first = classifyByQuery(http(200, withFailures(mapperFailure())), isDelete, MAX_BYTES);
        EXPECT_EQ(first.reason.rfind("200 mapper_parsing_exception: ", 0), 0U) << first.reason;
    }
}

TEST(QueryResponseTest, ByQueryConflictOnlyFailuresAreConflict)
{
    // obj. 5: conflicts=abort answers 200 with 409 failures; they go to the I86 budget, not to ItemPermanent.
    const std::string byStatus = R"({"index":"x","id":"3","status":409})";
    const std::string byType = R"({"index":"x","id":"4","cause":{"type":"version_conflict_engine_exception"}})";
    for (const bool isDelete : {DBQ, UBQ})
    {
        const auto counted =
            classifyByQuery(http(200, withFailures(conflictFailure() + "," + byStatus, 5)), isDelete, MAX_BYTES);
        EXPECT_EQ(counted.verdict, QueryVerdict::Conflict);
        EXPECT_EQ(counted.cause, Cause::None);
        EXPECT_EQ(counted.versionConflicts, 5U);

        const auto uncounted =
            classifyByQuery(http(200, withFailures(conflictFailure() + "," + byType, 0)), isDelete, MAX_BYTES);
        EXPECT_EQ(uncounted.verdict, QueryVerdict::Conflict);
        EXPECT_EQ(uncounted.versionConflicts, 2U);
    }
}

TEST(QueryResponseTest, ByQueryTimedOutIsRetry)
{
    const std::string body = R"({"took":60000,"timed_out":true,"total":9,"version_conflicts":2,"failures":[]})";
    for (const bool isDelete : {DBQ, UBQ})
    {
        const auto response = classifyByQuery(http(200, body), isDelete, MAX_BYTES);
        EXPECT_EQ(response.verdict, QueryVerdict::Retry);
        EXPECT_EQ(response.cause, Cause::None);
        EXPECT_EQ(response.httpStatus, 200);
    }
}

TEST(QueryResponseTest, ByQueryVersionConflictsWithoutFailuresIsConflict)
{
    const std::string body = R"({"took":5,"timed_out":false,"total":4,"version_conflicts":3,"failures":[]})";
    for (const bool isDelete : {DBQ, UBQ})
    {
        const auto response = classifyByQuery(http(200, body), isDelete, MAX_BYTES);
        EXPECT_EQ(response.verdict, QueryVerdict::Conflict);
        EXPECT_EQ(response.versionConflicts, 3U);
    }
}

TEST(QueryResponseTest, ByQueryUnparsableIsItemPermanent)
{
    for (const bool isDelete : {DBQ, UBQ})
    {
        for (const char* body : {"{\"failures\":", "", "[]", R"({"failures":"oops"})"})
        {
            const auto response = classifyByQuery(http(200, body), isDelete, MAX_BYTES);
            EXPECT_EQ(response.verdict, QueryVerdict::Fail) << body;
            EXPECT_EQ(response.cause, Cause::ItemPermanent) << body;
        }
    }
}

TEST(QueryResponseTest, Dbq404IndexNotFoundIsOkEmpty)
{
    const auto response = classifyByQuery(http(404, NOT_FOUND_BODY), DBQ, MAX_BYTES);
    EXPECT_EQ(response.verdict, QueryVerdict::Ok);
    EXPECT_EQ(response.cause, Cause::None);
    EXPECT_EQ(response.httpStatus, 404);
    EXPECT_EQ(response.body, nlohmann::json::object());
}

TEST(QueryResponseTest, Dbq404WithoutTheTypeIsClient4xx)
{
    // obj. 4: only the missing index is "nothing to delete".
    for (const char* body : {OTHER_404_BODY, ""})
    {
        const auto response = classifyByQuery(http(404, body), DBQ, MAX_BYTES);
        EXPECT_EQ(response.verdict, QueryVerdict::Fail) << body;
        EXPECT_EQ(response.cause, Cause::Client4xx) << body;
    }
}

TEST(QueryResponseTest, Ubq404IsNotFoundOrClient4xx)
{
    const auto missing = classifyByQuery(http(404, NOT_FOUND_BODY), UBQ, MAX_BYTES);
    EXPECT_EQ(missing.verdict, QueryVerdict::Fail);
    EXPECT_EQ(missing.cause, Cause::NotFound);
    EXPECT_NE(missing.reason.find("index_not_found_exception"), std::string::npos);

    const auto other = classifyByQuery(http(404, OTHER_404_BODY), UBQ, MAX_BYTES);
    EXPECT_EQ(other.verdict, QueryVerdict::Fail);
    EXPECT_EQ(other.cause, Cause::Client4xx);
}

// ------------------------------------------------------------------------------------------------------------- exists

TEST(QueryResponseTest, ExistsHead200And404)
{
    const auto present = classifyExists(http(200));
    EXPECT_EQ(present.verdict, QueryVerdict::Ok);
    EXPECT_TRUE(present.exists);
    EXPECT_EQ(present.httpStatus, 200);

    const auto absent = classifyExists(http(404));
    EXPECT_EQ(absent.verdict, QueryVerdict::Ok);
    EXPECT_FALSE(absent.exists);
    EXPECT_EQ(absent.httpStatus, 404);
}

TEST(QueryResponseTest, UnexpectedStatusIsAFinalFail)
{
    // Defensive only: the engine settles these with classifyRequest before calling the classifiers.
    EXPECT_EQ(classifySearch(http(400, OTHER_404_BODY), MAX_BYTES).cause, Cause::Client4xx);
    EXPECT_EQ(classifyByQuery(http(500), DBQ, MAX_BYTES).cause, Cause::Server5xx);
    EXPECT_EQ(classifyExists(http(0)).verdict, QueryVerdict::Fail);
}

// ------------------------------------------------------------------------------------------------------- PIT create

TEST(QueryResponseTest, PitCreate2xxWithPitIdIsOk)
{
    const auto response = classifyPitCreate(http(200, R"({"pit_id":"pit-1","_shards":{"failed":0}})"), MAX_BYTES);
    EXPECT_EQ(response.verdict, QueryVerdict::Ok);
    EXPECT_EQ(response.body.at("pit_id"), "pit-1");
}

// A PIT created without some shard is never accepted: Retry, and the body keeps its pit_id (that PIT exists).
TEST(QueryResponseTest, PitCreate2xxWithFailedShardsIsRetried)
{
    const auto response = classifyPitCreate(
        http(200, R"({"pit_id":"pit-1","_shards":{"total":2,"successful":1,"skipped":0,"failed":1}})"), MAX_BYTES);
    EXPECT_EQ(response.verdict, QueryVerdict::Retry);
    EXPECT_EQ(response.httpStatus, 200);
    EXPECT_EQ(response.reason, "200 partial PIT: 1 shards failed");
    EXPECT_EQ(response.body.at("pit_id"), "pit-1");

    // No `_shards`, or a `failed` that is 0 or not a number: as before.
    for (const char* body : {R"({"pit_id":"pit-1"})", R"({"pit_id":"pit-1","_shards":{"failed":"1"}})"})
    {
        EXPECT_EQ(classifyPitCreate(http(200, body), MAX_BYTES).verdict, QueryVerdict::Ok) << body;
    }
}

TEST(QueryResponseTest, PitCreate2xxWithoutAUsablePitIdIsItemPermanent)
{
    for (const char* body :
         {R"({"_shards":{"failed":0}})", R"({"pit_id":""})", R"({"pit_id":7})", R"({"pit_id":null})"})
    {
        const auto response = classifyPitCreate(http(200, body), MAX_BYTES);
        EXPECT_EQ(response.verdict, QueryVerdict::Fail) << body;
        EXPECT_EQ(response.cause, Cause::ItemPermanent) << body;
        EXPECT_EQ(response.httpStatus, 200) << body;
        EXPECT_NE(response.reason.find("response without pit_id"), std::string::npos) << response.reason;
    }
    EXPECT_EQ(classifyPitCreate(http(200, "{truncated"), MAX_BYTES).cause, Cause::ItemPermanent);
}

TEST(QueryResponseTest, PitCreate404IsNotFoundOnlyForAMissingIndex)
{
    const auto missing = classifyPitCreate(http(404, NOT_FOUND_BODY), MAX_BYTES);
    EXPECT_EQ(missing.verdict, QueryVerdict::Fail);
    EXPECT_EQ(missing.cause, Cause::NotFound);
    EXPECT_EQ(missing.reason.rfind("404 index_not_found_exception: ", 0), 0U) << missing.reason;
    for (const char* body : {OTHER_404_BODY, ""})
    {
        const auto other = classifyPitCreate(http(404, body), MAX_BYTES);
        EXPECT_EQ(other.verdict, QueryVerdict::Fail) << body;
        EXPECT_EQ(other.cause, Cause::Client4xx) << body;
    }
}

// ------------------------------------------------------------------------------------------------------- PIT search

TEST(QueryResponseTest, PitSearch404ContextMissingIsPitExpired)
{
    const char* direct =
        R"({"error":{"type":"search_context_missing_exception","reason":"No search context"},"status":404})";
    const char* inRootCause =
        R"({"error":{"root_cause":[{"type":"other_exception"},)"
        R"({"type":"search_context_missing_exception","reason":"No search context"}],)"
        R"("type":"search_phase_execution_exception","reason":"all shards failed"},"status":404})";
    for (const char* body : {direct, inRootCause})
    {
        const auto response = classifyPitSearch(http(404, body), MAX_BYTES);
        EXPECT_EQ(response.verdict, QueryVerdict::Fail) << body;
        EXPECT_EQ(response.cause, Cause::PitExpired) << body;
        EXPECT_EQ(response.httpStatus, 404) << body;
    }
}

TEST(QueryResponseTest, PitSearch404OfAnotherTypeIsNotAnExpiry)
{
    for (const char* body : {OTHER_404_BODY, "", "<html>not found</html>"})
    {
        const auto response = classifyPitSearch(http(404, body), MAX_BYTES);
        EXPECT_EQ(response.verdict, QueryVerdict::Fail) << body;
        EXPECT_EQ(response.cause, Cause::Client4xx) << body;
    }
    EXPECT_EQ(classifyPitSearch(http(404, NOT_FOUND_BODY), MAX_BYTES).cause, Cause::NotFound);
}

TEST(QueryResponseTest, PitSearch2xxShardFailureOfTheContextIsPitExpired)
{
    // The type in the failure's reason, in its cause, and in the caused_by of either.
    const std::string failures[] = {
        R"({"shard":0,"reason":{"type":"search_context_missing_exception","reason":"No search context"}})",
        R"({"shard":0,"cause":{"type":"search_context_missing_exception"}})",
        R"({"shard":0,"cause":{"type":"query_shard_exception",)"
        R"("caused_by":{"type":"search_context_missing_exception"}}})",
        R"({"shard":0,"reason":{"type":"x","caused_by":{"type":"search_context_missing_exception"}}})"};
    for (const auto& failure : failures)
    {
        const auto body = R"({"hits":{"hits":[]},"_shards":{"total":2,"failed":1,"failures":[{"shard":1,)"
                          R"("reason":{"type":"illegal_argument_exception"}},)" +
                          failure + "]}}";
        const auto response = classifyPitSearch(http(200, body), MAX_BYTES);
        EXPECT_EQ(response.verdict, QueryVerdict::Fail) << body;
        EXPECT_EQ(response.cause, Cause::PitExpired) << body;
    }
}

TEST(QueryResponseTest, PitSearch2xxOtherShardFailureIsRetry)
{
    const auto response =
        classifyPitSearch(http(200,
                               R"({"hits":{"hits":[]},"_shards":{"total":2,"failed":1,"failures":[{"shard":0,)"
                               R"("reason":{"type":"illegal_argument_exception","reason":"bad"}}]}})"),
                          MAX_BYTES);
    EXPECT_EQ(response.verdict, QueryVerdict::Retry);
    EXPECT_EQ(response.httpStatus, 200);
    EXPECT_NE(response.reason.find("illegal_argument_exception"), std::string::npos) << response.reason;

    const auto noFailures =
        classifyPitSearch(http(200, R"({"hits":{"hits":[]},"_shards":{"total":2,"failed":1}})"), MAX_BYTES);
    EXPECT_EQ(noFailures.verdict, QueryVerdict::Retry);
    EXPECT_NE(noFailures.reason.find("shard failure"), std::string::npos) << noFailures.reason;
}

TEST(QueryResponseTest, PitSearch2xxWithoutShardFailuresIsOk)
{
    for (const char* body : {R"({"hits":{"hits":[]}})",
                             R"({"hits":{"hits":[]},"_shards":"weird"})",
                             R"({"hits":{"hits":[]},"_shards":{"total":2,"failed":0}})",
                             R"({"pit_id":"pit-2","hits":{"hits":[]},"_shards":{"failed":0,"failures":[]}})"})
    {
        const auto response = classifyPitSearch(http(200, body), MAX_BYTES);
        EXPECT_EQ(response.verdict, QueryVerdict::Ok) << body;
    }
    EXPECT_EQ(classifyPitSearch(http(200, "{truncated"), MAX_BYTES).cause, Cause::ItemPermanent);
}

// ------------------------------------------------------------------------------------------------ errorType / reason

TEST(QueryResponseTest, ErrorTypeShapes)
{
    EXPECT_EQ(errorType(NOT_FOUND_BODY), "index_not_found_exception");
    EXPECT_EQ(errorType(R"({"error":"plain string error"})"), "plain string error");
    EXPECT_EQ(errorType(R"({"status":404})"), "");
    EXPECT_EQ(errorType(R"({"error":{"reason":"no type"}})"), "");
    EXPECT_EQ(errorType(R"({"error":{"type":7}})"), "");
    EXPECT_EQ(errorType(R"({"nested":{"error":{"type":"no"}}})"), "");
    EXPECT_EQ(errorType(R"([{"error":"in an array"}])"), "");
    EXPECT_EQ(errorType("{truncated"), "");
    EXPECT_EQ(errorType(""), "");
}

TEST(QueryResponseTest, ErrorReasonFormat)
{
    EXPECT_EQ(errorReason(404, R"({"error":"x"})"), R"(404 x: {"error":"x"})");
    EXPECT_EQ(errorReason(404, "plain"), "404: plain");
    EXPECT_EQ(errorReason(404, ""), "404");
}

TEST(QueryResponseTest, ErrorReasonKeepsAtMostReasonBodyBytes)
{
    const std::string body = R"({"error":{"type":"t"},"pad":")" + std::string(4 * REASON_BODY_BYTES, 'p') + "\"}";
    const auto reason = errorReason(400, body);
    const std::string prefix = "400 t: ";
    ASSERT_EQ(reason.rfind(prefix, 0), 0U) << reason;
    EXPECT_EQ(reason.size(), prefix.size() + REASON_BODY_BYTES);
    EXPECT_EQ(reason.substr(prefix.size()), body.substr(0, REASON_BODY_BYTES));
}

TEST(QueryResponseTest, ErrorReasonIsBoundedByMaxReason)
{
    // A hostile type longer than the whole reason: the result never exceeds OpResult::MAX_REASON.
    const std::string type(2 * OpResult::MAX_REASON, 'T');
    const auto reason = errorReason(400, R"({"error":{"type":")" + type + "\"}}");
    EXPECT_EQ(reason.size(), OpResult::MAX_REASON);
    EXPECT_EQ(reason.rfind("400 TTT", 0), 0U);
}

TEST(QueryResponseTest, ErrorReasonNeverSplitsUtf8)
{
    // A two-byte sequence straddling REASON_BODY_BYTES is dropped whole.
    const std::string body = std::string(REASON_BODY_BYTES - 1, 'a') + "\xC3\xA9" + "tail";
    const auto reason = errorReason(400, body);
    EXPECT_EQ(reason, "400: " + std::string(REASON_BODY_BYTES - 1, 'a'));
}
