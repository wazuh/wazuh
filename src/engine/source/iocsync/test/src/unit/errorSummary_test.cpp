// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <string>

#include "errorSummary.hpp"

using ioc::sync::detail::MAX_ERROR_SUMMARY_LENGTH;
using ioc::sync::detail::summarizeError;

namespace
{
// A circuit-breaker rejection as the indexer answers it: the root cause is repeated
std::string circuitBreakerMessage()
{
    const std::string reason =
        "[parent] Data too large, data for [<http_request>] would be [1030036280/982.3mb], which is larger than the "
        "limit of [1020054732/972.7mb], real usage: [1030035968/982.3mb], new bytes reserved: [312/312b], usages "
        "[request=0/0b, fielddata=0/0b, in_flight_requests=312/312b]";
    const std::string cause = R"({"type":"circuit_breaking_exception","reason":")" + reason
                              + R"(","bytes_wanted":1030036280,"bytes_limit":1020054732,"durability":"PERMANENT"})";
    const std::string body =
        R"({"error":{"root_cause":[)" + cause + "," + cause + "," + cause
        + R"(],"type":"circuit_breaking_exception","reason":")" + reason
        + R"(","bytes_wanted":1030036280,"bytes_limit":1020054732,"durability":"PERMANENT"},"status":429})";
    return "Failed to download IOCs to database 'iocsync_connection_ab12': Search request failed with status 429: "
           "HTTP response code said error. Response: "
           + body;
}
} // namespace

TEST(IocSyncErrorSummary, KeepsStatusTypeAndShortReason)
{
    const auto message = circuitBreakerMessage();
    ASSERT_GT(message.size(), 1000u);

    const auto summary = summarizeError(message);

    EXPECT_LE(summary.size(), MAX_ERROR_SUMMARY_LENGTH);
    EXPECT_EQ(summary.rfind("Failed to download IOCs to database 'iocsync_connection_ab12': Search request failed "
                            "with status 429: HTTP response code said error (circuit_breaking_exception: [parent] Data "
                            "too large",
                            0),
              0u)
        << summary;
    EXPECT_EQ(summary.find("Response"), std::string::npos) << summary;
    EXPECT_EQ(summary.find("root_cause"), std::string::npos) << summary;
    EXPECT_EQ(summary.back(), ')') << summary;
}

TEST(IocSyncErrorSummary, MessageWithoutBodyIsUnchanged)
{
    EXPECT_EQ(summarizeError("Remote IOC data index does not exist"), "Remote IOC data index does not exist");
}

TEST(IocSyncErrorSummary, UnparseableBodyKeepsTheTextBeforeIt)
{
    EXPECT_EQ(summarizeError("Search request failed with status 503: Service Unavailable. Response: {not json"),
              "Search request failed with status 503: Service Unavailable");
}

TEST(IocSyncErrorSummary, PlainStringErrorIsKept)
{
    EXPECT_EQ(
        summarizeError(R"(Failed to create PIT. Error: x, Status code: 404, Response: {"error":"no such index"})"),
        "Failed to create PIT. Error: x, Status code: 404 (no such index)");
}

TEST(IocSyncErrorSummary, LongMessageWithoutBodyIsBounded)
{
    const std::string message(5000, 'x');
    const auto summary = summarizeError(message);
    EXPECT_EQ(summary.size(), MAX_ERROR_SUMMARY_LENGTH);
    EXPECT_EQ(summary.substr(summary.size() - 3), "...");
}
