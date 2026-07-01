/*
 * Wazuh Indexer Connector - HttpErrorLogger tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "httpErrorLogger.hpp"
#include <chrono>
#include <gtest/gtest.h>
#include <string>

using IndexerConnector::HttpErrorLogger;

class HttpErrorLoggerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        HttpErrorLogger::instance().reset();
        HttpErrorLogger::instance().setSuppressionWindow(std::chrono::seconds {300});
    }
};

// The enriched message must identify the endpoint and surface the indexer reason.
TEST_F(HttpErrorLoggerTest, BuildDetailIncludesUrlStatusAndReason)
{
    const auto detail = HttpErrorLogger::buildDetail(
        "Bulk request failed",
        "https://127.0.0.1:9200/_bulk",
        "Client error",
        403,
        R"({"error":{"type":"security_exception","reason":"no permissions for [indices:data/write/bulk]"}})");

    EXPECT_NE(detail.find("Bulk request failed"), std::string::npos);
    EXPECT_NE(detail.find("Client error"), std::string::npos);
    EXPECT_NE(detail.find("status code: 403"), std::string::npos);
    EXPECT_NE(detail.find("https://127.0.0.1:9200/_bulk"), std::string::npos);
    EXPECT_NE(detail.find("security_exception"), std::string::npos);
    EXPECT_NE(detail.find("no permissions"), std::string::npos);
}

// A non-JSON body must still be surfaced (truncated), not dropped.
TEST_F(HttpErrorLoggerTest, BuildDetailFallsBackToRawBody)
{
    const auto detail = HttpErrorLogger::buildDetail("", "https://srv/_search", "Client error", 403, "Forbidden");
    EXPECT_NE(detail.find("response: Forbidden"), std::string::npos);
    EXPECT_NE(detail.find("status code: 403"), std::string::npos);
}

TEST_F(HttpErrorLoggerTest, BuildDetailOmitsResponseWhenBodyEmpty)
{
    const auto detail = HttpErrorLogger::buildDetail("", "https://srv/_bulk", "Client error", 500, "");
    EXPECT_EQ(detail.find("response:"), std::string::npos);
}

// First occurrence logs; identical repeats within the window are suppressed.
TEST_F(HttpErrorLoggerTest, RepeatsSuppressedWithinWindow)
{
    auto& logger = HttpErrorLogger::instance();
    const std::string key {"https://srv/_bulk|403|Client error"};
    auto t0 = std::chrono::steady_clock::time_point {};

    std::uint64_t suppressed = 0;
    EXPECT_TRUE(logger.shouldLogNow(key, t0, suppressed));
    EXPECT_EQ(suppressed, 0u);

    // The next 1000 identical errors within the window are all suppressed.
    for (int i = 0; i < 1000; ++i)
    {
        EXPECT_FALSE(logger.shouldLogNow(key, t0 + std::chrono::seconds {i % 60}, suppressed));
    }
}

// After the window elapses, it logs again and reports how many were suppressed.
TEST_F(HttpErrorLoggerTest, LogsAgainAfterWindowWithSuppressedCount)
{
    auto& logger = HttpErrorLogger::instance();
    logger.setSuppressionWindow(std::chrono::seconds {10});
    const std::string key {"https://srv/_bulk|403|Client error"};
    auto t0 = std::chrono::steady_clock::time_point {};

    std::uint64_t suppressed = 0;
    EXPECT_TRUE(logger.shouldLogNow(key, t0, suppressed));        // first
    EXPECT_FALSE(logger.shouldLogNow(key, t0 + std::chrono::seconds {3}, suppressed));
    EXPECT_FALSE(logger.shouldLogNow(key, t0 + std::chrono::seconds {6}, suppressed));

    // Past the 10s window: logs again, reporting the 2 suppressed in between.
    EXPECT_TRUE(logger.shouldLogNow(key, t0 + std::chrono::seconds {11}, suppressed));
    EXPECT_EQ(suppressed, 2u);
}

// Different endpoints/status codes are throttled independently.
TEST_F(HttpErrorLoggerTest, DistinctKeysThrottleIndependently)
{
    auto& logger = HttpErrorLogger::instance();
    auto t0 = std::chrono::steady_clock::time_point {};
    std::uint64_t suppressed = 0;

    EXPECT_TRUE(logger.shouldLogNow("https://srv/_bulk|403|Client error", t0, suppressed));
    EXPECT_TRUE(logger.shouldLogNow("https://srv/_search|403|Client error", t0, suppressed));
    EXPECT_TRUE(logger.shouldLogNow("https://srv/_bulk|500|Server error", t0, suppressed));

    // ...but a repeat of the first key is suppressed.
    EXPECT_FALSE(logger.shouldLogNow("https://srv/_bulk|403|Client error", t0, suppressed));
}

// The public log() path must be safe to call end-to-end.
TEST_F(HttpErrorLoggerTest, LogDoesNotThrow)
{
    EXPECT_NO_THROW(HttpErrorLogger::instance().log(
        "indexer-connector", "Bulk request failed", "https://srv/_bulk", "Client error", 403, "Forbidden"));
}

// A write-blocked index (FORBIDDEN/8) must be recognized and produce an actionable hint
// naming index.blocks.write, so the operator can clear it (issue #37156).
TEST_F(HttpErrorLoggerTest, BlockRemediationDetectsWriteBlock)
{
    const auto hint = HttpErrorLogger::blockRemediation(
        "cluster_block_exception index [wazuh-states-inventory-processes-node] blocked by: "
        "[FORBIDDEN/8/index write (api)];");
    EXPECT_NE(hint.find("index.blocks.write"), std::string::npos);
}

// The flood-stage disk watermark (FORBIDDEN/12 / read_only_allow_delete) maps to its own hint.
TEST_F(HttpErrorLoggerTest, BlockRemediationDetectsFloodStageReadOnly)
{
    const auto hint = HttpErrorLogger::blockRemediation(
        "index [wazuh-alerts] blocked by: [FORBIDDEN/12/index read-only / allow delete (api)];");
    EXPECT_NE(hint.find("read_only_allow_delete"), std::string::npos);
    EXPECT_NE(hint.find("disk"), std::string::npos);
}

// Unrelated errors must not be mistaken for an index block.
TEST_F(HttpErrorLoggerTest, BlockRemediationIgnoresNonBlockErrors)
{
    EXPECT_TRUE(HttpErrorLogger::blockRemediation("mapper_parsing_exception failed to parse field").empty());
    EXPECT_TRUE(HttpErrorLogger::blockRemediation("").empty());
}

// The enriched bulk-error line must carry the remediation hint end-to-end when the indexer
// response indicates a write block.
TEST_F(HttpErrorLoggerTest, BuildDetailAppendsBlockHint)
{
    const auto detail = HttpErrorLogger::buildDetail(
        "Bulk item rejected",
        "wazuh-states-inventory-processes-node",
        "cluster_block_exception",
        403,
        R"({"error":{"type":"cluster_block_exception","reason":"index [wazuh-states-inventory-processes-node] )"
        R"(blocked by: [FORBIDDEN/8/index write (api)];"}})");

    EXPECT_NE(detail.find("hint:"), std::string::npos);
    EXPECT_NE(detail.find("index.blocks.write"), std::string::npos);
    EXPECT_NE(detail.find("cluster_block_exception"), std::string::npos);
}
