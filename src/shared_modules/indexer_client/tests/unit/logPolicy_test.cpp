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

// What a log line may say about a document: named (index, id, size), quoted only behind the build-time switch.

#include <gtest/gtest.h>

#include <string>

#include "indexer_client/logPolicy.hpp"

namespace
{
    constexpr auto SENTINEL = "s3cr3t-value";
    const std::string DOCUMENT = std::string {R"({"user":{"name":")"} + SENTINEL + R"("}})";
} // namespace

TEST(LogPolicy, DocumentContentIsOffByDefault)
{
    EXPECT_FALSE(indexer_client::LOG_DOCUMENT_CONTENT);
}

TEST(LogPolicy, DocumentIsNamedNotQuoted)
{
    const auto line = indexer_client::documentForLog("wazuh-states-vulnerabilities", "001_abc", DOCUMENT);
    EXPECT_EQ(line,
              "index: 'wazuh-states-vulnerabilities', id: '001_abc', document size: " +
                  std::to_string(DOCUMENT.size()) + " bytes");
    EXPECT_EQ(line.find(SENTINEL), std::string::npos);
}

TEST(LogPolicy, NoIdIsNone)
{
    EXPECT_EQ(indexer_client::documentForLog("idx", "", ""), "index: 'idx', id: 'none', document size: 0 bytes");
}

TEST(LogPolicy, ContentOnlyWithTheFlag)
{
    const auto quoted = indexer_client::documentForLog("idx", "1", "a\nb", true);
    EXPECT_EQ(quoted, "index: 'idx', id: '1', document size: 3 bytes, document: a\\nb");
    EXPECT_EQ(indexer_client::documentForLog("idx", "1", "a\nb", false).find("document:"), std::string::npos);

    // Cut at MAX_LOGGED_DOCUMENT_BYTES, and said so.
    const std::string big(indexer_client::MAX_LOGGED_DOCUMENT_BYTES + 100, 'x');
    const auto cut = indexer_client::documentForLog("idx", "1", big, true);
    EXPECT_NE(cut.find(std::string(indexer_client::MAX_LOGGED_DOCUMENT_BYTES, 'x') + "..."), std::string::npos);
    EXPECT_EQ(cut.find(std::string(indexer_client::MAX_LOGGED_DOCUMENT_BYTES + 1, 'x')), std::string::npos);
}

TEST(LogPolicy, NamesAreOneLine)
{
    const auto line = indexer_client::documentForLog("idx\nforged", "id\r\x01", "{}");
    EXPECT_EQ(line, "index: 'idx\\nforged', id: 'id\\r\\x01', document size: 2 bytes");
}

TEST(LogPolicy, EscapingTwiceChangesNothing)
{
    const auto once = indexer_client::escapedForLog("a\nb\tc\x7f");
    EXPECT_EQ(once, "a\\nb\\tc\\x7f");
    EXPECT_EQ(indexer_client::escapedForLog(once), once);
}
