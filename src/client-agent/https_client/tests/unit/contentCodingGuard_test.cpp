/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "contentCodingGuard.hpp"

#include <gtest/gtest.h>

#include <initializer_list>
#include <string>

namespace
{
    /// Shows `guard` a reply's header lines as curl hands them over; false at the first refused one.
    bool admitReply(ContentCodingGuard& guard, std::initializer_list<std::string> lines)
    {
        for (const auto& line : lines)
        {
            if (!guard.admitHeader(line + "\r\n"))
            {
                return false;
            }
        }

        return true;
    }
} // namespace

TEST(ContentCodingGuardTest, AdmitsOneCoding)
{
    ContentCodingGuard guard;

    EXPECT_TRUE(admitReply(guard, {"HTTP/1.1 200 OK", "Content-Encoding: zstd", "Content-Type: application/octet-stream"}));
    EXPECT_FALSE(guard.refused());
    EXPECT_TRUE(guard.refusalNote().empty());
}

// Not only the offered one: curl decodes a single gzip error page with a window of its own size,
// and refusing it would hide the 503 it carries.
TEST(ContentCodingGuardTest, AdmitsOneCodingThatWasNotOffered)
{
    ContentCodingGuard guard;

    EXPECT_TRUE(admitReply(guard, {"HTTP/1.1 503 Service Unavailable", "Retry-After: 30", "Content-Encoding: gzip"}));
}

TEST(ContentCodingGuardTest, ReadsHeaderNamesAndCodingsCaseInsensitively)
{
    ContentCodingGuard guard;

    EXPECT_FALSE(admitReply(guard, {"HTTP/1.1 200 OK", "content-encoding: ZStd,\tzstd"}));
}

TEST(ContentCodingGuardTest, AdmitsIdentityAlongsideTheCoding)
{
    ContentCodingGuard guard;

    EXPECT_TRUE(admitReply(guard, {"HTTP/1.1 200 OK", "Content-Encoding: identity", "Content-Encoding: identity, zstd"}));
}

// curl would stack one zstd decoder, with its own window, per listed coding.
TEST(ContentCodingGuardTest, RefusesASecondCodingOnTheSameLine)
{
    ContentCodingGuard guard;

    EXPECT_FALSE(admitReply(guard, {"HTTP/1.1 200 OK", "Content-Encoding: zstd, zstd"}));
    EXPECT_TRUE(guard.refused());
    EXPECT_EQ("; refused Content-Encoding 'zstd, zstd': more than one coding", guard.refusalNote());
}

TEST(ContentCodingGuardTest, RefusesASecondCodingOnALaterLine)
{
    ContentCodingGuard guard;

    EXPECT_FALSE(admitReply(guard, {"HTTP/1.1 200 OK", "Content-Encoding: zstd", "Content-Encoding: gzip"}));
    EXPECT_EQ("; refused Content-Encoding 'gzip': more than one coding", guard.refusalNote());
}

// curl ignores the codings of a 1xx and builds the final response's decoders afresh (RFC 8297:
// hints must not affect how the final response is processed).
TEST(ContentCodingGuardTest, IgnoresTheCodingsOfAnInformationalResponse)
{
    ContentCodingGuard guard;

    EXPECT_TRUE(admitReply(guard,
    {
        "HTTP/1.1 103 Early Hints", "Content-Encoding: br, zstd",
        "HTTP/1.1 200 OK", "Content-Encoding: zstd"
    }));
}

TEST(ContentCodingGuardTest, IgnoresTheCodingsOfAResponseWithoutABody)
{
    for (const auto* status :
            {"HTTP/1.1 204 No Content", "HTTP/1.1 304 Not Modified"
            })
    {
        ContentCodingGuard guard;
        EXPECT_TRUE(admitReply(guard, {status, "Content-Encoding: zstd, zstd"})) << status;
    }
}

TEST(ContentCodingGuardTest, EmptyListsNameNoCoding)
{
    ContentCodingGuard guard;

    EXPECT_TRUE(admitReply(guard, {"HTTP/1.1 200 OK", "Content-Encoding: ,, ", "Content-Encoding:", "Content-Encoding: zstd"}));
}
