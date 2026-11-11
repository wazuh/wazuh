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
        "HTTP/1.1 103 Early Hints", "Content-Encoding: br, zstd", "",
        "HTTP/1.1 200 OK", "Content-Encoding: zstd"
    }));
}

// Only the first line of a block is a status line, for curl as for the guard: a header that reads
// like one must not end the response and reset the count.
TEST(ContentCodingGuardTest, AHeaderThatReadsLikeAStatusLineIsJustAHeader)
{
    ContentCodingGuard guard;

    EXPECT_FALSE(admitReply(guard, {"HTTP/1.1 200 OK", "HTTP/1.1 204: x", "Content-Encoding: zstd, zstd"}));
}

// curl takes the code right after "HTTP/1.x" and one space or tab, and skips leading blanks.
TEST(ContentCodingGuardTest, ReadsTheStatusCodeWhereCurlDoes)
{
    ContentCodingGuard tabbed;
    EXPECT_FALSE(admitReply(tabbed, {"HTTP/1.1\t200 204 x", "Content-Encoding: zstd, zstd"}));

    ContentCodingGuard tabbedNoContent;
    EXPECT_TRUE(admitReply(tabbedNoContent, {"HTTP/1.1\t204 No Content", "Content-Encoding: zstd, zstd"}));
}

// Over HTTP/2 and HTTP/3 curl writes the status line itself, with a space before the CRLF, and reads
// it back like any other: a 103 there is informational too, and a 204 has no body.
TEST(ContentCodingGuardTest, ReadsTheStatusLinesCurlWritesForHttp2AndHttp3)
{
    for (const std::string version :
            {"HTTP/2", "HTTP/3"
            })
    {
        ContentCodingGuard afterHints;
        EXPECT_FALSE(admitReply(afterHints, {version + " 103 ", "", version + " 200 ", "Content-Encoding: zstd, zstd"}))
                << version;

        ContentCodingGuard noContent;
        EXPECT_TRUE(admitReply(noContent, {version + " 204 ", "Content-Encoding: zstd, zstd"})) << version;
    }
}

// What curl doesn't read as a status line it reports as a 200 (an "HTTP/2 204" needs the space
// after the code), which has a body: so does the guard.
TEST(ContentCodingGuardTest, AStatusLineItCannotReadHasABody)
{
    for (const auto* status :
            {"HTTP/2 204", "http/1.1 204 No Content", "HTTP/1.1  204 No Content"
            })
    {
        ContentCodingGuard guard;
        EXPECT_FALSE(admitReply(guard, {status, "Content-Encoding: zstd, zstd"})) << status;
    }

    ContentCodingGuard afterHints;
    EXPECT_FALSE(admitReply(afterHints, {"HTTP/1.1 103 Early Hints", "", "http/1.1 200 OK", "Content-Encoding: zstd, zstd"}));
}

// curl builds no decoder from a chunked trailer, which arrives after the body.
TEST(ContentCodingGuardTest, IgnoresTheTrailersAfterTheBody)
{
    ContentCodingGuard guard;

    EXPECT_TRUE(admitReply(guard, {"HTTP/1.1 200 OK", "Content-Encoding: zstd", "", "Content-Encoding: zstd, gzip"}));
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

// A peer can fill the header with terminal escapes, and the note ends up in the agent's log.
TEST(ContentCodingGuardTest, TheRefusalNoteShowsAShortPrintableExcerpt)
{
    ContentCodingGuard guard;
    const std::string value = "zstd, \x1b[2J\x07" + std::string(200, 'A');

    EXPECT_FALSE(admitReply(guard, {"HTTP/1.1 200 OK", "Content-Encoding: " + value}));
    EXPECT_EQ("; refused Content-Encoding 'zstd, \\x1b[2J\\x07" + std::string(53, 'A') + "...': more than one coding",
              guard.refusalNote());
}

// curl maps "none" to its identity writer, and a token of control bytes names nothing: neither
// costs a window, so neither counts.
TEST(ContentCodingGuardTest, CountsOnlyWhatCurlTurnsIntoADecoder)
{
    for (const auto* value :
            {"none, zstd", "NONE, zstd", "zstd, \x01", "zstd, \x80"
            })
    {
        ContentCodingGuard guard;
        EXPECT_TRUE(admitReply(guard, {"HTTP/1.1 200 OK", std::string {"Content-Encoding: "} + value})) << value;
    }

    ContentCodingGuard twice;
    EXPECT_FALSE(admitReply(twice, {"HTTP/1.1 200 OK", "Content-Encoding: zstd,\x01\x02 ,zstd"}));
}

TEST(ContentCodingGuardTest, EmptyListsNameNoCoding)
{
    ContentCodingGuard guard;

    EXPECT_TRUE(admitReply(guard, {"HTTP/1.1 200 OK", "Content-Encoding: ,, ", "Content-Encoding:", "Content-Encoding: zstd"}));
}
