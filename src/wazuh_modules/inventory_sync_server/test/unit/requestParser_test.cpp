/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "http_server/requestParser.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using invsync::http::Method;
using invsync::http::RequestParser;
using Feed = invsync::http::RequestParser::Feed;

namespace
{
    /**
     * @brief The exact bytes remoted's AsioUdsHttpClient puts on the wire.
     *
     * Copied from buildRequestHead() in
     * src/remoted/remoted_module/src/downstream/asioUdsHttpClient.cpp. If that function changes,
     * this literal is what makes the mismatch visible here rather than in production.
     */
    std::string peerRequest(const std::string& body = "hello")
    {
        return "POST /inventory/sync HTTP/1.1\r\n"
               "Host: localhost\r\n"
               "Content-Type: application/octet-stream\r\n"
               "Content-Length: " +
               std::to_string(body.size()) +
               "\r\n"
               "Connection: close\r\n"
               "\r\n" +
               body;
    }

    /// Drives the parser the way a Session does: feed, and resume once the head is ready.
    Feed feedChunks(RequestParser& parser, const std::vector<std::string>& chunks)
    {
        auto verdict = Feed::Incomplete;
        for (const auto& chunk : chunks)
        {
            verdict = parser.feed(chunk.data(), chunk.size());
            if (verdict == Feed::HeadersReady)
            {
                verdict = parser.resume();
            }
            if (verdict == Feed::Complete || verdict == Feed::Reject || verdict == Feed::ProtocolError)
            {
                return verdict;
            }
        }
        return verdict;
    }

    RequestParser::Limits defaultLimits()
    {
        return RequestParser::Limits {};
    }
} // namespace

// The golden-bytes contract with the peer, fed in a single chunk. This is also what pins the
// byte accounting across the headers-complete pause: the body shares its read with the head here,
// so an off-by-one in the resume offset would corrupt it.
TEST(RequestParserTest, ParsesExactPeerRequestBytes)
{
    RequestParser parser {defaultLimits()};

    ASSERT_EQ(Feed::Complete, feedChunks(parser, {peerRequest()}));

    EXPECT_EQ(Method::Post, parser.request().method);
    EXPECT_EQ("/inventory/sync", parser.request().target);
    EXPECT_EQ("hello", parser.request().body);
    EXPECT_EQ("localhost", parser.request().headers.at("host"));
    EXPECT_EQ("application/octet-stream", parser.request().headers.at("content-type"));
    EXPECT_EQ("5", parser.request().headers.at("content-length"));
    EXPECT_EQ("close", parser.request().headers.at("connection"));
    EXPECT_EQ(5U, parser.declaredContentLength());
}

// The highest-value test here: every possible split point. Catches header field/value continuation
// across a boundary, a request line cut mid-token, and a body straddling two reads -- and it pins
// the resume-offset arithmetic at every alignment rather than just one.
TEST(RequestParserTest, ParsesPeerRequestSplitAtEveryOffset)
{
    const auto request = peerRequest("payload-bytes");

    for (std::size_t split = 1; split < request.size(); ++split)
    {
        RequestParser parser {defaultLimits()};
        const std::vector<std::string> chunks {request.substr(0, split), request.substr(split)};

        ASSERT_EQ(Feed::Complete, feedChunks(parser, chunks)) << "split at " << split;
        EXPECT_EQ(Method::Post, parser.request().method) << "split at " << split;
        EXPECT_EQ("/inventory/sync", parser.request().target) << "split at " << split;
        EXPECT_EQ("payload-bytes", parser.request().body) << "split at " << split;
        EXPECT_EQ("localhost", parser.request().headers.at("host")) << "split at " << split;
        EXPECT_EQ("application/octet-stream", parser.request().headers.at("content-type")) << "split at " << split;
    }
}

// Byte-at-a-time is the pathological case for callback continuation: every header name and value
// arrives one character per callback.
TEST(RequestParserTest, ParsesPeerRequestOneByteAtATime)
{
    const auto request = peerRequest("abc");
    std::vector<std::string> chunks;
    chunks.reserve(request.size());
    for (const char c : request)
    {
        chunks.emplace_back(1, c);
    }

    RequestParser parser {defaultLimits()};
    ASSERT_EQ(Feed::Complete, feedChunks(parser, chunks));
    EXPECT_EQ("/inventory/sync", parser.request().target);
    EXPECT_EQ("abc", parser.request().body);
    EXPECT_EQ("application/octet-stream", parser.request().headers.at("content-type"));
}

// The peer omits Content-Type when it is empty, so requiring it would reject legitimate traffic.
TEST(RequestParserTest, ParsesRequestWithoutContentTypeHeader)
{
    RequestParser parser {defaultLimits()};
    const std::string request {"POST /inventory/sync HTTP/1.1\r\n"
                               "Host: localhost\r\n"
                               "Content-Length: 2\r\n"
                               "Connection: close\r\n"
                               "\r\n"
                               "ok"};

    ASSERT_EQ(Feed::Complete, feedChunks(parser, {request}));
    EXPECT_EQ("ok", parser.request().body);
    EXPECT_EQ(0U, parser.request().headers.count("content-type"));
}

// The documented contract that remoted's own RESTinio implementation does not honour: a handler must
// be able to look up "content-type" without guessing at the sender's capitalization.
TEST(RequestParserTest, HeaderNamesAreLowerCasedAndValuesAreVerbatim)
{
    RequestParser parser {defaultLimits()};
    const std::string request {"POST /inventory/sync HTTP/1.1\r\n"
                               "HOST: localhost\r\n"
                               "Content-TYPE: Application/Octet-Stream\r\n"
                               "Content-Length: 0\r\n"
                               "\r\n"};

    ASSERT_EQ(Feed::Complete, feedChunks(parser, {request}));
    EXPECT_EQ("localhost", parser.request().headers.at("host"));
    // Name normalized, value untouched.
    EXPECT_EQ("Application/Octet-Stream", parser.request().headers.at("content-type"));
}

// The target is kept raw so it matches what the peer signed and logged; stripping the query is the
// router's job, not the parser's.
TEST(RequestParserTest, TargetKeepsTheQueryStringVerbatim)
{
    RequestParser parser {defaultLimits()};
    const std::string request {"POST /inventory/sync?module=fim&x=1 HTTP/1.1\r\n"
                               "Host: localhost\r\n"
                               "Content-Length: 0\r\n"
                               "\r\n"};

    ASSERT_EQ(Feed::Complete, feedChunks(parser, {request}));
    EXPECT_EQ("/inventory/sync?module=fim&x=1", parser.request().target);
}

// A bodyless GET must complete rather than sit waiting for a body that will never arrive -- the
// liveness probe depends on it, and the headers-complete pause makes this a real risk rather than a
// theoretical one.
TEST(RequestParserTest, BodylessGetCompletesAfterResume)
{
    RequestParser parser {defaultLimits()};
    const std::string request {"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"};

    ASSERT_EQ(Feed::Complete, feedChunks(parser, {request}));
    EXPECT_EQ(Method::Get, parser.request().method);
    EXPECT_EQ("/", parser.request().target);
    EXPECT_TRUE(parser.request().body.empty());
    EXPECT_EQ(0U, parser.declaredContentLength());
}

TEST(RequestParserTest, ExplicitZeroLengthBodyCompletes)
{
    RequestParser parser {defaultLimits()};
    const std::string request {"POST /inventory/sync HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"};

    ASSERT_EQ(Feed::Complete, feedChunks(parser, {request}));
    EXPECT_TRUE(parser.request().body.empty());
}

TEST(RequestParserTest, RecognizesEveryRoutableVerb)
{
    const std::vector<std::pair<std::string, Method>> cases {{"GET", Method::Get},
                                                             {"POST", Method::Post},
                                                             {"PUT", Method::Put},
                                                             {"DELETE", Method::Delete},
                                                             {"PATCH", Method::Patch}};

    for (const auto& [verb, expected] : cases)
    {
        RequestParser parser {defaultLimits()};
        const std::string request {verb + " /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"};
        ASSERT_EQ(Feed::Complete, feedChunks(parser, {request})) << verb;
        EXPECT_EQ(expected, parser.request().method) << verb;
    }
}

// Chunked is refused rather than supported: with no declared length there is nothing to reserve, so
// one connection could consume the whole in-flight budget.
TEST(RequestParserTest, RejectsChunkedWith411)
{
    RequestParser parser {defaultLimits()};
    const std::string request {"POST /inventory/sync HTTP/1.1\r\n"
                               "Host: localhost\r\n"
                               "Transfer-Encoding: chunked\r\n"
                               "\r\n"
                               "5\r\nhello\r\n0\r\n\r\n"};

    ASSERT_EQ(Feed::Reject, feedChunks(parser, {request}));
    EXPECT_EQ(411, parser.rejectStatus());
}

TEST(RequestParserTest, DetectsChunkedRegardlessOfHeaderCase)
{
    RequestParser parser {defaultLimits()};
    const std::string request {"POST /inventory/sync HTTP/1.1\r\n"
                               "Host: localhost\r\n"
                               "TRANSFER-ENCODING: Chunked\r\n"
                               "\r\n"};

    ASSERT_EQ(Feed::Reject, feedChunks(parser, {request}));
    EXPECT_EQ(411, parser.rejectStatus());
}

// The decision is taken from the DECLARED length, so an oversized body costs nothing to refuse.
TEST(RequestParserTest, RejectsOversizedContentLengthWith413BeforeAnyBodyByte)
{
    auto limits = defaultLimits();
    limits.maxBodySize = 16;

    RequestParser parser {limits};
    const std::string request {"POST /inventory/sync HTTP/1.1\r\n"
                               "Host: localhost\r\n"
                               "Content-Length: 1000\r\n"
                               "\r\n"};

    ASSERT_EQ(Feed::Reject, feedChunks(parser, {request}));
    EXPECT_EQ(413, parser.rejectStatus());
    EXPECT_TRUE(parser.request().body.empty()) << "no body byte may be buffered for a request we refuse";
}

TEST(RequestParserTest, AcceptsABodyExactlyAtTheCap)
{
    auto limits = defaultLimits();
    limits.maxBodySize = 8;

    RequestParser parser {limits};
    ASSERT_EQ(Feed::Complete, feedChunks(parser, {peerRequest("12345678")}));
    EXPECT_EQ("12345678", parser.request().body);
}

TEST(RequestParserTest, RejectsOversizedUrlWith414)
{
    auto limits = defaultLimits();
    limits.maxUrlSize = 16;

    RequestParser parser {limits};
    const std::string request {"POST /" + std::string(64, 'a') +
                               " HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"};

    ASSERT_EQ(Feed::Reject, feedChunks(parser, {request}));
    EXPECT_EQ(414, parser.rejectStatus());
}

TEST(RequestParserTest, RejectsOversizedHeaderValueWith431)
{
    auto limits = defaultLimits();
    limits.maxHeaderValueSize = 16;

    RequestParser parser {limits};
    const std::string request {"POST /x HTTP/1.1\r\nHost: localhost\r\nX-Big: " + std::string(64, 'v') +
                               "\r\nContent-Length: 0\r\n\r\n"};

    ASSERT_EQ(Feed::Reject, feedChunks(parser, {request}));
    EXPECT_EQ(431, parser.rejectStatus());
}

TEST(RequestParserTest, RejectsOversizedHeaderNameWith431)
{
    auto limits = defaultLimits();
    limits.maxHeaderNameSize = 8;

    RequestParser parser {limits};
    const std::string request {"POST /x HTTP/1.1\r\nHost: localhost\r\nX-" + std::string(64, 'n') +
                               ": v\r\nContent-Length: 0\r\n\r\n"};

    ASSERT_EQ(Feed::Reject, feedChunks(parser, {request}));
    EXPECT_EQ(431, parser.rejectStatus());
}

TEST(RequestParserTest, RejectsTooManyHeadersWith431)
{
    auto limits = defaultLimits();
    limits.maxHeaderCount = 3;

    RequestParser parser {limits};
    std::string request {"POST /x HTTP/1.1\r\n"};
    for (int i = 0; i < 20; ++i)
    {
        request += "X-H" + std::to_string(i) + ": v\r\n";
    }
    request += "Content-Length: 0\r\n\r\n";

    ASSERT_EQ(Feed::Reject, feedChunks(parser, {request}));
    EXPECT_EQ(431, parser.rejectStatus());
}

// Malformed input must never reach a handler, and must be distinguishable from a limit we enforced
// (which is what rejectStatus() is for).
TEST(RequestParserTest, MalformedRequestLineIsAProtocolError)
{
    RequestParser parser {defaultLimits()};
    ASSERT_EQ(Feed::ProtocolError, feedChunks(parser, {"NOT-HTTP AT ALL\r\n\r\n"}));
    EXPECT_EQ(0, parser.rejectStatus());
}

TEST(RequestParserTest, GarbageBytesAreAProtocolError)
{
    RequestParser parser {defaultLimits()};
    ASSERT_EQ(Feed::ProtocolError, feedChunks(parser, {std::string {"\x01\x02\x03\xff\xfe", 5}}));
}

TEST(RequestParserTest, PeerClosingMidRequestIsAProtocolError)
{
    RequestParser parser {defaultLimits()};
    const auto request = peerRequest("full-body");

    // Head plus one body byte, then the peer goes away.
    const auto truncated = request.substr(0, request.size() - 3);
    EXPECT_EQ(Feed::Incomplete, feedChunks(parser, {truncated}));
    EXPECT_EQ(Feed::ProtocolError, parser.finish());
}

TEST(RequestParserTest, FinishAfterACompleteRequestReportsComplete)
{
    RequestParser parser {defaultLimits()};
    ASSERT_EQ(Feed::Complete, feedChunks(parser, {peerRequest()}));
    EXPECT_EQ(Feed::Complete, parser.finish());
}

// Once spent, the verdict is stable: a caller that is mid-teardown cannot accidentally resurrect the
// parser and get a different answer.
TEST(RequestParserTest, VerdictIsStableAfterRejection)
{
    auto limits = defaultLimits();
    limits.maxBodySize = 4;

    RequestParser parser {limits};
    const std::string request {"POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 999\r\n\r\n"};

    ASSERT_EQ(Feed::Reject, feedChunks(parser, {request}));
    EXPECT_EQ(Feed::Reject, parser.feed("more", 4));
    EXPECT_EQ(Feed::Reject, parser.resume());
    EXPECT_EQ(413, parser.rejectStatus());
}

// A rejection is decided inside on_headers_complete, which llhttp reserves non-zero returns for
// ("no body" and "upgrade"). Returning one of those to signal a rejection would silently change the
// parse instead of stopping it, so the decision has to travel out through rejectStatus().
TEST(RequestParserTest, RejectionDecidedAtHeadersCompleteDoesNotSkipToTheNextMessage)
{
    auto limits = defaultLimits();
    limits.maxBodySize = 2;

    RequestParser parser {limits};
    // A second request follows the first in the same buffer. If the rejection were signalled by
    // returning 1 from on_headers_complete, llhttp would treat the first body as a new message and
    // could report Complete for the wrong request.
    const std::string bytes {"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 100\r\n\r\n"
                             "POST /b HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n"};

    ASSERT_EQ(Feed::Reject, feedChunks(parser, {bytes}));
    EXPECT_EQ(413, parser.rejectStatus());
    EXPECT_EQ("/a", parser.request().target) << "the verdict must belong to the first request";
}

// resume() outside the HeadersReady state is a no-op rather than a way to double-advance the parser.
TEST(RequestParserTest, ResumeBeforeHeadersReadyIsANoOp)
{
    RequestParser parser {defaultLimits()};
    EXPECT_EQ(Feed::Incomplete, parser.resume());
    EXPECT_EQ(Feed::Incomplete, parser.feed("POST /x HTTP/1.1\r\n", 18));
}

// Bytes that arrive while the caller is still deciding must not be lost -- they are body bytes.
TEST(RequestParserTest, BytesArrivingWhilePausedAreRetained)
{
    RequestParser parser {defaultLimits()};
    const auto request = peerRequest("retained");
    const auto headEnd = request.find("\r\n\r\n") + 4;

    ASSERT_EQ(Feed::HeadersReady, parser.feed(request.data(), headEnd));

    // Still paused: feed the body before resuming.
    const auto body = request.substr(headEnd);
    EXPECT_EQ(Feed::Incomplete, parser.feed(body.data(), body.size()));

    ASSERT_EQ(Feed::Complete, parser.resume());
    EXPECT_EQ("retained", parser.request().body);
}

/**
 * @brief The header limit counts LINES, not distinct names.
 *
 * It used to be compared against the size of the header map, which is keyed by lowercased name and
 * filled with insert_or_assign -- so repeating one name never grew it and the limit bounded nothing at
 * all. A peer could send `x-a: <8 KiB>` without end, held back only by the header timeout, while the
 * in-flight byte budget charged a per-request overhead computed from that very limit.
 *
 * The existing RejectsTooManyHeadersWith431 uses distinct names, so it never covered this.
 */
TEST(RequestParserTest, RepeatedHeaderNamesConsumeTheHeaderCountQuota)
{
    RequestParser::Limits limits;
    limits.maxHeaderCount = 4;
    RequestParser parser {limits};

    std::string request {"POST /inventory/sync HTTP/1.1\r\nHost: localhost\r\n"};
    // One name, repeated well past the limit.
    for (int i = 0; i < 40; ++i)
    {
        request += "x-repeated: filler\r\n";
    }
    request += "Content-Length: 0\r\n\r\n";

    const auto verdict = parser.feed(request.data(), request.size());

    EXPECT_EQ(RequestParser::Feed::Reject, verdict) << "repeating one header name must still exhaust the quota";
    EXPECT_EQ(431, parser.rejectStatus());
}
