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

// Compressed responses: every request asks for gzip, a gzip body is delivered decoded, the
// response cap counts decoded bytes (a gzip bomb is ResponseTooLarge) and a body that does not decode is the node's
// failure (RecvError, curl 61). The blobs are built here with the zlib that libwazuhext exports.

#include <stdexcept>
#include <string>

#include <curl/curl.h>
#include <zlib.h>

#include "componentFixture.hpp"
#include "fakeIndexer.hpp"

using namespace component;
using indexer_client::testing::FakeIndexer;
using indexer_client::testing::Framing;
using indexer_client::testing::Rule;

namespace
{
    constexpr std::size_t CAP = 64 * 1024;

    /// `input` as a gzip member (RFC 1952), at the best compression level.
    std::string gzip(const std::string& input)
    {
        z_stream stream {};
        if (deflateInit2(&stream, Z_BEST_COMPRESSION, Z_DEFLATED, 15 + 16, 9, Z_DEFAULT_STRATEGY) != Z_OK)
        {
            throw std::runtime_error("deflateInit2 failed");
        }
        std::string output(deflateBound(&stream, static_cast<uLong>(input.size())), '\0');
        stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));
        stream.avail_in = static_cast<uInt>(input.size());
        stream.next_out = reinterpret_cast<Bytef*>(output.data());
        stream.avail_out = static_cast<uInt>(output.size());
        const int rc = deflate(&stream, Z_FINISH);
        output.resize(stream.total_out);
        deflateEnd(&stream);
        if (rc != Z_STREAM_END)
        {
            throw std::runtime_error("deflate did not finish");
        }
        return output;
    }

    /// A JSON document of about `size` bytes (repetitive, so it compresses well).
    std::string jsonOf(std::size_t size)
    {
        std::string json {"{\"hits\":["};
        while (json.size() < size)
        {
            json += "{\"_id\":\"" + std::to_string(json.size()) + "\",\"_source\":{\"agent\":{\"name\":\"a\"}}},";
        }
        json += "{}]}";
        return json;
    }

    Rule gzipRule(const std::string& path, std::string body)
    {
        Rule rule;
        rule.pathRegex = path;
        rule.body = std::move(body);
        rule.headers = {{"Content-Encoding", "gzip"}};
        return rule;
    }
} // namespace

class TransportGzipTest : public TransportTest
{
};

// Every request announces gzip, and only gzip (no deflate, br or zstd).
TEST_F(TransportGzipTest, RequestsGzip)
{
    FakeIndexer fake;
    fake.start();
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    const auto get = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/get"));
    const auto post = submitTo(*transport,
                               collector,
                               request(HttpMethod::Post,
                                       fake.baseUrl() + "/_bulk",
                                       std::make_shared<const std::string>("{\"index\":{}}\n{}\n")));
    const auto head = submitTo(*transport, collector, request(HttpMethod::Head, fake.baseUrl() + "/head"));
    ASSERT_TRUE(collector->waitTotal(3, 10s));
    for (const auto* one : {&get, &post, &head})
    {
        EXPECT_EQ(collector->result(one->key)->cause, TransportCause::None);
    }

    const auto received = fake.requests();
    ASSERT_EQ(received.size(), 3u);
    for (const auto& got : received)
    {
        EXPECT_EQ(got.headers.count("Accept-Encoding"), 1u) << got.method << " " << got.path;
        const auto encoding = got.headers.find("Accept-Encoding");
        ASSERT_NE(encoding, got.headers.end()) << got.method << " " << got.path;
        EXPECT_EQ(encoding->second, "gzip") << got.method << " " << got.path;
    }
}

// A gzip body (Content-Length and chunked) is delivered decoded, byte for byte.
TEST_F(TransportGzipTest, DecodesGzipBody)
{
    const auto original = jsonOf(20000);
    const auto compressed = gzip(original);
    ASSERT_LT(compressed.size(), original.size());

    FakeIndexer fake;
    fake.addRule(gzipRule("/fixed", compressed));
    auto chunked = gzipRule("/chunked", compressed);
    chunked.framing = Framing::Chunked;
    chunked.chunkSize = 100;
    fake.addRule(chunked);
    fake.start();
    auto transport = startRuntime(1, 2, {{"max_response_bytes", std::to_string(CAP)}});
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    const auto fixed = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/fixed"));
    const auto streamed = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/chunked"));
    ASSERT_TRUE(collector->waitTotal(2, 10s));
    for (const auto* one : {&fixed, &streamed})
    {
        const auto result = collector->result(one->key);
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->cause, TransportCause::None)
            << indexer_client::detail::toString(result->cause) << " (curl " << result->curlCode << ")";
        EXPECT_EQ(result->status, 200);
        EXPECT_EQ(result->body.size(), original.size());
        EXPECT_TRUE(result->body == original) << "the body was not decoded";
    }
}

// A gzip bomb: at most 4 KiB on the wire that decode to 16 times the cap. The cap counts decoded bytes, so it trips
// (ResponseTooLarge, curl 23) and the body never grows past it.
TEST_F(TransportGzipTest, BombHitsDecodedCap)
{
    const auto bomb = gzip(std::string(16 * CAP, '0'));
    ASSERT_LE(bomb.size(), 4u * 1024u);

    FakeIndexer fake;
    fake.addRule(gzipRule("/bomb", bomb));
    fake.start();
    auto transport = startRuntime(1, 2, {{"max_response_bytes", std::to_string(CAP)}});
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    const auto one = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/bomb"));
    ASSERT_TRUE(collector->waitKey(one.key, 10s));
    const auto result = collector->result(one.key);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->cause, TransportCause::ResponseTooLarge)
        << indexer_client::detail::toString(result->cause) << " (curl " << result->curlCode << ")";
    EXPECT_EQ(result->curlCode, CURLE_WRITE_ERROR);
    EXPECT_FALSE(result->nodeAttributable);
    EXPECT_LE(result->body.size(), CAP);
}

// `Content-Encoding: gzip` over bytes that are not gzip: curl 61, the node's failure (RecvError, attributable).
TEST_F(TransportGzipTest, CorruptGzipIsRecvError)
{
    FakeIndexer fake;
    fake.addRule(gzipRule("/corrupt", "{\"this is\":\"not gzip at all\"}"));
    fake.start();
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    const auto one = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/corrupt"));
    ASSERT_TRUE(collector->waitKey(one.key, 10s));
    const auto result = collector->result(one.key);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->cause, TransportCause::RecvError)
        << indexer_client::detail::toString(result->cause) << " (curl " << result->curlCode << ")";
    EXPECT_EQ(result->curlCode, CURLE_BAD_CONTENT_ENCODING);
    EXPECT_TRUE(result->nodeAttributable);
    EXPECT_EQ(result->status, 200);
}
