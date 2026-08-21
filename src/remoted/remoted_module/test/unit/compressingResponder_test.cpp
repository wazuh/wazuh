/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * August 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "http_server/compressingResponder.hpp"

#include "common/zstdDecoder.hpp"
#include "http_server/inFlightBudget.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <variant>

using remoted::common::zstdDecode;
using remoted::http::acceptsZstdResponseEncoding;
using remoted::http::HttpResponse;
using remoted::http::InFlightBudget;
using remoted::http::StreamResponse;
using remoted::http::ZstdCompressingResponder;

namespace
{
    const auto alwaysReserve = [](std::size_t)
    {
        return true;
    };

    class FakePlainSource final : public remoted::http::IByteSource
    {
    public:
        explicit FakePlainSource(std::string contents)
            : m_contents {std::move(contents)}
        {
        }

        std::size_t read(char* buffer, std::size_t capacity) override
        {
            const auto remaining = m_contents.size() - m_served;
            const auto slice = remaining < capacity ? remaining : capacity;
            std::memcpy(buffer, m_contents.data() + m_served, slice);
            m_served += slice;
            return slice;
        }

    private:
        std::string m_contents;
        std::size_t m_served {0};
    };

    /// Records whichever delivery the wrapper forwards, draining a streamed body like the
    /// transport would.
    class RecordingResponder final : public remoted::http::IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            sent = true;
            status = response.status;
            body = std::move(response.body);
        }

        void stream(StreamResponse response) override
        {
            streamed = true;
            status = response.status;
            headers = response.headers;
            source = response.source;

            std::string chunk(64U * 1024U, '\0');
            while (true)
            {
                const auto bytesRead = response.source->read(chunk.data(), chunk.size());
                if (bytesRead == 0)
                {
                    break;
                }
                body.append(chunk.data(), bytesRead);
            }
        }

        bool sent {false};
        bool streamed {false};
        int status {0};
        std::string body;
        std::vector<std::pair<std::string, std::string>> headers;
        std::shared_ptr<remoted::http::IByteSource> source;
    };

    bool hasZstdContentEncoding(const std::vector<std::pair<std::string, std::string>>& headers)
    {
        for (const auto& [name, value] : headers)
        {
            if (name == "Content-Encoding" && value == "zstd")
            {
                return true;
            }
        }
        return false;
    }

    StreamResponse streamResponseOver(std::string contents)
    {
        StreamResponse response;
        response.status = 200;
        response.headers.emplace_back("Content-Type", "application/octet-stream");
        response.source = std::make_shared<FakePlainSource>(std::move(contents));
        return response;
    }

    std::string repetitiveText(std::size_t size)
    {
        static const std::string line {"<agent_config>merged shared configuration</agent_config>\n"};
        std::string text;
        while (text.size() < size)
        {
            text += line;
        }
        text.resize(size);
        return text;
    }
} // namespace

// ---------------------------------------------------------------------------
// Accept-Encoding negotiation
// ---------------------------------------------------------------------------

TEST(AcceptsZstdResponseEncodingTest, AcceptsThePlainToken)
{
    EXPECT_TRUE(acceptsZstdResponseEncoding("zstd"));
    EXPECT_TRUE(acceptsZstdResponseEncoding("ZSTD")); // codings are case-insensitive
    EXPECT_TRUE(acceptsZstdResponseEncoding(" zstd "));
}

TEST(AcceptsZstdResponseEncodingTest, FindsZstdInAnElementList)
{
    EXPECT_TRUE(acceptsZstdResponseEncoding("gzip, zstd"));
    EXPECT_TRUE(acceptsZstdResponseEncoding("gzip;q=1.0, zstd;q=0.5, br;q=0.1"));
    EXPECT_TRUE(acceptsZstdResponseEncoding("zstd ; q=0.5"));
}

TEST(AcceptsZstdResponseEncodingTest, RejectsAbsentOrForeignCodings)
{
    EXPECT_FALSE(acceptsZstdResponseEncoding(""));
    EXPECT_FALSE(acceptsZstdResponseEncoding("gzip"));
    EXPECT_FALSE(acceptsZstdResponseEncoding("gzip, br"));
    EXPECT_FALSE(acceptsZstdResponseEncoding("notzstd"));
    EXPECT_FALSE(acceptsZstdResponseEncoding("zstd2"));
}

TEST(AcceptsZstdResponseEncodingTest, TheWildcardIsDeliberatelyNotHonored)
{
    EXPECT_FALSE(acceptsZstdResponseEncoding("*"));
    EXPECT_FALSE(acceptsZstdResponseEncoding("*;q=1.0"));
}

TEST(AcceptsZstdResponseEncodingTest, AZeroQualityMeansNotAcceptable)
{
    EXPECT_FALSE(acceptsZstdResponseEncoding("zstd;q=0"));
    EXPECT_FALSE(acceptsZstdResponseEncoding("zstd;q=0.000"));
    EXPECT_TRUE(acceptsZstdResponseEncoding("zstd;q=0.001"));
}

// ---------------------------------------------------------------------------
// The responder wrapper
// ---------------------------------------------------------------------------

TEST(ZstdCompressingResponderTest, CompressesAStreamedResponse)
{
    const auto plain = repetitiveText(200U * 1024U);
    InFlightBudget budget {64U * 1024U * 1024U};
    auto inner = std::make_shared<RecordingResponder>();
    ZstdCompressingResponder responder {inner, &budget};

    responder.stream(streamResponseOver(plain));

    ASSERT_TRUE(inner->streamed);
    EXPECT_TRUE(hasZstdContentEncoding(inner->headers));
    EXPECT_LT(inner->body.size(), plain.size() / 5);

    const auto decoded = zstdDecode(inner->body, alwaysReserve, alwaysReserve);
    ASSERT_TRUE(std::holds_alternative<std::string>(decoded));
    EXPECT_EQ(std::get<std::string>(decoded), plain);

    // The transfer has been drained and the recorder is the last owner of the wrapped source:
    // its reservation must be back in the budget once the source is dropped.
    inner->source.reset();
    EXPECT_EQ(budget.availableBytes(), budget.maxBytes());
}

TEST(ZstdCompressingResponderTest, ServesPlainWhenTheResponseOptsOut)
{
    const std::string plain = "already-compressed WPK bytes";
    InFlightBudget budget {64U * 1024U * 1024U};
    auto inner = std::make_shared<RecordingResponder>();
    ZstdCompressingResponder responder {inner, &budget};

    auto response = streamResponseOver(plain);
    response.compressible = false;
    responder.stream(std::move(response));

    ASSERT_TRUE(inner->streamed);
    EXPECT_FALSE(hasZstdContentEncoding(inner->headers));
    EXPECT_EQ(inner->body, plain);
    EXPECT_EQ(budget.availableBytes(), budget.maxBytes()); // nothing was ever reserved
}

TEST(ZstdCompressingResponderTest, ServesPlainWhenTheBudgetHasNoRoom)
{
    const std::string plain = "merged configuration";
    // Enabled but far below the compressor's working memory: the reservation is refused.
    InFlightBudget budget {1024U};
    auto inner = std::make_shared<RecordingResponder>();
    ZstdCompressingResponder responder {inner, &budget};

    responder.stream(streamResponseOver(plain));

    ASSERT_TRUE(inner->streamed);
    EXPECT_FALSE(hasZstdContentEncoding(inner->headers));
    EXPECT_EQ(inner->body, plain);
}

TEST(ZstdCompressingResponderTest, ServesPlainWithoutABudget)
{
    const std::string plain = "merged configuration";
    auto inner = std::make_shared<RecordingResponder>();
    ZstdCompressingResponder responder {inner, nullptr};

    responder.stream(streamResponseOver(plain));

    ASSERT_TRUE(inner->streamed);
    EXPECT_FALSE(hasZstdContentEncoding(inner->headers));
    EXPECT_EQ(inner->body, plain);
}

TEST(ZstdCompressingResponderTest, BufferedResponsesPassThroughUntouched)
{
    InFlightBudget budget {64U * 1024U * 1024U};
    auto inner = std::make_shared<RecordingResponder>();
    ZstdCompressingResponder responder {inner, &budget};

    responder.send(HttpResponse::json(404, R"({"error":"Resource not found","code":404})"));

    ASSERT_TRUE(inner->sent);
    EXPECT_FALSE(inner->streamed);
    EXPECT_EQ(inner->status, 404);
    EXPECT_EQ(inner->body, R"({"error":"Resource not found","code":404})");
}
