/*
 * Wazuh remoted module (C++ worker bridge) - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "common/zstdDecoder.hpp"
#include "common/zstdEncoder.hpp"
#include "http_server/IHttpServer.hpp"
#include "http_server/compressingResponder.hpp"
#include "http_server/inFlightBudget.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

using remoted::common::zstdDecode;
using remoted::common::ZstdEncoder;
using remoted::http::CompressingResponder;
using remoted::http::HttpResponse;
using remoted::http::IByteSource;
using remoted::http::IHttpResponder;
using remoted::http::InFlightBudget;
using remoted::http::StreamResponse;

namespace
{
    bool alwaysReserve(std::size_t)
    {
        return true;
    }

    class StringSource final : public IByteSource
    {
    public:
        explicit StringSource(std::string data)
            : m_data {std::move(data)}
        {
        }

        std::size_t read(char* buffer, std::size_t capacity) override
        {
            const auto count = std::min(capacity, m_data.size() - m_offset);
            std::memcpy(buffer, m_data.data() + m_offset, count);
            m_offset += count;
            return count;
        }

    private:
        std::string m_data;
        std::size_t m_offset {0};
    };

    /// Records what the layer underneath receives. By default it keeps the stream so a test can
    /// drain it; with dropStreams it discards it the way a responder that already answered does.
    class RecordingResponder final : public IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            sent = std::move(response);
        }

        void stream(StreamResponse response) override
        {
            ++streamCalls;
            if (!dropStreams)
            {
                received = std::move(response);
            }
        }

        std::string drainStream() const
        {
            std::string collected;
            std::string buffer(4096, '\0');
            while (const auto count = received->source->read(buffer.data(), buffer.size()))
            {
                collected.append(buffer.data(), count);
            }
            return collected;
        }

        std::optional<HttpResponse> sent;
        std::optional<StreamResponse> received;
        int streamCalls {0};
        bool dropStreams {false};
    };

    std::string headerOf(const StreamResponse& response, const std::string& name)
    {
        for (const auto& [key, value] : response.headers)
        {
            if (key == name)
            {
                return value;
            }
        }
        return {};
    }

    /// A responder over a real budget, counting how often the compressor's memory is asked for.
    struct Fixture
    {
        explicit Fixture(std::size_t budgetBytes = 64U * 1024U * 1024U)
            : budget {budgetBytes}
            , inner {std::make_shared<RecordingResponder>()}
            , responder {inner,
                         [this](std::size_t bytes)
                         {
                             ++reserveCalls;
                             return budget.tryReserveUncounted(bytes);
                         }}
        {
        }

        StreamResponse streamOf(std::string body) const
        {
            StreamResponse response;
            response.headers.emplace_back("Content-Type", "application/octet-stream");
            response.source = std::make_shared<StringSource>(std::move(body));
            return response;
        }

        InFlightBudget budget;
        std::shared_ptr<RecordingResponder> inner;
        int reserveCalls {0};
        CompressingResponder responder;
    };
} // namespace

TEST(CompressingResponder, SendIsDelegatedUntouched)
{
    Fixture fixture;
    auto response = HttpResponse::json(404, R"({"error":"Resource not found","code":404})");

    fixture.responder.send(response);

    ASSERT_TRUE(fixture.inner->sent.has_value());
    EXPECT_EQ(fixture.inner->sent->status, 404);
    EXPECT_EQ(fixture.inner->sent->body, response.body);
    EXPECT_EQ(fixture.inner->sent->headers, response.headers) << "an error body must carry no Content-Encoding";
    EXPECT_EQ(fixture.reserveCalls, 0) << "a buffered answer must not cost any compressor memory";
}

TEST(CompressingResponder, CompressesAStreamAndSaysSo)
{
    Fixture fixture;
    const std::string plain(100000, 'x');

    fixture.responder.stream(fixture.streamOf(plain));

    ASSERT_EQ(fixture.inner->streamCalls, 1);
    EXPECT_EQ(headerOf(*fixture.inner->received, "Content-Encoding"), "zstd");
    EXPECT_EQ(headerOf(*fixture.inner->received, "Content-Type"), "application/octet-stream")
        << "the handler's own headers are kept";

    const auto frame = fixture.inner->drainStream();
    EXPECT_LT(frame.size(), plain.size());
    const auto decoded = zstdDecode(frame, alwaysReserve, alwaysReserve);
    ASSERT_TRUE(std::holds_alternative<std::string>(decoded));
    EXPECT_EQ(std::get<std::string>(decoded), plain);
}

TEST(CompressingResponder, ChargesTheCompressorToTheBudgetUntilTheTransferEnds)
{
    Fixture fixture;
    const auto before = fixture.budget.availableBytes();

    fixture.responder.stream(fixture.streamOf("some configuration"));

    EXPECT_EQ(fixture.reserveCalls, 1);
    EXPECT_EQ(fixture.budget.availableBytes(), before - ZstdEncoder::memoryRequired());

    fixture.inner->drainStream();
    EXPECT_EQ(fixture.budget.availableBytes(), before - ZstdEncoder::memoryRequired())
        << "the memory is held until the transfer drops its source, not when the last byte is read";

    fixture.inner->received.reset();
    EXPECT_EQ(fixture.budget.availableBytes(), before);
}

TEST(CompressingResponder, AResponseMarkedNotCompressibleIsPassedThroughUntouched)
{
    Fixture fixture;
    const auto before = fixture.budget.availableBytes();
    auto response = fixture.streamOf("an already compressed wpk");
    const auto* source = response.source.get();
    response.compressible = false;

    fixture.responder.stream(std::move(response));

    ASSERT_EQ(fixture.inner->streamCalls, 1);
    EXPECT_EQ(fixture.inner->received->source.get(), source) << "the source must not be wrapped";
    EXPECT_EQ(headerOf(*fixture.inner->received, "Content-Encoding"), "");
    EXPECT_EQ(fixture.reserveCalls, 0);
    EXPECT_EQ(fixture.budget.availableBytes(), before);
    EXPECT_EQ(fixture.inner->drainStream(), "an already compressed wpk");
}

TEST(CompressingResponder, ARefusedReservationServesThePlainBody)
{
    // Room for the request but not for a compressor: the response degrades to what every client
    // has to accept anyway.
    Fixture fixture {ZstdEncoder::memoryRequired() / 2};
    auto response = fixture.streamOf("plain when there is no room");
    const auto* source = response.source.get();

    fixture.responder.stream(std::move(response));

    ASSERT_EQ(fixture.inner->streamCalls, 1);
    EXPECT_EQ(fixture.reserveCalls, 1);
    EXPECT_EQ(fixture.inner->received->source.get(), source);
    EXPECT_EQ(headerOf(*fixture.inner->received, "Content-Encoding"), "") << "no header when no compression";
    EXPECT_EQ(fixture.inner->drainStream(), "plain when there is no room");
}

TEST(CompressingResponder, ABudgetThatRefusesEverythingServesPlain)
{
    auto inner = std::make_shared<RecordingResponder>();
    CompressingResponder refusing {inner, [](std::size_t) { return std::optional<InFlightBudget::Reservation> {}; }};

    StreamResponse response;
    response.source = std::make_shared<StringSource>("x");
    refusing.stream(std::move(response));

    ASSERT_EQ(inner->streamCalls, 1);
    EXPECT_TRUE(inner->received->headers.empty());
}

TEST(CompressingResponder, AStreamWithoutASourceReachesTheTransportUntouched)
{
    // The transport answers 500 for it; this layer must not hide that behind a compressor.
    Fixture fixture;
    StreamResponse response;

    fixture.responder.stream(std::move(response));

    ASSERT_EQ(fixture.inner->streamCalls, 1);
    EXPECT_EQ(fixture.inner->received->source, nullptr);
    EXPECT_EQ(fixture.reserveCalls, 0);
    EXPECT_TRUE(fixture.inner->received->headers.empty());
}

TEST(CompressingResponder, ReleasesTheReservationWhenTheLayerBelowDropsTheResponse)
{
    // A responder that already answered discards a second stream(); its source, and the compressor
    // memory it carries, must go with it.
    Fixture fixture;
    fixture.inner->dropStreams = true;
    const auto before = fixture.budget.availableBytes();

    fixture.responder.stream(fixture.streamOf("never sent"));

    EXPECT_EQ(fixture.inner->streamCalls, 1);
    EXPECT_EQ(fixture.budget.availableBytes(), before);
}

TEST(CompressingResponder, TransfersDoNotShareACompressor)
{
    Fixture fixture;
    const auto before = fixture.budget.availableBytes();
    auto second = std::make_shared<RecordingResponder>();
    CompressingResponder other {second,
                                [&fixture](std::size_t bytes) { return fixture.budget.tryReserveUncounted(bytes); }};

    fixture.responder.stream(fixture.streamOf("first"));
    other.stream(fixture.streamOf("second"));

    EXPECT_EQ(fixture.budget.availableBytes(), before - 2 * ZstdEncoder::memoryRequired());
    const auto first = zstdDecode(fixture.inner->drainStream(), alwaysReserve, alwaysReserve);
    const auto secondFrame = zstdDecode(second->drainStream(), alwaysReserve, alwaysReserve);
    ASSERT_TRUE(std::holds_alternative<std::string>(first));
    ASSERT_TRUE(std::holds_alternative<std::string>(secondFrame));
    EXPECT_EQ(std::get<std::string>(first), "first");
    EXPECT_EQ(std::get<std::string>(secondFrame), "second");
}
