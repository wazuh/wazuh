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
#include "http_server/responseEncoding.hpp"
#include "http_server/zstdResponseEncoding.hpp"
#include "zstdTestHelper.hpp"

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
using remoted::http::HttpRequest;
using remoted::http::HttpResponse;
using remoted::http::IByteSource;
using remoted::http::IHttpResponder;
using remoted::http::InFlightBudget;
using remoted::http::IResponseEncoding;
using remoted::http::makeResponseEncodingDecorator;
using remoted::http::makeZstdResponseDecorator;
using remoted::http::ReserveBytesFn;
using remoted::http::StreamResponse;
using remoted::http::ZstdResponseEncoding;
using remoted::testutil::alwaysReserve;

namespace
{
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
                         std::make_shared<const ZstdResponseEncoding>(),
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
    CompressingResponder refusing {inner,
                                   std::make_shared<const ZstdResponseEncoding>(),
                                   [](std::size_t) { return std::optional<InFlightBudget::Reservation> {}; }};

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
                                std::make_shared<const ZstdResponseEncoding>(),
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

// ---------------------------------------------------------------------------
// Codec neutrality and negotiation: nothing below mentions zstd except where it is the codec under test
// ---------------------------------------------------------------------------

namespace
{
    /// A stand-in coding: prefixes the body with "ENC:". Proves the decorator and the factory work
    /// for any IResponseEncoding, not just the one the manager ships.
    class FakeEncoding final : public IResponseEncoding
    {
    public:
        explicit FakeEncoding(std::string token, std::size_t memory = 1000)
            : m_token {std::move(token)}
            , m_memory {memory}
        {
        }

        std::string_view token() const noexcept override
        {
            return m_token;
        }

        std::size_t memoryRequired() const override
        {
            return m_memory;
        }

        std::shared_ptr<IByteSource> wrap(std::shared_ptr<IByteSource> inner,
                                          InFlightBudget::Reservation reservation) const override
        {
            return std::make_shared<PrefixSource>(std::move(inner), std::move(reservation));
        }

    private:
        class PrefixSource final : public IByteSource
        {
        public:
            PrefixSource(std::shared_ptr<IByteSource> inner, InFlightBudget::Reservation reservation)
                : m_inner {std::move(inner)}
                , m_reservation {std::move(reservation)}
            {
            }

            std::size_t read(char* buffer, std::size_t capacity) override
            {
                if (!m_prefixed)
                {
                    m_prefixed = true;
                    std::memcpy(buffer, "ENC:", 4);
                    return 4;
                }
                return m_inner->read(buffer, capacity);
            }

        private:
            std::shared_ptr<IByteSource> m_inner;
            InFlightBudget::Reservation m_reservation;
            bool m_prefixed {false};
        };

        std::string m_token;
        std::size_t m_memory;
    };

    HttpRequest requestOffering(const std::string& acceptEncoding, const std::string& headerName = "Accept-Encoding")
    {
        HttpRequest request;
        if (!acceptEncoding.empty())
        {
            request.headers.emplace(headerName, acceptEncoding);
        }
        return request;
    }

    /// Runs @p responder's stream() and returns what the transport underneath received.
    std::shared_ptr<RecordingResponder> streamThrough(const std::shared_ptr<IHttpResponder>& responder,
                                                      const std::shared_ptr<RecordingResponder>& transport,
                                                      std::string body = "body")
    {
        StreamResponse response;
        response.source = std::make_shared<StringSource>(std::move(body));
        responder->stream(std::move(response));
        return transport;
    }

    ReserveBytesFn reserveFrom(InFlightBudget& budget, int* calls = nullptr)
    {
        return [&budget, calls](std::size_t bytes)
        {
            if (calls != nullptr)
            {
                ++*calls;
            }
            return budget.tryReserveUncounted(bytes);
        };
    }
} // namespace

TEST(CompressingResponder, WorksForAnyEncodingItIsGiven)
{
    InFlightBudget budget {1024U * 1024U};
    auto transport = std::make_shared<RecordingResponder>();
    CompressingResponder responder {
        transport, std::make_shared<const FakeEncoding>("x-test", 1000), reserveFrom(budget)};

    StreamResponse response;
    response.source = std::make_shared<StringSource>("abc");
    responder.stream(std::move(response));

    EXPECT_EQ(headerOf(*transport->received, "Content-Encoding"), "x-test");
    EXPECT_EQ(transport->drainStream(), "ENC:abc");
    EXPECT_EQ(budget.availableBytes(), 1024U * 1024U - 1000U)
        << "the encoding's own memoryRequired() is what is reserved";

    transport->received.reset();
    EXPECT_EQ(budget.availableBytes(), 1024U * 1024U);
}

TEST(ResponseEncodingDecorator, LeavesTheResponderAloneWhenNothingIsOffered)
{
    InFlightBudget budget {1024U * 1024U};
    auto transport = std::make_shared<RecordingResponder>();
    const auto decorate = makeResponseEncodingDecorator({std::make_shared<const FakeEncoding>("x-test")});

    EXPECT_EQ(decorate(requestOffering(""), transport, reserveFrom(budget)), transport) << "no Accept-Encoding at all";
    EXPECT_EQ(decorate(requestOffering("gzip, br"), transport, reserveFrom(budget)), transport) << "none of ours";
    EXPECT_EQ(decorate(requestOffering("x-test;q=0"), transport, reserveFrom(budget)), transport) << "refused";
    EXPECT_EQ(decorate(requestOffering("*"), transport, reserveFrom(budget)), transport) << "wildcard is not an offer";
}

TEST(ResponseEncodingDecorator, WrapsWhenTheClientOffersACodingTheServerHas)
{
    InFlightBudget budget {1024U * 1024U};
    auto transport = std::make_shared<RecordingResponder>();
    const auto decorate = makeResponseEncodingDecorator({std::make_shared<const FakeEncoding>("x-test")});

    const auto decorated = decorate(requestOffering("gzip, x-test"), transport, reserveFrom(budget));

    ASSERT_NE(decorated, transport);
    streamThrough(decorated, transport);
    EXPECT_EQ(headerOf(*transport->received, "Content-Encoding"), "x-test");
}

TEST(ResponseEncodingDecorator, ReadsTheHeaderWhateverCaseTheTransportReportsIt)
{
    InFlightBudget budget {1024U * 1024U};
    auto transport = std::make_shared<RecordingResponder>();
    const auto decorate = makeResponseEncodingDecorator({std::make_shared<const FakeEncoding>("x-test")});

    for (const auto* name : {"Accept-Encoding", "accept-encoding", "ACCEPT-ENCODING"})
    {
        EXPECT_NE(decorate(requestOffering("X-TEST", name), transport, reserveFrom(budget)), transport) << name;
    }
}

TEST(ResponseEncodingDecorator, TheServersPreferenceDecidesWhenTheClientOffersSeveral)
{
    InFlightBudget budget {1024U * 1024U};
    const auto decorate = makeResponseEncodingDecorator(
        {std::make_shared<const FakeEncoding>("x-first"), std::make_shared<const FakeEncoding>("x-second")});

    // The client lists its second choice first; the server's order still wins.
    auto both = std::make_shared<RecordingResponder>();
    streamThrough(decorate(requestOffering("x-second, x-first"), both, reserveFrom(budget)), both);
    EXPECT_EQ(headerOf(*both->received, "Content-Encoding"), "x-first");

    // And a client that only offers the less preferred one gets that one.
    auto only = std::make_shared<RecordingResponder>();
    streamThrough(decorate(requestOffering("x-second"), only, reserveFrom(budget)), only);
    EXPECT_EQ(headerOf(*only->received, "Content-Encoding"), "x-second");
}

TEST(ResponseEncodingDecorator, UsesTheReserveFunctionTheTransportHandsIt)
{
    InFlightBudget budget {1024U * 1024U};
    int calls = 0;
    auto transport = std::make_shared<RecordingResponder>();
    const auto decorate = makeResponseEncodingDecorator({std::make_shared<const FakeEncoding>("x-test")});

    streamThrough(decorate(requestOffering("x-test"), transport, reserveFrom(budget, &calls)), transport);

    EXPECT_EQ(calls, 1);
}

TEST(ResponseEncodingDecorator, ZstdIsJustOneEncodingBehindTheSameHook)
{
    InFlightBudget budget {64U * 1024U * 1024U};
    auto transport = std::make_shared<RecordingResponder>();
    const auto decorate = makeZstdResponseDecorator();
    const std::string plain(50000, 'x');

    streamThrough(
        decorate(requestOffering("deflate, gzip, br, zstd"), transport, reserveFrom(budget)), transport, plain);

    EXPECT_EQ(headerOf(*transport->received, "Content-Encoding"), "zstd");
    const auto decoded = zstdDecode(transport->drainStream(), alwaysReserve, alwaysReserve);
    ASSERT_TRUE(std::holds_alternative<std::string>(decoded));
    EXPECT_EQ(std::get<std::string>(decoded), plain);
}
