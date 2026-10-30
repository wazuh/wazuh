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
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

using remoted::common::zstdDecode;
using remoted::common::ZstdEncoder;
using remoted::http::HttpRequest;
using remoted::http::IByteSource;
using remoted::http::InFlightBudget;
using remoted::http::IResponseEncoding;
using remoted::http::makeEncodingTransform;
using remoted::http::makeResponseEncodingFactory;
using remoted::http::makeZstdStreamTransformFactory;
using remoted::http::ReserveBytesFn;
using remoted::http::StreamResponse;
using remoted::http::StreamTransform;
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

    StreamResponse streamOf(std::string body)
    {
        StreamResponse response;
        response.headers.emplace_back("Content-Type", "application/octet-stream");
        response.source = std::make_shared<StringSource>(std::move(body));
        return response;
    }

    std::string drain(IByteSource& source)
    {
        std::string collected;
        std::string buffer(4096, '\0');
        while (const auto count = source.read(buffer.data(), buffer.size()))
        {
            collected.append(buffer.data(), count);
        }
        return collected;
    }

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

    std::optional<std::string> decode(const std::string& frame)
    {
        const auto result = zstdDecode(frame, alwaysReserve, alwaysReserve);
        if (const auto* text = std::get_if<std::string>(&result))
        {
            return *text;
        }
        return std::nullopt;
    }

    /// A reserve function over a real budget that counts how often it is asked.
    struct Budget
    {
        explicit Budget(std::size_t bytes = 64U * 1024U * 1024U)
            : budget {bytes}
            , initial {budget.availableBytes()}
        {
        }

        ReserveBytesFn reserve()
        {
            return [this](std::size_t bytes)
            {
                ++calls;
                return budget.tryReserveUncounted(bytes);
            };
        }

        InFlightBudget budget;
        std::size_t initial;
        int calls {0};
    };

    /// A stand-in coding that prefixes the body with "ENC:". It never touches a reservation: holding
    /// it is the transform's job, which is exactly what its tests check.
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

        std::shared_ptr<IByteSource> wrap(std::shared_ptr<IByteSource> inner) const override
        {
            return std::make_shared<PrefixSource>(std::move(inner));
        }

    private:
        class PrefixSource final : public IByteSource
        {
        public:
            explicit PrefixSource(std::shared_ptr<IByteSource> inner)
                : m_inner {std::move(inner)}
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
            bool m_prefixed {false};
        };

        std::string m_token;
        std::size_t m_memory;
    };

    /// A coding whose wrap() fails, the way an allocation can.
    class ThrowingEncoding final : public IResponseEncoding
    {
    public:
        std::string_view token() const noexcept override
        {
            return "x-boom";
        }

        std::size_t memoryRequired() const override
        {
            return 500;
        }

        std::shared_ptr<IByteSource> wrap(std::shared_ptr<IByteSource>) const override
        {
            throw std::runtime_error {"could not create the encoder"};
        }
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

    std::shared_ptr<const IResponseEncoding> zstd()
    {
        return std::make_shared<const ZstdResponseEncoding>();
    }
} // namespace

// ---------------------------------------------------------------------------
// The transform: what it does to a streamed response
// ---------------------------------------------------------------------------

TEST(EncodingTransform, EncodesAStreamAndSaysSo)
{
    Budget fixture;
    const auto transform = makeEncodingTransform(zstd(), fixture.reserve());
    const std::string plain(100000, 'x');
    auto response = streamOf(plain);

    transform(response);

    EXPECT_EQ(headerOf(response, "Content-Encoding"), "zstd");
    EXPECT_EQ(headerOf(response, "Content-Type"), "application/octet-stream") << "the handler's headers are kept";
    const auto frame = drain(*response.source);
    EXPECT_LT(frame.size(), plain.size());
    EXPECT_EQ(decode(frame), plain);
}

TEST(EncodingTransform, ChargesTheEncodingToTheBudgetUntilTheTransferEnds)
{
    Budget fixture;
    const auto transform = makeEncodingTransform(zstd(), fixture.reserve());
    auto response = streamOf("some configuration");

    transform(response);

    EXPECT_EQ(fixture.calls, 1);
    EXPECT_EQ(fixture.budget.availableBytes(), fixture.initial - ZstdEncoder::memoryRequired());

    drain(*response.source);
    EXPECT_EQ(fixture.budget.availableBytes(), fixture.initial - ZstdEncoder::memoryRequired())
        << "held until the transfer drops its source, not when the last byte is read";

    response.source.reset();
    EXPECT_EQ(fixture.budget.availableBytes(), fixture.initial);
}

TEST(EncodingTransform, AnEncodingNeverHasToKeepTheReservationItself)
{
    // FakeEncoding does nothing with a reservation, and the memory is still charged for the whole
    // transfer: holding it is the transform's job, so a codec cannot get the accounting wrong.
    Budget fixture;
    const auto transform =
        makeEncodingTransform(std::make_shared<const FakeEncoding>("x-test", 1000), fixture.reserve());
    auto response = streamOf("abc");

    transform(response);

    EXPECT_EQ(headerOf(response, "Content-Encoding"), "x-test");
    EXPECT_EQ(drain(*response.source), "ENC:abc");
    EXPECT_EQ(fixture.budget.availableBytes(), fixture.initial - 1000U);

    response.source.reset();
    EXPECT_EQ(fixture.budget.availableBytes(), fixture.initial);
}

TEST(EncodingTransform, AResponseMarkedNotCompressibleIsLeftUntouched)
{
    Budget fixture;
    const auto transform = makeEncodingTransform(zstd(), fixture.reserve());
    auto response = streamOf("an already compressed wpk");
    const auto* source = response.source.get();
    response.compressible = false;

    transform(response);

    EXPECT_EQ(response.source.get(), source) << "the source must not be wrapped";
    EXPECT_EQ(headerOf(response, "Content-Encoding"), "");
    EXPECT_EQ(fixture.calls, 0) << "no memory is reserved for a body that will not be encoded";
    EXPECT_EQ(fixture.budget.availableBytes(), fixture.initial);
    EXPECT_EQ(drain(*response.source), "an already compressed wpk");
}

TEST(EncodingTransform, ARefusedReservationLeavesThePlainBody)
{
    // Room for the request but not for an encoder: the response degrades to what every client has
    // to accept anyway.
    Budget fixture {ZstdEncoder::memoryRequired() / 2};
    const auto transform = makeEncodingTransform(zstd(), fixture.reserve());
    auto response = streamOf("plain when there is no room");
    const auto* source = response.source.get();

    transform(response);

    EXPECT_EQ(fixture.calls, 1);
    EXPECT_EQ(response.source.get(), source);
    EXPECT_EQ(headerOf(response, "Content-Encoding"), "") << "no header when nothing was encoded";
    EXPECT_EQ(drain(*response.source), "plain when there is no room");
}

TEST(EncodingTransform, AResponseWithoutASourceIsLeftUntouched)
{
    Budget fixture;
    const auto transform = makeEncodingTransform(zstd(), fixture.reserve());
    StreamResponse response;

    transform(response);

    // The transport answers 500 for it; this layer must not hide that behind an encoder.
    EXPECT_EQ(response.source, nullptr);
    EXPECT_EQ(fixture.calls, 0);
    EXPECT_TRUE(response.headers.empty());
}

TEST(EncodingTransform, ReleasesTheReservationWhenTheResponseIsDropped)
{
    // A responder that already answered discards a second stream(); the memory goes with it.
    Budget fixture;
    const auto transform = makeEncodingTransform(zstd(), fixture.reserve());

    {
        auto response = streamOf("never sent");
        transform(response);
        EXPECT_LT(fixture.budget.availableBytes(), fixture.initial);
    }

    EXPECT_EQ(fixture.budget.availableBytes(), fixture.initial);
}

TEST(EncodingTransform, AnEncodingThatFailsToWrapLeavesTheResponseUntouchedAndReleasesTheReservation)
{
    Budget fixture;
    const auto transform = makeEncodingTransform(std::make_shared<const ThrowingEncoding>(), fixture.reserve());
    auto response = streamOf("body");
    const auto* source = response.source.get();

    EXPECT_THROW(transform(response), std::runtime_error);

    EXPECT_EQ(response.source.get(), source) << "nothing is changed unless wrap() succeeded";
    EXPECT_EQ(headerOf(response, "Content-Encoding"), "");
    EXPECT_EQ(fixture.budget.availableBytes(), fixture.initial) << "the reservation must not leak";
}

TEST(EncodingTransform, TransfersDoNotShareAnEncoder)
{
    Budget fixture;
    const auto transform = makeEncodingTransform(zstd(), fixture.reserve());
    auto first = streamOf("first");
    auto second = streamOf("second");

    transform(first);
    transform(second);

    EXPECT_EQ(fixture.budget.availableBytes(), fixture.initial - 2 * ZstdEncoder::memoryRequired());
    EXPECT_EQ(decode(drain(*first.source)), "first");
    EXPECT_EQ(decode(drain(*second.source)), "second");
}

// ---------------------------------------------------------------------------
// The factory: negotiation, and the choice among codings
// ---------------------------------------------------------------------------

TEST(ResponseEncodingFactory, ChoosesNoTransformWhenNothingIsOffered)
{
    Budget fixture;
    const auto factory = makeResponseEncodingFactory({std::make_shared<const FakeEncoding>("x-test")});

    EXPECT_FALSE(factory(requestOffering(""), fixture.reserve())) << "no Accept-Encoding at all";
    EXPECT_FALSE(factory(requestOffering("gzip, br"), fixture.reserve())) << "none of ours";
    EXPECT_FALSE(factory(requestOffering("x-test;q=0"), fixture.reserve())) << "refused";
    EXPECT_FALSE(factory(requestOffering("*"), fixture.reserve())) << "a wildcard is not an offer";
    EXPECT_EQ(fixture.calls, 0) << "choosing reserves nothing";
}

TEST(ResponseEncodingFactory, ChoosesATransformWhenTheClientOffersACodingTheServerHas)
{
    Budget fixture;
    const auto factory = makeResponseEncodingFactory({std::make_shared<const FakeEncoding>("x-test")});

    const auto transform = factory(requestOffering("gzip, x-test"), fixture.reserve());

    ASSERT_TRUE(transform);
    auto response = streamOf("body");
    transform(response);
    EXPECT_EQ(headerOf(response, "Content-Encoding"), "x-test");
}

TEST(ResponseEncodingFactory, ReadsTheHeaderWhateverCaseTheTransportReportsIt)
{
    Budget fixture;
    const auto factory = makeResponseEncodingFactory({std::make_shared<const FakeEncoding>("x-test")});

    for (const auto* name : {"Accept-Encoding", "accept-encoding", "ACCEPT-ENCODING"})
    {
        EXPECT_TRUE(factory(requestOffering("X-TEST", name), fixture.reserve())) << name;
    }
}

TEST(ResponseEncodingFactory, TheServersPreferenceDecidesWhenTheClientOffersSeveral)
{
    Budget fixture;
    const auto factory = makeResponseEncodingFactory(
        {std::make_shared<const FakeEncoding>("x-first"), std::make_shared<const FakeEncoding>("x-second")});

    // The client lists its second choice first; the server's order still wins.
    auto both = streamOf("body");
    factory(requestOffering("x-second, x-first"), fixture.reserve())(both);
    EXPECT_EQ(headerOf(both, "Content-Encoding"), "x-first");

    // And a client that only offers the less preferred one gets that one.
    auto only = streamOf("body");
    factory(requestOffering("x-second"), fixture.reserve())(only);
    EXPECT_EQ(headerOf(only, "Content-Encoding"), "x-second");
}

TEST(ResponseEncodingFactory, TheTransformUsesTheReserveFunctionTheTransportHandsIt)
{
    Budget fixture;
    const auto factory = makeResponseEncodingFactory({std::make_shared<const FakeEncoding>("x-test")});

    const auto transform = factory(requestOffering("x-test"), fixture.reserve());
    EXPECT_EQ(fixture.calls, 0);

    auto response = streamOf("body");
    transform(response);
    EXPECT_EQ(fixture.calls, 1);
}

TEST(ResponseEncodingFactory, ZstdIsJustOneEncodingBehindTheSameFactory)
{
    Budget fixture;
    const auto factory = makeZstdStreamTransformFactory();
    const std::string plain(50000, 'x');
    auto response = streamOf(plain);

    const auto transform = factory(requestOffering("deflate, gzip, br, zstd"), fixture.reserve());
    ASSERT_TRUE(transform);
    transform(response);

    EXPECT_EQ(headerOf(response, "Content-Encoding"), "zstd");
    EXPECT_EQ(decode(drain(*response.source)), plain);
}
