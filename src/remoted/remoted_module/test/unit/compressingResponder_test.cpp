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
#include "http_server/compressingResponder.hpp"
#include "http_server/inFlightBudget.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <optional>
#include <random>
#include <stdexcept>
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
    using Headers = std::vector<std::pair<std::string, std::string>>;

    constexpr std::size_t BUDGET_BYTES = 64U * 1024U * 1024U;

    // Pseudorandom bytes, so the compressed frame is not trivially small.
    std::string incompressible(std::size_t size, std::uint32_t seed)
    {
        std::mt19937 gen(seed);
        std::string data(size, '\0');
        for (auto& c : data)
        {
            c = static_cast<char>(gen() & 0xFF);
        }
        return data;
    }

    // Delivers `data` in slices of at most `slice` bytes, then 0.
    class ScriptedByteSource final : public IByteSource
    {
    public:
        explicit ScriptedByteSource(std::string data, std::size_t slice = 4096)
            : m_data {std::move(data)}
            , m_slice {slice}
        {
        }

        std::size_t read(char* buffer, std::size_t capacity) override
        {
            const auto n = std::min({capacity, m_slice, m_data.size() - m_pos});
            std::copy_n(m_data.data() + m_pos, n, buffer);
            m_pos += n;
            return n;
        }

    private:
        std::string m_data;
        std::size_t m_slice;
        std::size_t m_pos {0};
    };

    // Records every call; stream() can be told to throw after recording.
    class RecordingInner final : public IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            sent.push_back(std::move(response));
        }

        void stream(StreamResponse response) override
        {
            streamed.push_back(std::move(response));
            if (throwOnStream)
            {
                throw std::runtime_error("inner stream failure");
            }
        }

        std::vector<HttpResponse> sent;
        std::vector<StreamResponse> streamed;
        bool throwOnStream {false};
    };

    std::string drain(IByteSource& source)
    {
        std::string out;
        std::vector<char> buf(16384);
        for (;;)
        {
            const auto n = source.read(buf.data(), buf.size());
            if (n == 0)
            {
                return out;
            }
            out.append(buf.data(), n);
        }
    }

    std::string decode(const std::string& frame)
    {
        const auto always = [](std::size_t)
        {
            return true;
        };
        auto decoded = zstdDecode(frame, always, always);
        EXPECT_TRUE(std::holds_alternative<std::string>(decoded));
        return std::holds_alternative<std::string>(decoded) ? std::get<std::string>(decoded) : std::string {};
    }

    std::size_t countContentEncoding(const Headers& headers)
    {
        return static_cast<std::size_t>(std::count_if(headers.begin(),
                                                      headers.end(),
                                                      [](const auto& header)
                                                      {
                                                          std::string lower = header.first;
                                                          for (auto& c : lower)
                                                          {
                                                              c = static_cast<char>(
                                                                  std::tolower(static_cast<unsigned char>(c)));
                                                          }
                                                          return lower == "content-encoding";
                                                      }));
    }

    std::size_t expectedReservation(std::optional<std::uint64_t> hint)
    {
        return ZstdEncoder::estimateMemory(hint) + ZstdEncoder::inputBufferSize(hint) +
               ZstdEncoder::outputBufferSize(hint);
    }

    StreamResponse plainResponse(std::shared_ptr<IByteSource> source, std::optional<std::uint64_t> hint = 1024)
    {
        StreamResponse response;
        response.status = 200;
        response.headers.emplace_back("Content-Type", "application/octet-stream");
        response.source = std::move(source);
        response.chunkSize = 777;
        response.sizeHint = hint;
        return response;
    }

    // Asserts that `got` is `expected` forwarded untouched (same source object, same fields).
    void expectUntouched(const StreamResponse& got, const StreamResponse& expected)
    {
        EXPECT_EQ(got.status, expected.status);
        EXPECT_EQ(got.headers, expected.headers);
        EXPECT_EQ(got.source.get(), expected.source.get());
        EXPECT_EQ(got.chunkSize, expected.chunkSize);
        EXPECT_EQ(got.compressible, expected.compressible);
        EXPECT_EQ(got.sizeHint, expected.sizeHint);
    }
} // namespace

TEST(CompressingResponder, SendIsDelegatedUntouched)
{
    auto inner = std::make_shared<RecordingInner>();
    int reserveCalls = 0;
    CompressingResponder responder(inner,
                                   [&](std::size_t) -> std::optional<InFlightBudget::Reservation>
                                   {
                                       ++reserveCalls;
                                       return std::nullopt;
                                   });

    auto response = HttpResponse::json(404, R"({"error":"Not found","code":404})");
    response.headers.emplace_back("X-Extra", "1");
    responder.send(response);

    ASSERT_EQ(inner->sent.size(), 1U);
    EXPECT_EQ(inner->sent[0].status, response.status);
    EXPECT_EQ(inner->sent[0].body, response.body);
    EXPECT_EQ(inner->sent[0].headers, response.headers);
    EXPECT_TRUE(inner->streamed.empty());
    EXPECT_EQ(reserveCalls, 0);
}

TEST(CompressingResponder, ACompressibleStreamIsReplacedAndLabelled)
{
    InFlightBudget budget(BUDGET_BYTES);
    auto inner = std::make_shared<RecordingInner>();
    CompressingResponder responder(inner, [&](std::size_t bytes) { return budget.tryReserveUncounted(bytes); });

    const auto payload = incompressible(300U * 1024U, 11);
    auto source = std::make_shared<ScriptedByteSource>(payload);
    responder.stream(plainResponse(source, payload.size()));

    ASSERT_EQ(inner->streamed.size(), 1U);
    auto& got = inner->streamed[0];
    const Headers expectedHeaders {{"Content-Type", "application/octet-stream"}, {"Content-Encoding", "zstd"}};
    EXPECT_EQ(got.headers, expectedHeaders);
    EXPECT_FALSE(got.sizeHint.has_value());
    EXPECT_EQ(got.status, 200);
    EXPECT_EQ(got.chunkSize, 777U);
    ASSERT_NE(got.source, nullptr);
    EXPECT_NE(got.source.get(), source.get());
    EXPECT_LT(budget.availableBytes(), BUDGET_BYTES); // the encoder's memory is held by the new source

    EXPECT_EQ(decode(drain(*got.source)), payload);

    inner->streamed.clear();
    EXPECT_EQ(budget.availableBytes(), BUDGET_BYTES);
}

TEST(CompressingResponder, ANotCompressibleStreamIsForwardedUntouched)
{
    InFlightBudget budget(BUDGET_BYTES);
    auto inner = std::make_shared<RecordingInner>();
    int reserveCalls = 0;
    CompressingResponder responder(inner,
                                   [&](std::size_t bytes)
                                   {
                                       ++reserveCalls;
                                       return budget.tryReserveUncounted(bytes);
                                   });

    auto response = plainResponse(std::make_shared<ScriptedByteSource>("payload"));
    response.compressible = false;
    const auto expected = response;
    responder.stream(response);

    ASSERT_EQ(inner->streamed.size(), 1U);
    expectUntouched(inner->streamed[0], expected);
    EXPECT_EQ(reserveCalls, 0);
}

TEST(CompressingResponder, ANullSourceIsForwardedUntouched)
{
    InFlightBudget budget(BUDGET_BYTES);
    auto inner = std::make_shared<RecordingInner>();
    int reserveCalls = 0;
    CompressingResponder responder(inner,
                                   [&](std::size_t bytes)
                                   {
                                       ++reserveCalls;
                                       return budget.tryReserveUncounted(bytes);
                                   });

    const auto expected = plainResponse(nullptr);
    responder.stream(expected);

    ASSERT_EQ(inner->streamed.size(), 1U);
    expectUntouched(inner->streamed[0], expected);
    EXPECT_EQ(reserveCalls, 0);
}

TEST(CompressingResponder, AnExistingContentEncodingIsNotDuplicated)
{
    for (const std::string name : {"content-encoding", "Content-Encoding"})
    {
        SCOPED_TRACE(name);
        InFlightBudget budget(BUDGET_BYTES);
        auto inner = std::make_shared<RecordingInner>();
        int reserveCalls = 0;
        CompressingResponder responder(inner,
                                       [&](std::size_t bytes)
                                       {
                                           ++reserveCalls;
                                           return budget.tryReserveUncounted(bytes);
                                       });

        auto response = plainResponse(std::make_shared<ScriptedByteSource>("payload"));
        response.headers.emplace_back(name, "gzip");
        const auto expected = response;
        responder.stream(response);

        ASSERT_EQ(inner->streamed.size(), 1U);
        expectUntouched(inner->streamed[0], expected);
        EXPECT_EQ(countContentEncoding(inner->streamed[0].headers), 1U);
        EXPECT_EQ(reserveCalls, 0);
    }
}

TEST(CompressingResponder, ARefusedReservationServesPlain)
{
    auto inner = std::make_shared<RecordingInner>();
    std::vector<std::string> reasons;
    CompressingResponder responder(
        inner,
        [](std::size_t) -> std::optional<InFlightBudget::Reservation> { return std::nullopt; },
        {},
        [&](const char* reason) { reasons.emplace_back(reason); });

    const auto expected = plainResponse(std::make_shared<ScriptedByteSource>("payload"));
    responder.stream(expected);

    ASSERT_EQ(inner->streamed.size(), 1U);
    expectUntouched(inner->streamed[0], expected);
    ASSERT_EQ(reasons.size(), 1U);
    EXPECT_EQ(reasons[0], "reservation refused");
}

TEST(CompressingResponder, AFactoryThatThrowsServesPlainAndKeepsTheSource)
{
    InFlightBudget budget(BUDGET_BYTES);
    auto inner = std::make_shared<RecordingInner>();
    std::vector<std::string> reasons;
    std::size_t reservedInFactory = 0;
    CompressingResponder responder(
        inner,
        [&](std::size_t bytes) { return budget.tryReserveUncounted(bytes); },
        [&](std::shared_ptr<IByteSource>,
            InFlightBudget::Reservation reservation,
            std::optional<std::uint64_t>) -> std::shared_ptr<IByteSource>
        {
            reservedInFactory = reservation.bytes();
            throw std::runtime_error("factory failure");
        },
        [&](const char* reason) { reasons.emplace_back(reason); });

    auto source = std::make_shared<ScriptedByteSource>("payload");
    const auto expected = plainResponse(source);
    responder.stream(expected);

    EXPECT_GT(reservedInFactory, 0U);
    ASSERT_EQ(inner->streamed.size(), 1U);
    expectUntouched(inner->streamed[0], expected);
    // Alive and owned only by the local handle, `expected` and the forwarded response.
    EXPECT_EQ(source.use_count(), 3);
    EXPECT_EQ(budget.availableBytes(), BUDGET_BYTES);
    ASSERT_EQ(reasons.size(), 1U);
    EXPECT_EQ(reasons[0], "compressor setup failed");
}

TEST(CompressingResponder, AReserveFunctionThatThrowsServesPlain)
{
    auto inner = std::make_shared<RecordingInner>();
    std::vector<std::string> reasons;
    CompressingResponder responder(
        inner,
        [](std::size_t) -> std::optional<InFlightBudget::Reservation> { throw std::bad_alloc(); },
        {},
        [&](const char* reason) { reasons.emplace_back(reason); });

    const auto expected = plainResponse(std::make_shared<ScriptedByteSource>("payload"));
    responder.stream(expected);

    ASSERT_EQ(inner->streamed.size(), 1U);
    expectUntouched(inner->streamed[0], expected);
    ASSERT_EQ(reasons.size(), 1U);
    EXPECT_EQ(reasons[0], "compressor setup failed");
}

TEST(CompressingResponder, AFallbackCallbackThatThrowsDoesNotEscape)
{
    auto inner = std::make_shared<RecordingInner>();
    CompressingResponder responder(
        inner,
        [](std::size_t) -> std::optional<InFlightBudget::Reservation> { return std::nullopt; },
        {},
        [](const char*) { throw std::runtime_error("logger failure"); });

    const auto expected = plainResponse(std::make_shared<ScriptedByteSource>("payload"));
    EXPECT_NO_THROW(responder.stream(expected));

    ASSERT_EQ(inner->streamed.size(), 1U);
    expectUntouched(inner->streamed[0], expected);
}

TEST(CompressingResponder, AnInnerStreamThatThrowsIsDelegatedOnce)
{
    InFlightBudget budget(BUDGET_BYTES);
    auto inner = std::make_shared<RecordingInner>();
    inner->throwOnStream = true;
    CompressingResponder responder(inner, [&](std::size_t bytes) { return budget.tryReserveUncounted(bytes); });

    EXPECT_THROW(responder.stream(plainResponse(std::make_shared<ScriptedByteSource>("payload"))), std::runtime_error);

    ASSERT_EQ(inner->streamed.size(), 1U);
    EXPECT_EQ(countContentEncoding(inner->streamed[0].headers), 1U); // it was the compressed response
}

TEST(CompressingResponder, TheReservationIsTheEncoderEstimatePlusBuffers)
{
    for (const auto hint : {std::optional<std::uint64_t> {20000}, std::optional<std::uint64_t> {}})
    {
        SCOPED_TRACE(hint ? std::to_string(*hint) : std::string {"no hint"});
        auto inner = std::make_shared<RecordingInner>();
        std::vector<std::size_t> requested;
        CompressingResponder responder(inner,
                                       [&](std::size_t bytes) -> std::optional<InFlightBudget::Reservation>
                                       {
                                           requested.push_back(bytes);
                                           return std::nullopt;
                                       });

        responder.stream(plainResponse(std::make_shared<ScriptedByteSource>("payload"), hint));

        ASSERT_EQ(requested.size(), 1U);
        EXPECT_EQ(requested[0], expectedReservation(hint));
    }
}

TEST(CompressingResponder, TheFactoryReceivesTheSizeHintAndTheWholeReservation)
{
    for (const auto hint : {std::optional<std::uint64_t> {20000}, std::optional<std::uint64_t> {}})
    {
        SCOPED_TRACE(hint ? std::to_string(*hint) : std::string {"no hint"});
        InFlightBudget budget(BUDGET_BYTES);
        auto inner = std::make_shared<RecordingInner>();
        std::optional<std::uint64_t> seenHint {std::uint64_t {1}};
        std::size_t seenBytes = 0;
        CompressingResponder responder(
            inner,
            [&](std::size_t bytes) { return budget.tryReserveUncounted(bytes); },
            [&](std::shared_ptr<IByteSource> source,
                InFlightBudget::Reservation reservation,
                std::optional<std::uint64_t> sizeHint) -> std::shared_ptr<IByteSource>
            {
                seenHint = sizeHint;
                seenBytes = reservation.bytes();
                return source;
            });

        responder.stream(plainResponse(std::make_shared<ScriptedByteSource>("payload"), hint));

        EXPECT_EQ(seenHint, hint);
        EXPECT_EQ(seenBytes, expectedReservation(hint));
        ASSERT_EQ(inner->streamed.size(), 1U);
        EXPECT_FALSE(inner->streamed[0].sizeHint.has_value());
    }
}

TEST(CompressingResponder, TwoStreamCallsAreBothProcessed)
{
    InFlightBudget budget(BUDGET_BYTES);
    auto inner = std::make_shared<RecordingInner>();
    int reserveCalls = 0;
    CompressingResponder responder(inner,
                                   [&](std::size_t bytes)
                                   {
                                       ++reserveCalls;
                                       return budget.tryReserveUncounted(bytes);
                                   });

    responder.stream(plainResponse(std::make_shared<ScriptedByteSource>("first"), 5));
    responder.stream(plainResponse(std::make_shared<ScriptedByteSource>("second"), 6));

    EXPECT_EQ(reserveCalls, 2);
    ASSERT_EQ(inner->streamed.size(), 2U);
    EXPECT_EQ(decode(drain(*inner->streamed[0].source)), "first");
    EXPECT_EQ(decode(drain(*inner->streamed[1].source)), "second");
}
