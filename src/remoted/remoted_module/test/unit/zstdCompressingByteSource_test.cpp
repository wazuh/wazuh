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
#include "http_server/inFlightBudget.hpp"
#include "http_server/zstdCompressingByteSource.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

using remoted::common::zstdDecode;
using remoted::common::ZstdDecodeError;
using remoted::http::IByteSource;
using remoted::http::InFlightBudget;
using remoted::http::ZstdCompressingByteSource;

namespace
{
    bool alwaysReserve(std::size_t)
    {
        return true;
    }

    // Pseudorandom bytes: a repeated pattern makes zstd emit almost nothing until the frame ends.
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

    // Delivers `data` in slices of at most `slice` bytes. Optionally throws once `throwAfter` bytes
    // were delivered, or in place of the end of stream. Reading it after its first 0 fails the test.
    class ScriptedByteSource final : public IByteSource
    {
    public:
        ScriptedByteSource(std::string data, std::size_t slice)
            : m_data {std::move(data)}
            , m_slice {slice}
        {
        }

        std::size_t read(char* buffer, std::size_t capacity) override
        {
            ++m_calls;
            if (m_zeroReturned)
            {
                ADD_FAILURE() << "inner source read after its end of stream";
                return 0;
            }
            if (m_throwAfter && m_pos >= *m_throwAfter)
            {
                throw std::runtime_error("scripted failure");
            }
            if (m_pos == m_data.size())
            {
                if (m_throwAtEnd)
                {
                    throw std::runtime_error("scripted failure at end");
                }
                m_zeroReturned = true;
                return 0;
            }
            auto limit = m_data.size();
            if (m_throwAfter)
            {
                limit = std::min(limit, *m_throwAfter);
            }
            const auto n = std::min({capacity, m_slice, limit - m_pos});
            std::copy_n(m_data.data() + m_pos, n, buffer);
            m_pos += n;
            return n;
        }

        void throwAfter(std::size_t bytes)
        {
            m_throwAfter = bytes;
        }

        void throwAtEnd()
        {
            m_throwAtEnd = true;
        }

        std::size_t calls() const
        {
            return m_calls;
        }

    private:
        std::string m_data;
        std::size_t m_slice;
        std::optional<std::size_t> m_throwAfter;
        bool m_throwAtEnd {false};
        std::size_t m_pos {0};
        std::size_t m_calls {0};
        bool m_zeroReturned {false};
    };

    // Reads until the first 0 or an exception; `threw` tells which.
    std::string drain(IByteSource& source, std::size_t capacity, bool* threw = nullptr)
    {
        std::string out;
        std::vector<char> buf(capacity);
        try
        {
            for (;;)
            {
                const auto n = source.read(buf.data(), buf.size());
                if (n == 0)
                {
                    break;
                }
                out.append(buf.data(), n);
            }
        }
        catch (const std::runtime_error&)
        {
            if (threw)
            {
                *threw = true;
            }
        }
        return out;
    }

    std::variant<std::string, ZstdDecodeError> decode(const std::string& frame)
    {
        return zstdDecode(frame, alwaysReserve, alwaysReserve);
    }
} // namespace

TEST(ZstdCompressingByteSource, NeverReturnsZeroBeforeTheFrameIsComplete)
{
    for (const std::size_t payloadSize : {0, 1, 100, 200000})
    {
        const auto payload = incompressible(payloadSize, 7);
        for (const std::size_t slice : {1, 7, 4096, 65536})
        {
            // A one-byte slice over 200000 bytes is the slow corner; it stays well under a second.
            for (const std::size_t capacity : {1, 13, 4096, 65536})
            {
                for (const bool withHint : {false, true})
                {
                    SCOPED_TRACE("payload=" + std::to_string(payloadSize) + " slice=" + std::to_string(slice) +
                                 " capacity=" + std::to_string(capacity) + " hint=" + std::to_string(withHint));
                    auto inner = std::make_shared<ScriptedByteSource>(payload, slice);
                    ZstdCompressingByteSource source(
                        inner, {}, withHint ? std::optional<std::uint64_t> {payload.size()} : std::nullopt);

                    bool threw = false;
                    const auto frame = drain(source, capacity, &threw);
                    ASSERT_FALSE(threw);
                    const auto decoded = decode(frame);
                    ASSERT_TRUE(std::holds_alternative<std::string>(decoded));
                    EXPECT_EQ(std::get<std::string>(decoded), payload);
                }
            }
        }
    }
}

TEST(ZstdCompressingByteSource, EmptyInnerSourceYieldsAValidEmptyFrame)
{
    auto inner = std::make_shared<ScriptedByteSource>("", 4096);
    ZstdCompressingByteSource source(inner, {}, std::nullopt);

    char buf[64];
    std::string frame;
    for (;;)
    {
        const auto n = source.read(buf, sizeof(buf));
        if (n == 0)
        {
            break;
        }
        frame.append(buf, n);
    }
    ASSERT_FALSE(frame.empty());

    const auto decoded = decode(frame);
    ASSERT_TRUE(std::holds_alternative<std::string>(decoded));
    EXPECT_TRUE(std::get<std::string>(decoded).empty());
    EXPECT_EQ(source.read(buf, sizeof(buf)), 0u);
}

TEST(ZstdCompressingByteSource, KeepsReturningZeroAfterTheEnd)
{
    auto inner = std::make_shared<ScriptedByteSource>(incompressible(1000, 3), 4096);
    ZstdCompressingByteSource source(inner, {}, std::nullopt);
    drain(source, 4096);
    const auto callsAtEnd = inner->calls();

    char buf[16];
    for (int i = 0; i < 3; ++i)
    {
        EXPECT_EQ(source.read(buf, sizeof(buf)), 0u);
    }
    EXPECT_EQ(inner->calls(), callsAtEnd);
}

TEST(ZstdCompressingByteSource, InnerFailureMidStreamPropagates)
{
    const auto payload = incompressible(1024 * 1024, 11);
    auto inner = std::make_shared<ScriptedByteSource>(payload, 65536);
    inner->throwAfter(512 * 1024);
    ZstdCompressingByteSource source(inner, {}, std::nullopt);

    bool threw = false;
    const auto received = drain(source, 65536, &threw);

    EXPECT_TRUE(threw);
    ASSERT_FALSE(received.empty());
    const auto decoded = decode(received);
    ASSERT_TRUE(std::holds_alternative<ZstdDecodeError>(decoded));
    EXPECT_EQ(std::get<ZstdDecodeError>(decoded), ZstdDecodeError::Malformed);
}

TEST(ZstdCompressingByteSource, InnerFailureInPlaceOfEndOfStreamPropagates)
{
    const auto payload = incompressible(300 * 1024, 13);
    auto inner = std::make_shared<ScriptedByteSource>(payload, 65536);
    inner->throwAtEnd();
    ZstdCompressingByteSource source(inner, {}, std::nullopt);

    bool threw = false;
    const auto received = drain(source, 65536, &threw);

    EXPECT_TRUE(threw);
    const auto decoded = decode(received);
    ASSERT_TRUE(std::holds_alternative<ZstdDecodeError>(decoded));
    EXPECT_EQ(std::get<ZstdDecodeError>(decoded), ZstdDecodeError::Malformed);
}

TEST(ZstdCompressingByteSource, TheReservationLivesAsLongAsTheSource)
{
    constexpr std::size_t N = 1 << 20;
    constexpr std::size_t k = 4096;
    InFlightBudget budget(N);

    {
        auto reservation = budget.tryReserveUncounted(k);
        ASSERT_TRUE(reservation.has_value());
        ASSERT_EQ(budget.availableBytes(), N - k);

        auto inner = std::make_shared<ScriptedByteSource>(incompressible(1000, 5), 4096);
        ZstdCompressingByteSource source(inner, std::move(*reservation), std::nullopt);
        EXPECT_EQ(budget.availableBytes(), N - k);

        drain(source, 4096);
        EXPECT_EQ(budget.availableBytes(), N - k);
    }
    EXPECT_EQ(budget.availableBytes(), N);

    {
        auto reservation = budget.tryReserveUncounted(k);
        ASSERT_TRUE(reservation.has_value());
        auto inner = std::make_shared<ScriptedByteSource>(incompressible(1000, 5), 4096);
        inner->throwAtEnd();
        ZstdCompressingByteSource source(inner, std::move(*reservation), std::nullopt);

        bool threw = false;
        drain(source, 4096, &threw);
        EXPECT_TRUE(threw);
        EXPECT_EQ(budget.availableBytes(), N - k);
    }
    EXPECT_EQ(budget.availableBytes(), N);
}
