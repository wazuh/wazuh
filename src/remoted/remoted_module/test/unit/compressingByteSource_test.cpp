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

#include "http_server/compressingByteSource.hpp"

#include "common/zstdDecoder.hpp"
#include "http_server/inFlightBudget.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <variant>

using remoted::common::zstdDecode;
using remoted::http::InFlightBudget;
using remoted::http::ZstdCompressingByteSource;

namespace
{
    const auto alwaysReserve = [](std::size_t)
    {
        return true;
    };

    /// Serves a fixed buffer in bounded slices; optionally throws once a byte count is crossed,
    /// standing in for FileByteSource's mid-transfer modification abort.
    class FakePlainSource final : public remoted::http::IByteSource
    {
    public:
        explicit FakePlainSource(std::string contents,
                                 std::size_t maxSlice = 8U * 1024U,
                                 std::size_t throwAfterBytes = SIZE_MAX)
            : m_contents {std::move(contents)}
            , m_maxSlice {maxSlice}
            , m_throwAfterBytes {throwAfterBytes}
        {
        }

        std::size_t read(char* buffer, std::size_t capacity) override
        {
            if (m_served >= m_throwAfterBytes)
            {
                throw std::runtime_error {"the resource was modified while it was being streamed"};
            }

            const auto remaining = m_contents.size() - m_served;
            auto slice = remaining < capacity ? remaining : capacity;
            if (slice > m_maxSlice)
            {
                slice = m_maxSlice;
            }
            std::memcpy(buffer, m_contents.data() + m_served, slice);
            m_served += slice;
            return slice;
        }

    private:
        std::string m_contents;
        std::size_t m_maxSlice;
        std::size_t m_throwAfterBytes;
        std::size_t m_served {0};
    };

    std::string repetitiveText(std::size_t size)
    {
        static const std::string line {"<localfile><log_format>syslog</log_format></localfile>\n"};
        std::string text;
        while (text.size() < size)
        {
            text += line;
        }
        text.resize(size);
        return text;
    }

    /// Drains a source the way StreamPump does, asserting the read contract: every read before
    /// end-of-stream returns at least one byte.
    std::string drain(remoted::http::IByteSource& source, std::size_t capacity)
    {
        std::string collected;
        std::string chunk(capacity, '\0');
        while (true)
        {
            const auto bytesRead = source.read(chunk.data(), capacity);
            if (bytesRead == 0)
            {
                // 0 must mean end-of-stream, permanently.
                EXPECT_EQ(source.read(chunk.data(), capacity), 0U);
                return collected;
            }
            collected.append(chunk.data(), bytesRead);
        }
    }

    std::string decode(const std::string& compressed)
    {
        const auto result = zstdDecode(compressed, alwaysReserve, alwaysReserve);
        if (!std::holds_alternative<std::string>(result))
        {
            ADD_FAILURE() << "the source produced a frame the production decoder rejects";
            return {};
        }
        return std::get<std::string>(result);
    }
} // namespace

TEST(ZstdCompressingByteSourceTest, RoundTripsThroughTheProductionDecoder)
{
    const std::string plain = repetitiveText(300U * 1024U);
    ZstdCompressingByteSource source {std::make_shared<FakePlainSource>(plain), {}};

    const auto compressed = drain(source, 64U * 1024U);

    EXPECT_LT(compressed.size(), plain.size() / 5);
    EXPECT_EQ(decode(compressed), plain);
}

TEST(ZstdCompressingByteSourceTest, HonorsTheReadContractUnderATinyCapacity)
{
    // A pathologically small pull size forces the flush path to span many read() calls; none of
    // them may return 0 before the frame terminator is out (drain() asserts exactly that).
    const std::string plain = repetitiveText(64U * 1024U);
    ZstdCompressingByteSource source {std::make_shared<FakePlainSource>(plain), {}};

    const auto compressed = drain(source, 5);

    EXPECT_EQ(decode(compressed), plain);
}

TEST(ZstdCompressingByteSourceTest, AnEmptyInnerSourceYieldsAValidEmptyFrame)
{
    ZstdCompressingByteSource source {std::make_shared<FakePlainSource>(""), {}};

    const auto compressed = drain(source, 4096);

    ASSERT_GT(compressed.size(), 0U);
    EXPECT_EQ(decode(compressed), "");
}

TEST(ZstdCompressingByteSourceTest, AnInnerAbortPropagatesInsteadOfEndingTheStream)
{
    // The modification check throwing mid-transfer must reach StreamPump as a throw -- a 0 return
    // here would emit the terminating chunk around a truncated frame that looks complete.
    const std::string plain = repetitiveText(256U * 1024U);
    ZstdCompressingByteSource source {
        std::make_shared<FakePlainSource>(plain, 8U * 1024U, /*throwAfterBytes=*/100U * 1024U), {}};

    std::string chunk(64U * 1024U, '\0');
    EXPECT_THROW(
        {
            while (source.read(chunk.data(), chunk.size()) > 0)
            {
            }
        },
        std::runtime_error);
}

TEST(ZstdCompressingByteSourceTest, HoldsItsBudgetReservationForItsWholeLife)
{
    InFlightBudget budget {16U * 1024U * 1024U};
    const auto initiallyAvailable = budget.availableBytes();

    {
        auto reservation = budget.tryReserveUncounted(ZstdCompressingByteSource::workingMemoryBytes());
        ASSERT_TRUE(reservation.has_value());

        ZstdCompressingByteSource source {std::make_shared<FakePlainSource>("bytes"),
                                          std::move(*reservation)};
        EXPECT_LT(budget.availableBytes(), initiallyAvailable);
    }

    // Destroying the source releases the compressor state's bytes back to the budget.
    EXPECT_EQ(budget.availableBytes(), initiallyAvailable);
}

TEST(ZstdCompressingByteSourceTest, RefusesANullInnerSource)
{
    EXPECT_THROW(ZstdCompressingByteSource(nullptr, {}), std::runtime_error);
}
