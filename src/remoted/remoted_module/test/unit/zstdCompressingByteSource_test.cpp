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
#include "http_server/zstdCompressingByteSource.hpp"
#include "zstdTestHelper.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

using remoted::common::zstdDecode;
using remoted::common::ZstdDecodeError;
using remoted::common::ZstdEncoder;
using remoted::http::IByteSource;
using remoted::http::InFlightBudget;
using remoted::http::ZstdCompressingByteSource;
using remoted::testutil::alwaysReserve;
using remoted::testutil::configLikeText;
using remoted::testutil::incompressibleBytes;

namespace
{
    /// Serves @p data in pieces of at most @p slice bytes. Optionally throws on the @p throwAtRead'th
    /// call to read() (1-based), or instead of reporting end-of-stream, the way FileByteSource does
    /// when the file changed under the transfer.
    class SliceSource final : public IByteSource
    {
    public:
        SliceSource(std::string data, std::size_t slice)
            : m_data {std::move(data)}
            , m_slice {slice}
        {
        }

        std::size_t read(char* buffer, std::size_t capacity) override
        {
            ++m_reads;
            if (m_reads == throwAtRead)
            {
                throw std::runtime_error {"the resource was modified while it was being streamed"};
            }

            const auto remaining = m_data.size() - m_offset;
            if (remaining == 0)
            {
                if (throwAtEnd)
                {
                    throw std::runtime_error {"the resource was truncated while it was being streamed"};
                }
                return 0;
            }

            const auto count = std::min({capacity, remaining, m_slice});
            std::memcpy(buffer, m_data.data() + m_offset, count);
            m_offset += count;
            return count;
        }

        std::size_t throwAtRead {std::numeric_limits<std::size_t>::max()};
        bool throwAtEnd {false};

    private:
        std::string m_data;
        std::size_t m_slice;
        std::size_t m_offset {0};
        std::size_t m_reads {0};
    };

    /// What drain() saw.
    struct Drained
    {
        std::string bytes;
        std::vector<std::size_t> sizes; ///< Return value of every read(), including the final 0.
    };

    /// Reads @p source to end-of-stream through a @p capacity-byte buffer.
    Drained drain(IByteSource& source, std::size_t capacity)
    {
        Drained drained;
        std::string buffer(capacity, '\0');
        while (true)
        {
            const auto count = source.read(buffer.data(), buffer.size());
            drained.sizes.push_back(count);
            if (count == 0)
            {
                return drained;
            }
            drained.bytes.append(buffer.data(), count);
        }
    }

    std::shared_ptr<ZstdCompressingByteSource> compressing(std::shared_ptr<IByteSource> inner,
                                                           InFlightBudget::Reservation reservation = {})
    {
        return std::make_shared<ZstdCompressingByteSource>(std::move(inner), std::move(reservation));
    }

    std::string decodeOrFail(const std::string& frame)
    {
        const auto result = zstdDecode(frame, alwaysReserve, alwaysReserve);
        EXPECT_TRUE(std::holds_alternative<std::string>(result)) << "the frame did not decode";
        return std::holds_alternative<std::string>(result) ? std::get<std::string>(result) : std::string {};
    }
} // namespace

TEST(ZstdCompressingByteSource, RoundTripsAMultiSliceBody)
{
    const auto plain = configLikeText(3U * 1024U * 1024U);

    for (const std::size_t capacity : {std::size_t {4096}, std::size_t {64U * 1024U}})
    {
        auto source = compressing(std::make_shared<SliceSource>(plain, 64U * 1024U));

        const auto drained = drain(*source, capacity);

        EXPECT_EQ(decodeOrFail(drained.bytes), plain) << "capacity " << capacity;
    }
}

TEST(ZstdCompressingByteSource, NeverReturnsZeroBeforeTheFrameIsComplete)
{
    // Zero means end-of-stream to the pump, which then writes the terminating chunk. A zero before
    // the frame is flushed would pass a truncated frame off as complete, so the only zero allowed is
    // the last read, and the bytes handed out by then must be the whole frame.
    const auto plain = configLikeText(40000);

    for (const std::size_t capacity : {std::size_t {1}, std::size_t {3}, std::size_t {17}, std::size_t {4096}})
    {
        auto source = compressing(std::make_shared<SliceSource>(plain, 1000));

        const auto drained = drain(*source, capacity);

        ASSERT_FALSE(drained.sizes.empty());
        EXPECT_EQ(drained.sizes.back(), 0U);
        for (std::size_t i = 0; i + 1 < drained.sizes.size(); ++i)
        {
            ASSERT_GT(drained.sizes[i], 0U) << "a zero before the end, at read " << i << ", capacity " << capacity;
        }
        EXPECT_EQ(decodeOrFail(drained.bytes), plain) << "capacity " << capacity;
    }
}

TEST(ZstdCompressingByteSource, ABufferSmallerThanTheFrameStillGetsEveryByte)
{
    // chunkSize bounds the COMPRESSED bytes of one read.
    const auto plain = incompressibleBytes(512U * 1024U);
    auto source = compressing(std::make_shared<SliceSource>(plain, 128U * 1024U));
    std::string buffer(4096, '\0');
    std::string frame;

    while (true)
    {
        const auto count = source->read(buffer.data(), buffer.size());
        ASSERT_LE(count, buffer.size());
        if (count == 0)
        {
            break;
        }
        frame.append(buffer.data(), count);
    }

    EXPECT_EQ(decodeOrFail(frame), plain);
}

TEST(ZstdCompressingByteSource, ReturnsZeroForEveryReadAfterTheFrameEnded)
{
    auto source = compressing(std::make_shared<SliceSource>("a small body", 100));
    std::string buffer(4096, '\0');

    while (source->read(buffer.data(), buffer.size()) != 0)
    {
    }

    EXPECT_EQ(source->read(buffer.data(), buffer.size()), 0U);
    EXPECT_EQ(source->read(buffer.data(), buffer.size()), 0U);
}

TEST(ZstdCompressingByteSource, AnEmptyInnerSourceYieldsAValidEmptyFrame)
{
    auto source = compressing(std::make_shared<SliceSource>("", 100));

    const auto drained = drain(*source, 4096);

    EXPECT_FALSE(drained.bytes.empty()) << "an empty body is still a frame, not zero bytes";
    EXPECT_EQ(decodeOrFail(drained.bytes), "");
}

TEST(ZstdCompressingByteSource, ShortReadsFromTheInnerSourceAreNotEndOfStream)
{
    // One byte per inner read: zstd swallows thousands of them before emitting anything, and the
    // source has to keep pulling rather than answer 0 in the meantime.
    const auto plain = configLikeText(5000);
    auto source = compressing(std::make_shared<SliceSource>(plain, 1));

    const auto drained = drain(*source, 4096);

    EXPECT_EQ(decodeOrFail(drained.bytes), plain);
}

TEST(ZstdCompressingByteSource, AZeroCapacityReadProducesNothing)
{
    auto source = compressing(std::make_shared<SliceSource>("body", 100));
    char byte = 0;

    EXPECT_EQ(source->read(&byte, 0), 0U);
    EXPECT_EQ(source->read(nullptr, 16), 0U);

    // Neither consumed anything: the body is still all there.
    EXPECT_EQ(decodeOrFail(drain(*source, 4096).bytes), "body");
}

TEST(ZstdCompressingByteSource, AnInnerFailureMidStreamPropagatesAndLeavesATruncatedFrame)
{
    // The inner source throwing is how a file modified mid-transfer aborts it: the pump drops the
    // builder without a terminator, so the agent holds whatever was emitted so far. That must not
    // be a decodable frame.
    const auto plain = incompressibleBytes(2U * 1024U * 1024U);
    auto inner = std::make_shared<SliceSource>(plain, 128U * 1024U);
    inner->throwAtRead = 6;
    auto source = compressing(inner);
    std::string buffer(64U * 1024U, '\0');
    std::string emitted;

    EXPECT_THROW(
        {
            while (true)
            {
                const auto count = source->read(buffer.data(), buffer.size());
                ASSERT_GT(count, 0U);
                emitted.append(buffer.data(), count);
            }
        },
        std::runtime_error);

    ASSERT_FALSE(emitted.empty()) << "the failure has to land after some output was already sent";
    const auto result = zstdDecode(emitted, alwaysReserve, alwaysReserve);
    ASSERT_TRUE(std::holds_alternative<ZstdDecodeError>(result));
    EXPECT_EQ(std::get<ZstdDecodeError>(result), ZstdDecodeError::Malformed);
}

TEST(ZstdCompressingByteSource, AFailureInPlaceOfEndOfStreamNeverCompletesTheFrame)
{
    // FileByteSource's last read can throw instead of returning 0 (a writer landed after the final
    // data read). The frame must not have been closed by then: compression finishes only once the
    // inner source has really reported the end.
    const auto plain = configLikeText(300000);
    auto inner = std::make_shared<SliceSource>(plain, 64U * 1024U);
    inner->throwAtEnd = true;
    auto source = compressing(inner);
    std::string buffer(64U * 1024U, '\0');
    std::string emitted;

    EXPECT_THROW(
        {
            while (true)
            {
                const auto count = source->read(buffer.data(), buffer.size());
                ASSERT_GT(count, 0U);
                emitted.append(buffer.data(), count);
            }
        },
        std::runtime_error);

    if (!emitted.empty())
    {
        const auto result = zstdDecode(emitted, alwaysReserve, alwaysReserve);
        ASSERT_TRUE(std::holds_alternative<ZstdDecodeError>(result)) << "a complete frame left before the failure";
        EXPECT_EQ(std::get<ZstdDecodeError>(result), ZstdDecodeError::Malformed);
    }
}

TEST(ZstdCompressingByteSource, HoldsItsReservationForTheLifeOfTheTransfer)
{
    InFlightBudget budget {64U * 1024U * 1024U};
    const auto before = budget.availableBytes();
    auto reservation = budget.tryReserveUncounted(ZstdEncoder::memoryRequired());
    ASSERT_TRUE(reservation.has_value());
    EXPECT_EQ(budget.availableBytes(), before - ZstdEncoder::memoryRequired());

    auto source = compressing(std::make_shared<SliceSource>(configLikeText(100000), 4096), std::move(*reservation));

    // Still charged while the body is being produced, and after the last byte, until the transfer
    // drops the source.
    std::string buffer(4096, '\0');
    ASSERT_GT(source->read(buffer.data(), buffer.size()), 0U);
    EXPECT_EQ(budget.availableBytes(), before - ZstdEncoder::memoryRequired());
    while (source->read(buffer.data(), buffer.size()) != 0)
    {
    }
    EXPECT_EQ(budget.availableBytes(), before - ZstdEncoder::memoryRequired());

    source.reset();
    EXPECT_EQ(budget.availableBytes(), before);
}

TEST(ZstdCompressingByteSource, ReleasesTheInnerSourceWithItself)
{
    class Flagged final : public IByteSource
    {
    public:
        explicit Flagged(std::shared_ptr<std::atomic_bool> destroyed)
            : m_destroyed {std::move(destroyed)}
        {
        }
        ~Flagged() override
        {
            m_destroyed->store(true);
        }
        std::size_t read(char*, std::size_t) override
        {
            return 0;
        }

    private:
        std::shared_ptr<std::atomic_bool> m_destroyed;
    };

    auto destroyed = std::make_shared<std::atomic_bool>(false);
    auto source = compressing(std::make_shared<Flagged>(destroyed));

    EXPECT_FALSE(destroyed->load());
    source.reset();
    EXPECT_TRUE(destroyed->load()) << "an aborted transfer must release the file descriptor the inner source owns";
}
