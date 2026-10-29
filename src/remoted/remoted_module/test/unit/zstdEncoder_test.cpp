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
#include "zstdTestHelper.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>

using remoted::common::zstdDecode;
using remoted::common::ZstdDecodeError;
using remoted::common::ZstdEncoder;
using remoted::testutil::alwaysReserve;
using remoted::testutil::configLikeText;
using remoted::testutil::incompressibleBytes;

namespace
{
    /// Feeds @p plain in @p slice-byte pieces and finishes the frame, writing through an output
    /// buffer of @p capacity bytes. Returns the whole frame.
    std::string compressFully(std::string_view plain, std::size_t slice, std::size_t capacity)
    {
        ZstdEncoder encoder;
        std::string frame;
        std::string out(capacity, '\0');

        std::size_t position = 0;
        while (position < plain.size())
        {
            const auto step = encoder.compress(plain.substr(position, slice), out.data(), out.size(), false);
            position += step.consumed;
            frame.append(out.data(), step.produced);
            EXPECT_FALSE(step.finished) << "the frame must not finish before it is asked to";
        }

        ZstdEncoder::Step step;
        do
        {
            step = encoder.compress({}, out.data(), out.size(), true);
            frame.append(out.data(), step.produced);
        } while (!step.finished);

        return frame;
    }

    std::string decodeOrFail(std::string_view frame)
    {
        const auto result = zstdDecode(frame, alwaysReserve, alwaysReserve);
        EXPECT_TRUE(std::holds_alternative<std::string>(result)) << "the frame did not decode";
        return std::holds_alternative<std::string>(result) ? std::get<std::string>(result) : std::string {};
    }
} // namespace

TEST(ZstdEncoder, RoundTripsAgainstTheDecoder)
{
    const std::string plain = "Hello, this is a Wazuh configuration payload.";

    EXPECT_EQ(decodeOrFail(compressFully(plain, plain.size(), 4096)), plain);
}

TEST(ZstdEncoder, RoundTripsAnEmptyBody)
{
    ZstdEncoder encoder;
    std::string out(64, '\0');

    const auto step = encoder.compress({}, out.data(), out.size(), true);

    EXPECT_EQ(step.consumed, 0U);
    EXPECT_GT(step.produced, 0U) << "an empty body still has a frame header and epilogue";
    EXPECT_TRUE(step.finished);
    EXPECT_EQ(decodeOrFail(std::string_view {out.data(), step.produced}), "");
}

TEST(ZstdEncoder, RoundTripsAMultiMegabyteBodyFedInRecommendedSlices)
{
    const auto plain = configLikeText(6U * 1024U * 1024U);

    const auto frame = compressFully(plain, ZstdEncoder::inputSize(), 64U * 1024U);

    EXPECT_EQ(decodeOrFail(frame), plain);
    EXPECT_LT(frame.size(), plain.size() / 10) << "repetitive text should compress far below its size";
}

TEST(ZstdEncoder, RoundTripsIncompressibleData)
{
    const auto plain = incompressibleBytes(1U * 1024U * 1024U);

    EXPECT_EQ(decodeOrFail(compressFully(plain, ZstdEncoder::inputSize(), 64U * 1024U)), plain);
}

TEST(ZstdEncoder, FinishesTheFrameThroughATinyOutputBuffer)
{
    // With a one- or seven-byte output buffer the epilogue needs several calls; the frame must
    // still come out whole.
    const auto plain = configLikeText(50000);

    EXPECT_EQ(decodeOrFail(compressFully(plain, 4096, 1)), plain);
    EXPECT_EQ(decodeOrFail(compressFully(plain, 4096, 7)), plain);
}

TEST(ZstdEncoder, ProducesExactlyOneFrame)
{
    // zstdDecode() refuses anything after the first frame, so a successful decode is the proof.
    const auto plain = configLikeText(300000);

    EXPECT_EQ(decodeOrFail(compressFully(plain, 100000, 4096)), plain);
}

TEST(ZstdEncoder, AFrameThatWasNeverFinishedDoesNotDecode)
{
    // What the agent sees when a transfer is aborted: the bytes so far, no epilogue.
    const auto plain = incompressibleBytes(1U * 1024U * 1024U);
    ZstdEncoder encoder;
    std::string out(256U * 1024U, '\0');
    std::string partial;

    for (std::size_t position = 0; position < plain.size();)
    {
        const auto step = encoder.compress(
            std::string_view {plain}.substr(position, ZstdEncoder::inputSize()), out.data(), out.size(), false);
        position += step.consumed;
        partial.append(out.data(), step.produced);
    }

    ASSERT_FALSE(partial.empty());
    const auto result = zstdDecode(partial, alwaysReserve, alwaysReserve);
    ASSERT_TRUE(std::holds_alternative<ZstdDecodeError>(result));
    EXPECT_EQ(std::get<ZstdDecodeError>(result), ZstdDecodeError::Malformed);
}

TEST(ZstdEncoder, MemoryRequiredCoversTheContextAndTheStagingBuffer)
{
    // The context alone is a couple of MiB at level 3; the staging slice comes on top of it.
    EXPECT_GT(ZstdEncoder::inputSize(), 0U);
    EXPECT_GT(ZstdEncoder::memoryRequired(), ZstdEncoder::inputSize());
    EXPECT_GT(ZstdEncoder::memoryRequired(), 1024U * 1024U);
}

TEST(ZstdEncoder, TheFrameWindowStaysWithinWhatTheDecoderAccepts)
{
    // zstdDecode() refuses a declared window over 8 MiB. Level 3 declares 2 MiB, so a body larger
    // than the window must still decode: it would be refused as TooLarge otherwise.
    const auto plain = configLikeText(20U * 1024U * 1024U);

    EXPECT_EQ(decodeOrFail(compressFully(plain, ZstdEncoder::inputSize(), 64U * 1024U)), plain);
}
