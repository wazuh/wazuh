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

#include "common/zstdDecoder.hpp"
#include "common/zstdEncoder.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <string>
#include <variant>

using remoted::common::zstdDecode;
using remoted::common::ZstdStreamCompressor;

namespace
{
    const auto alwaysReserve = [](std::size_t)
    {
        return true;
    };

    /// Decode with the production decoder, failing the test on any decode error.
    std::string decode(const std::string& compressed)
    {
        const auto result = zstdDecode(compressed, alwaysReserve, alwaysReserve);
        if (!std::holds_alternative<std::string>(result))
        {
            ADD_FAILURE() << "the encoder produced a frame the production decoder rejects";
            return {};
        }
        return std::get<std::string>(result);
    }

    /// Repetitive (compressible) content, like the shared-configuration text this exists for.
    std::string sampleText(std::size_t size)
    {
        static const std::string line {"<agent_config>shared configuration line</agent_config>\n"};
        std::string text;
        text.reserve(size + line.size());
        while (text.size() < size)
        {
            text += line;
        }
        text.resize(size);
        return text;
    }
} // namespace

TEST(ZstdEncoder, RoundTripsInASingleStep)
{
    const std::string plain = "merged configuration contents";
    ZstdStreamCompressor compressor;

    std::string output(1024, '\0');
    const auto step = compressor.step(plain.data(), plain.size(), /*endOfInput=*/true, output.data(), output.size());

    EXPECT_EQ(step.consumed, plain.size());
    EXPECT_TRUE(step.frameComplete);
    ASSERT_GT(step.produced, 0U);

    output.resize(step.produced);
    EXPECT_EQ(decode(output), plain);
}

TEST(ZstdEncoder, RoundTripsAcrossManySmallSteps)
{
    // Bigger than a zstd block, fed in slices, drained into a small output window: exercises
    // every branch step() has (buffering with no output, partial flush, final terminator).
    const std::string plain = sampleText(300U * 1024U);
    ZstdStreamCompressor compressor;

    std::string compressed;
    std::size_t inputPos = 0;
    constexpr std::size_t kInputSlice = 7U * 1024U;
    constexpr std::size_t kOutputSlice = 512U;
    char window[kOutputSlice];

    bool frameComplete = false;
    while (!frameComplete)
    {
        const auto remaining = plain.size() - inputPos;
        const auto sliceSize = remaining < kInputSlice ? remaining : kInputSlice;
        const bool endOfInput = inputPos + sliceSize == plain.size();

        const auto step =
            compressor.step(plain.data() + inputPos, sliceSize, endOfInput, window, sizeof(window));

        inputPos += step.consumed;
        compressed.append(window, step.produced);
        frameComplete = step.frameComplete;
    }

    EXPECT_EQ(inputPos, plain.size());
    EXPECT_LT(compressed.size(), plain.size() / 5); // repetitive text compresses far below 20%
    EXPECT_EQ(decode(compressed), plain);
}

TEST(ZstdEncoder, BuffersInputWithoutProducingOutput)
{
    // The behavior ZstdCompressingByteSource's internal loop exists for: a small non-final input
    // is consumed whole while zstd holds it back for a fuller block.
    ZstdStreamCompressor compressor;
    const std::string plain = "tiny";
    char output[256];

    const auto step = compressor.step(plain.data(), plain.size(), /*endOfInput=*/false, output, sizeof(output));

    EXPECT_EQ(step.consumed, plain.size());
    EXPECT_EQ(step.produced, 0U);
    EXPECT_FALSE(step.frameComplete);
}

TEST(ZstdEncoder, RoundTripsEmptyInput)
{
    ZstdStreamCompressor compressor;
    std::string output(256, '\0');

    const auto step = compressor.step(nullptr, 0, /*endOfInput=*/true, output.data(), output.size());

    EXPECT_TRUE(step.frameComplete);
    ASSERT_GT(step.produced, 0U); // even an empty frame has a header and terminator

    output.resize(step.produced);
    EXPECT_EQ(decode(output), "");
}

TEST(ZstdEncoder, SizingHelpersReportRealFigures)
{
    EXPECT_GT(ZstdStreamCompressor::estimatedStateBytes(), 0U);
    EXPECT_GT(ZstdStreamCompressor::recommendedInputSize(), 0U);
}
