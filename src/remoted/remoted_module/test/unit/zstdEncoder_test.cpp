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

#include <zstd.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

using remoted::common::zstdDecode;
using remoted::common::ZstdDecodeError;
using remoted::common::ZstdEncoder;
using remoted::testutil::zstdCompressWithoutDeclaredSize;

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

    std::string text(std::size_t size)
    {
        const std::string unit = "Wazuh agent package download, chunk of readable text. ";
        std::string data;
        while (data.size() < size)
        {
            data += unit;
        }
        data.resize(size);
        return data;
    }

    // Drives step(finish=true) to completion over `in`, re-passing the unconsumed tail.
    std::string finishAll(ZstdEncoder& enc, std::string_view in, std::size_t outCapacity)
    {
        std::string result;
        std::vector<char> out(outCapacity);
        std::size_t offset = 0;
        for (;;)
        {
            const auto s = enc.step(in.data() + offset, in.size() - offset, true, out.data(), out.size());
            result.append(out.data(), s.produced);
            offset += s.consumed;
            if (s.done)
            {
                EXPECT_EQ(offset, in.size());
                return result;
            }
        }
    }

    std::string encodeInChunks(std::string_view data, std::optional<std::uint64_t> hint)
    {
        ZstdEncoder enc(hint);
        const std::size_t chunk = ZstdEncoder::inputBufferSize();
        std::vector<char> out(ZstdEncoder::outputBufferSize());
        std::string result;
        for (std::size_t offset = 0; offset < data.size();)
        {
            const std::size_t take = std::min(chunk, data.size() - offset);
            std::size_t fed = 0;
            while (fed < take)
            {
                const auto s = enc.step(data.data() + offset + fed, take - fed, false, out.data(), out.size());
                result.append(out.data(), s.produced);
                fed += s.consumed;
            }
            offset += take;
        }
        result += finishAll(enc, {}, out.size());
        return result;
    }

    std::string decodeOrFail(const std::string& frame)
    {
        const auto decoded = zstdDecode(frame, alwaysReserve, alwaysReserve);
        EXPECT_TRUE(std::holds_alternative<std::string>(decoded));
        return std::holds_alternative<std::string>(decoded) ? std::get<std::string>(decoded) : std::string {};
    }
} // namespace

TEST(ZstdEncoder, RoundTripsAgainstZstdDecode)
{
    const std::string plain = text(10 * 1024);
    ZstdEncoder enc(plain.size());

    const std::string frame = finishAll(enc, plain, ZSTD_compressBound(plain.size()));

    EXPECT_EQ(decodeOrFail(frame), plain);
}

TEST(ZstdEncoder, RoundTripsEmptyInput)
{
    for (const std::optional<std::uint64_t> hint : {std::optional<std::uint64_t> {}, std::optional<std::uint64_t> {0}})
    {
        ZstdEncoder enc(hint);
        const std::string frame = finishAll(enc, {}, ZstdEncoder::outputBufferSize(hint));

        ASSERT_FALSE(frame.empty());
        EXPECT_EQ(decodeOrFail(frame), "");
    }
}

TEST(ZstdEncoder, RoundTripsMultiMiB)
{
    const std::string plain = incompressible(4U * 1024U * 1024U, 1);

    for (const std::optional<std::uint64_t> hint :
         {std::optional<std::uint64_t> {}, std::optional<std::uint64_t> {plain.size()}})
    {
        EXPECT_EQ(decodeOrFail(encodeInChunks(plain, hint)), plain);
    }
}

TEST(ZstdEncoder, FinishesThroughAOneByteOutputBuffer)
{
    const std::string plain = incompressible(300U * 1024U, 2);
    ZstdEncoder enc(std::nullopt);

    std::string frame;
    char byte = 0;
    std::size_t offset = 0;
    bool done = false;
    while (!done)
    {
        const auto s = enc.step(plain.data() + offset, plain.size() - offset, true, &byte, 1);
        EXPECT_LE(s.produced, 1U);
        frame.append(&byte, s.produced);
        offset += s.consumed;
        done = s.done;
        if (!done)
        {
            ASSERT_TRUE(s.produced > 0 || s.consumed > 0) << "no progress";
        }
    }

    EXPECT_EQ(offset, plain.size());
    EXPECT_EQ(decodeOrFail(frame), plain);
}

TEST(ZstdEncoder, AnUnfinishedFrameIsNotDecodable)
{
    const std::string plain = incompressible(1024U * 1024U, 3);
    ZstdEncoder enc(std::nullopt);
    std::vector<char> out(ZSTD_compressBound(plain.size()));

    std::size_t offset = 0;
    std::size_t produced = 0;
    while (offset < plain.size())
    {
        const auto s =
            enc.step(plain.data() + offset, plain.size() - offset, false, out.data() + produced, out.size() - produced);
        EXPECT_FALSE(s.done);
        offset += s.consumed;
        produced += s.produced;
    }
    ASSERT_GT(produced, 0U);

    const auto decoded = zstdDecode(std::string(out.data(), produced), alwaysReserve, alwaysReserve);
    ASSERT_TRUE(std::holds_alternative<ZstdDecodeError>(decoded));
    EXPECT_EQ(std::get<ZstdDecodeError>(decoded), ZstdDecodeError::Malformed);
}

TEST(ZstdEncoder, LevelThreeMatchesTheStreamingHelper)
{
    const std::string plain = text(60U * 1024U);
    ZstdEncoder enc(std::nullopt);
    std::vector<char> out(ZSTD_compressBound(plain.size()));

    std::string frame;
    std::size_t offset = 0;
    while (offset < plain.size())
    {
        const auto s = enc.step(plain.data() + offset, plain.size() - offset, false, out.data(), out.size());
        frame.append(out.data(), s.produced);
        offset += s.consumed;
    }
    frame += finishAll(enc, {}, out.size());

    EXPECT_EQ(frame, zstdCompressWithoutDeclaredSize(plain, 3));
}

TEST(ZstdEncoder, ASizeMismatchThrows)
{
    std::vector<char> out(64U * 1024U);
    const auto finishUntilDone = [&](ZstdEncoder& enc)
    {
        while (!enc.step(nullptr, 0, true, out.data(), out.size()).done)
        {
        }
    };

    {
        // More than declared: zstd notices while the data is still being fed.
        const std::string plain(200, 'x');
        ZstdEncoder enc(100);
        EXPECT_THROW(enc.step(plain.data(), plain.size(), false, out.data(), out.size()), std::runtime_error);
    }
    {
        // Fewer than declared: only ending the frame can tell.
        const std::string plain(50, 'x');
        ZstdEncoder enc(100);
        EXPECT_NO_THROW(enc.step(plain.data(), plain.size(), false, out.data(), out.size()));
        EXPECT_THROW(finishUntilDone(enc), std::runtime_error);
    }
}

TEST(ZstdEncoder, TheFrameHeaderDeclaresTheSizeOnlyWithAHint)
{
    const std::string plain = text(10 * 1024);
    for (const std::optional<std::uint64_t> hint :
         {std::optional<std::uint64_t> {}, std::optional<std::uint64_t> {plain.size()}})
    {
        ZstdEncoder enc(hint);
        std::vector<char> out(ZSTD_compressBound(plain.size()));
        std::size_t offset = 0;
        std::size_t produced = 0;
        while (offset < plain.size())
        {
            const auto s = enc.step(
                plain.data() + offset, plain.size() - offset, false, out.data() + produced, out.size() - produced);
            offset += s.consumed;
            produced += s.produced;
        }
        for (;;)
        {
            const auto s = enc.step(nullptr, 0, true, out.data() + produced, out.size() - produced);
            produced += s.produced;
            if (s.done)
            {
                break;
            }
        }
        EXPECT_EQ(ZSTD_getFrameContentSize(out.data(), produced), hint ? plain.size() : ZSTD_CONTENTSIZE_UNKNOWN);
    }
}

TEST(ZstdEncoder, EstimateCoversWhatZstdAllocates)
{
    // Replays the encoder's setup on a raw context: the reservation must not undercount real memory.
    for (const std::optional<std::uint64_t> hint : {std::optional<std::uint64_t> {},
                                                    std::optional<std::uint64_t> {0},
                                                    std::optional<std::uint64_t> {20U * 1024U},
                                                    std::optional<std::uint64_t> {1U << 20}})
    {
        SCOPED_TRACE(hint ? "hint=" + std::to_string(*hint) : std::string("no hint"));
        const std::size_t payloadSize = hint ? static_cast<std::size_t>(*hint) : (1U << 20);
        const std::string plain = incompressible(payloadSize, 11);

        ZSTD_CCtx* ctx = ZSTD_createCCtx();
        ASSERT_NE(ctx, nullptr);
        ASSERT_FALSE(ZSTD_isError(ZSTD_CCtx_setParameter(ctx, ZSTD_c_compressionLevel, 3)));
        if (hint)
        {
            ASSERT_FALSE(ZSTD_isError(ZSTD_CCtx_setPledgedSrcSize(ctx, *hint)));
        }
        std::vector<char> out(ZSTD_compressBound(plain.size()));
        ZSTD_inBuffer in {plain.data(), plain.size(), 0};
        ZSTD_outBuffer outBuf {out.data(), out.size(), 0};
        ASSERT_EQ(ZSTD_compressStream2(ctx, &outBuf, &in, ZSTD_e_end), 0U);

        const std::size_t real = ZSTD_sizeof_CCtx(ctx);
        const std::size_t estimate = ZstdEncoder::estimateMemory(hint);
        RecordProperty(hint ? "real_" + std::to_string(*hint) : std::string("real_nohint"), std::to_string(real));
        RecordProperty(hint ? "estimate_" + std::to_string(*hint) : std::string("estimate_nohint"),
                       std::to_string(estimate));
        EXPECT_LE(real, estimate);
        ZSTD_freeCCtx(ctx);
    }
}

TEST(ZstdEncoder, SizesFollowTheHint)
{
    constexpr std::uint64_t k20KiB = 20U * 1024U;
    const std::optional<std::uint64_t> none;

    EXPECT_LT(ZstdEncoder::estimateMemory(0), ZstdEncoder::estimateMemory(none));
    EXPECT_LT(ZstdEncoder::estimateMemory(k20KiB), ZstdEncoder::estimateMemory(none));

    EXPECT_EQ(ZstdEncoder::outputBufferSize(none), ZSTD_CStreamOutSize());
    EXPECT_EQ(ZstdEncoder::inputBufferSize(none), ZSTD_CStreamInSize());
    for (const std::uint64_t hint : {std::uint64_t {0}, k20KiB})
    {
        EXPECT_LT(ZstdEncoder::inputBufferSize(hint), ZstdEncoder::inputBufferSize(none));
        EXPECT_LT(ZstdEncoder::outputBufferSize(hint), ZstdEncoder::outputBufferSize(none));
    }
}
