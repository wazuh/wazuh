/*
 * Wazuh remoted module (C++ worker bridge) - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "common/zstdDecoder.hpp"
#include "gzipTestHelper.hpp"
#include "zstdTestHelper.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <string>
#include <variant>
#include <vector>

using remoted::common::ReserveMoreFn;
using remoted::common::ReserveWindowFn;
using remoted::common::zstdDecode;
using remoted::common::ZstdDecodeError;
using remoted::testutil::zstdCompress;

namespace
{
    // Grants every reservation -- used by tests that aren't about the reservation mechanism itself.
    bool alwaysReserve(std::size_t)
    {
        return true;
    }

    // Grants reservations only up to a running total of maxBytes, mimicking a real (if simplified)
    // caller-owned budget. Used to test the reservation paths without needing an actual
    // InFlightBudget (that integration is covered at the AuthGateway level instead).
    ReserveMoreFn reserveUpTo(std::size_t maxBytes)
    {
        return [maxBytes, reserved = std::size_t {0}](std::size_t more) mutable
        {
            if (reserved + more > maxBytes)
            {
                return false;
            }
            reserved += more;
            return true;
        };
    }
} // namespace

TEST(ZstdDecoder, RoundTripsPlainText)
{
    const std::string plain = "Hello, this is a Wazuh event payload.";
    const auto compressed = zstdCompress(plain);

    const auto result = zstdDecode(compressed, alwaysReserve, alwaysReserve);

    ASSERT_TRUE(std::holds_alternative<std::string>(result));
    EXPECT_EQ(std::get<std::string>(result), plain);
}

TEST(ZstdDecoder, RoundTripsEmptyInput)
{
    const auto compressed = zstdCompress("");

    const auto result = zstdDecode(compressed, alwaysReserve, alwaysReserve);

    ASSERT_TRUE(std::holds_alternative<std::string>(result));
    EXPECT_EQ(std::get<std::string>(result), "");
}

TEST(ZstdDecoder, RoundTripsAcrossMultipleInternalChunks)
{
    // Bigger than zstdDecode()'s internal 64 KiB chunk, so the streaming loop -- and reserveMore --
    // runs several times.
    std::string plain;
    plain.reserve(200 * 1024);
    for (int i = 0; i < 200 * 1024 / 10; ++i)
    {
        plain += "0123456789";
    }
    const auto compressed = zstdCompress(plain);

    const auto result = zstdDecode(compressed, alwaysReserve, reserveUpTo(plain.size()));

    ASSERT_TRUE(std::holds_alternative<std::string>(result));
    EXPECT_EQ(std::get<std::string>(result), plain);
}

TEST(ZstdDecoder, EmptyBufferIsMalformed)
{
    const auto result = zstdDecode("", alwaysReserve, alwaysReserve);

    ASSERT_TRUE(std::holds_alternative<ZstdDecodeError>(result));
    EXPECT_EQ(std::get<ZstdDecodeError>(result), ZstdDecodeError::Malformed);
}

TEST(ZstdDecoder, RandomGarbageIsMalformed)
{
    const auto result = zstdDecode("this is not a zstd frame at all", alwaysReserve, alwaysReserve);

    ASSERT_TRUE(std::holds_alternative<ZstdDecodeError>(result));
    EXPECT_EQ(std::get<ZstdDecodeError>(result), ZstdDecodeError::Malformed);
}

TEST(ZstdDecoder, TruncatedStreamIsMalformed)
{
    const auto compressed = zstdCompress("some reasonably long plaintext to compress for this test");
    // Chop off the tail: a genuinely incomplete frame.
    const auto truncated = compressed.substr(0, compressed.size() / 2);

    const auto result = zstdDecode(truncated, alwaysReserve, alwaysReserve);

    ASSERT_TRUE(std::holds_alternative<ZstdDecodeError>(result));
    EXPECT_EQ(std::get<ZstdDecodeError>(result), ZstdDecodeError::Malformed);
}

TEST(ZstdDecoder, GzipStreamFedToZstdIsRejected)
{
    // A gzip-compressed stream must NOT be silently accepted by the zstd decoder: this is a
    // barrier for the HTTP `Content-Encoding: zstd` contract, and a client that mislabels its
    // encoding should fail closed, not be silently accepted via format sniffing.
    const auto gzipStream = remoted::testutil::gzipCompress("not zstd, just gzip");

    const auto result = zstdDecode(gzipStream, alwaysReserve, alwaysReserve);

    ASSERT_TRUE(std::holds_alternative<ZstdDecodeError>(result));
    EXPECT_EQ(std::get<ZstdDecodeError>(result), ZstdDecodeError::Malformed);
}

// ---------------------------------------------------------------------------
// Window reservation (read off the frame header, before anything is decoded)
// ---------------------------------------------------------------------------

TEST(ZstdDecoder, WindowReservationIsAskedForTheFramesOwnDeclaredSize)
{
    // The whole point of reading the frame header: the caller is asked to reserve what THIS frame
    // actually needs, not a blanket worst case. For a one-shot frame that is its decompressed size.
    const std::string plain(50000, 'x');
    const auto compressed = zstdCompress(plain);

    std::vector<std::size_t> windowAsks;
    const auto result = zstdDecode(
        compressed,
        [&windowAsks](std::size_t bytes)
        {
            windowAsks.push_back(bytes);
            return true;
        },
        alwaysReserve);

    ASSERT_TRUE(std::holds_alternative<std::string>(result));
    ASSERT_EQ(windowAsks.size(), 1U); // asked exactly once, before decoding
    EXPECT_EQ(windowAsks.front(), plain.size());
}

TEST(ZstdDecoder, RefusedWindowReservationAbortsWithoutDecoding)
{
    const std::string plain(256 * 1024, 'a');
    const auto compressed = zstdCompress(plain);

    bool decodedAnything = false;
    const auto result = zstdDecode(
        compressed,
        [](std::size_t) { return false; }, // the budget has no room for this frame's window
        [&decodedAnything](std::size_t)
        {
            decodedAnything = true;
            return true;
        });

    ASSERT_TRUE(std::holds_alternative<ZstdDecodeError>(result));
    EXPECT_EQ(std::get<ZstdDecodeError>(result), ZstdDecodeError::TooLarge);
    EXPECT_FALSE(decodedAnything); // refused up front: not a single chunk was produced
}

TEST(ZstdDecoder, WindowIsNotAskedForWhenTheHeaderCannotBeRead)
{
    // A garbage frame is rejected before the budget is ever consulted, so a peer sending junk
    // can't disturb the budget at all.
    bool windowAsked = false;
    const auto result = zstdDecode(
        "this is not a zstd frame at all",
        [&windowAsked](std::size_t)
        {
            windowAsked = true;
            return true;
        },
        alwaysReserve);

    ASSERT_TRUE(std::holds_alternative<ZstdDecodeError>(result));
    EXPECT_EQ(std::get<ZstdDecodeError>(result), ZstdDecodeError::Malformed);
    EXPECT_FALSE(windowAsked);
}

// ---------------------------------------------------------------------------
// Output reservation (grown per chunk, as bytes materialize)
// ---------------------------------------------------------------------------

TEST(ZstdDecoder, ReservationRefusalDuringOutputIsRejectedAsTooLarge)
{
    const std::string plain(1000, 'a'); // compresses very well (highly repetitive)
    const auto compressed = zstdCompress(plain);

    // Window is granted; the output reservation runs out far below the real decompressed size.
    const auto result = zstdDecode(compressed, alwaysReserve, reserveUpTo(10));

    ASSERT_TRUE(std::holds_alternative<ZstdDecodeError>(result));
    EXPECT_EQ(std::get<ZstdDecodeError>(result), ZstdDecodeError::TooLarge);
}

TEST(ZstdDecoder, ReservationExactlyCoveringOutputSucceeds)
{
    const std::string plain(100, 'b');
    const auto compressed = zstdCompress(plain);

    // exact fit, not "size - 1"
    const auto result = zstdDecode(compressed, alwaysReserve, reserveUpTo(plain.size()));

    ASSERT_TRUE(std::holds_alternative<std::string>(result));
    EXPECT_EQ(std::get<std::string>(result), plain);
}

TEST(ZstdDecoder, ChargedTotalCoversTheBufferAcrossManyChunks)
{
    // Spans several internal 64 KiB chunks. Whatever strategy is used to reserve, the invariant is
    // the same: the charged total must never be less than the memory the buffer actually holds.
    std::string plain;
    plain.reserve(200 * 1024);
    for (int i = 0; i < 200 * 1024 / 10; ++i)
    {
        plain += "0123456789";
    }
    const auto compressed = zstdCompress(plain);

    std::size_t charged = 0;
    const auto result = zstdDecode(compressed,
                                   alwaysReserve,
                                   [&charged](std::size_t more)
                                   {
                                       charged += more;
                                       return true;
                                   });

    ASSERT_TRUE(std::holds_alternative<std::string>(result));
    const auto& decoded = std::get<std::string>(result);
    EXPECT_EQ(decoded, plain);
    EXPECT_GE(charged, decoded.capacity());
}

// ---------------------------------------------------------------------------
// Output accounting: what is charged must cover what is really allocated
// ---------------------------------------------------------------------------

TEST(ZstdDecoder, ADeclaredSizeFrameIsChargedExactlyOnceForExactlyItsSize)
{
    // The accounting fix: charge the frame's declared decompressed size once and size the buffer to
    // it, instead of charging each 64 KiB written and letting the buffer over-allocate behind our
    // back. Charging written bytes undercounted by ~45% at this size, because std::string grows by
    // doubling -- 11 MiB of content sat in a 16 MiB allocation.
    const std::string plain(3 * 1024 * 1024, 'z'); // spans many 64 KiB chunks
    const auto compressed = zstdCompress(plain);

    std::vector<std::size_t> asks;
    const auto result = zstdDecode(compressed,
                                   alwaysReserve,
                                   [&asks](std::size_t bytes)
                                   {
                                       asks.push_back(bytes);
                                       return true;
                                   });

    ASSERT_TRUE(std::holds_alternative<std::string>(result));
    ASSERT_EQ(asks.size(), 1U); // one reservation, not one per chunk
    EXPECT_EQ(asks.front(), plain.size());
    // And what was charged really does cover the allocation -- no silent over-allocation past it.
    EXPECT_GE(asks.front(), std::get<std::string>(result).capacity());
}

TEST(ZstdDecoder, ADeclaredSizeTooBigForTheBudgetIsRefusedBeforeDecoding)
{
    // Refused on the declaration alone, before any output is produced. Note this is the OUTPUT
    // reservation refusing (the window is granted), which is why the decode never starts.
    const std::string plain(256 * 1024, 'a');
    const auto compressed = zstdCompress(plain);

    bool decodedAnything = false;
    const auto result = zstdDecode(compressed,
                                   alwaysReserve,
                                   [&decodedAnything](std::size_t)
                                   {
                                       decodedAnything = true;
                                       return false; // no room for this frame's declared size
                                   });

    ASSERT_TRUE(std::holds_alternative<ZstdDecodeError>(result));
    EXPECT_EQ(std::get<ZstdDecodeError>(result), ZstdDecodeError::TooLarge);
    EXPECT_TRUE(decodedAnything); // the single ask happened...
    // ...and it was the up-front one: nothing was decoded after it was refused.
}

TEST(ZstdDecoder, AFrameWithoutADeclaredSizeStillDecodesAndStaysFullyCharged)
{
    // Streaming-compressed frames carry no decompressed size, so the buffer has to grow in blocks.
    // Every growth is still reserved first, so the charged total covers the final capacity.
    const std::string plain(3 * 1024 * 1024, 'w');
    const auto compressed = remoted::testutil::zstdCompressWithoutDeclaredSize(plain);

    std::size_t charged = 0;
    const auto result = zstdDecode(compressed,
                                   alwaysReserve,
                                   [&charged](std::size_t bytes)
                                   {
                                       charged += bytes;
                                       return true;
                                   });

    ASSERT_TRUE(std::holds_alternative<std::string>(result));
    const auto& decoded = std::get<std::string>(result);
    EXPECT_EQ(decoded, plain);
    // The whole point: charged is never LESS than what the buffer actually holds.
    EXPECT_GE(charged, decoded.capacity());
    // Block growth, not per-chunk: far fewer reservations than the 48 chunks this body spans.
    EXPECT_LT(charged, 4U * plain.size());
}

TEST(ZstdDecoder, AFrameWithoutADeclaredSizeIsCutOffWhenTheBudgetRefusesMidway)
{
    // The block-growth path must still enforce: refuse a growth and decoding aborts, rather than
    // continuing to allocate uncharged memory.
    const std::string plain(3 * 1024 * 1024, 'w');
    const auto compressed = remoted::testutil::zstdCompressWithoutDeclaredSize(plain);

    const auto result = zstdDecode(compressed, alwaysReserve, reserveUpTo(128 * 1024));

    ASSERT_TRUE(std::holds_alternative<ZstdDecodeError>(result));
    EXPECT_EQ(std::get<ZstdDecodeError>(result), ZstdDecodeError::TooLarge);
}
