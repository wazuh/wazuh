/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

// CA-E11b-1 (D88): the arithmetic invsync and VD share to cut their writes into Groups (indexer_client/chunking.hpp).
// The values are the ones both consumers pinned before the extraction. That the estimate covers the library's real
// charge is the component case ChunkingCharge.EstimateCoversRealCharge.

#include <string>

#include <gtest/gtest.h>

#include "indexer_client/chunking.hpp"

using namespace indexer_client;

namespace
{
    constexpr std::size_t MIB {1024 * 1024};
    constexpr std::uint64_t RESERVE {2048};

    Op op(Op::Kind kind, std::string index, std::string id, std::string body, std::string version = {})
    {
        Op result;
        result.kind = kind;
        result.index = std::move(index);
        result.id = std::move(id);
        result.body = std::move(body);
        result.body.shrink_to_fit();
        result.version = std::move(version);
        return result;
    }
} // namespace

TEST(ChunkingTest, ChunkCapIsFourFifthsOverTwoPerLane)
{
    EXPECT_EQ(209715U, chunkCap(1 * MIB, 2));              // 0.8 * 1 MiB / (2 * 2)
    EXPECT_EQ(13421772U, chunkCap(64 * MIB, 2));           // invsync's default inventory quota, two lanes
    EXPECT_EQ(419430U, chunkCap(1 * MIB, 1));              // one lane: an open and a pending chunk
    EXPECT_EQ(chunkCap(1 * MIB, 1), chunkCap(1 * MIB, 0)); // 0 lanes counts as one
    EXPECT_EQ(1U, chunkCap(0, 4));                         // never 0
    EXPECT_EQ(1U, chunkCap(1, 1));                         // 0.4 rounds down, floored at 1
}

TEST(ChunkingTest, EscapedSizeBound)
{
    EXPECT_EQ(0U, escapedSizeBound(""));
    EXPECT_EQ(3U, escapedSizeBound("abc"));
    EXPECT_EQ(4U, escapedSizeBound("a\"b"));     // '"' takes 2
    EXPECT_EQ(4U, escapedSizeBound("a\\b"));     // '\' takes 2
    EXPECT_EQ(8U, escapedSizeBound("a\nb"));     // a control character at most 6
    EXPECT_EQ(6U, escapedSizeBound("\x1f"));     // the last control character
    EXPECT_EQ(1U, escapedSizeBound(" "));        // 0x20 is not one
    EXPECT_EQ(1U, escapedSizeBound("\x7f"));     // nor DEL
    EXPECT_EQ(2U, escapedSizeBound("\xc3\xa9")); // UTF-8 goes as is
}

TEST(ChunkingTest, EstimateChargeByKind)
{
    const auto index = op(Op::Kind::Index, "idx", "id\"1", std::string(100, 'x'));
    // frame 64 + index 3 + id 5 + reserve + body capacity + '\n'
    EXPECT_EQ(64U + 3U + 5U + RESERVE + index.body.capacity() + 1U, estimateCharge(index, RESERVE));

    const auto remove = op(Op::Kind::Delete, "idx", "id", "ignored");
    EXPECT_EQ(64U + 3U + 2U + RESERVE, estimateCharge(remove, RESERVE)) << "a delete has no body";

    const auto versioned = op(Op::Kind::IndexVersionedScript, "idx", "id", std::string(100, 'x'), "42");
    // frame 64 + index + id + reserve + script frame 512 + version + the document twice
    EXPECT_EQ(64U + 3U + 2U + RESERVE + 512U + 2U + 200U, estimateCharge(versioned, RESERVE));

    const auto autoId = op(Op::Kind::IndexAutoId, "idx", "", std::string(10, 'x'));
    EXPECT_EQ(64U + 3U + RESERVE + autoId.body.capacity() + 1U, estimateCharge(autoId, RESERVE));
}

TEST(ChunkingTest, EstimateChargeCountsTheBodysSlack)
{
    auto withSlack = op(Op::Kind::Index, "idx", "id", "{}");
    withSlack.body.reserve(4096);
    EXPECT_GE(estimateCharge(withSlack, RESERVE), 64U + 3U + 2U + RESERVE + 4096U + 1U);
}

TEST(ChunkingTest, EstimateChargeTakesTheReserveAsGiven)
{
    const auto index = op(Op::Kind::Index, "idx", "id", "{}");
    EXPECT_EQ(estimateCharge(index, 0) + 4096U, estimateCharge(index, 4096));
}
