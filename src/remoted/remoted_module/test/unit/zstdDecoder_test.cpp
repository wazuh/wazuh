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

#include <string>
#include <variant>

using remoted::common::zstdDecode;
using remoted::common::ZstdDecodeError;
using remoted::testutil::zstdCompress;

TEST(ZstdDecoder, RoundTripsPlainText)
{
    const std::string plain = "Hello, this is a Wazuh event payload.";
    const auto compressed = zstdCompress(plain);

    const auto result = zstdDecode(compressed, 1024 * 1024);

    ASSERT_TRUE(std::holds_alternative<std::string>(result));
    EXPECT_EQ(std::get<std::string>(result), plain);
}

TEST(ZstdDecoder, RoundTripsEmptyInput)
{
    const auto compressed = zstdCompress("");

    const auto result = zstdDecode(compressed, 1024);

    ASSERT_TRUE(std::holds_alternative<std::string>(result));
    EXPECT_EQ(std::get<std::string>(result), "");
}

TEST(ZstdDecoder, RoundTripsAcrossMultipleInternalChunks)
{
    // Bigger than zstdDecode()'s internal 64 KiB chunk, so the streaming loop runs several times.
    std::string plain;
    plain.reserve(200 * 1024);
    for (int i = 0; i < 200 * 1024 / 10; ++i)
    {
        plain += "0123456789";
    }
    const auto compressed = zstdCompress(plain);

    const auto result = zstdDecode(compressed, plain.size() + 1);

    ASSERT_TRUE(std::holds_alternative<std::string>(result));
    EXPECT_EQ(std::get<std::string>(result), plain);
}

TEST(ZstdDecoder, EmptyBufferIsMalformed)
{
    const auto result = zstdDecode("", 1024);

    ASSERT_TRUE(std::holds_alternative<ZstdDecodeError>(result));
    EXPECT_EQ(std::get<ZstdDecodeError>(result), ZstdDecodeError::Malformed);
}

TEST(ZstdDecoder, RandomGarbageIsMalformed)
{
    const auto result = zstdDecode("this is not a zstd frame at all", 1024);

    ASSERT_TRUE(std::holds_alternative<ZstdDecodeError>(result));
    EXPECT_EQ(std::get<ZstdDecodeError>(result), ZstdDecodeError::Malformed);
}

TEST(ZstdDecoder, TruncatedStreamIsMalformed)
{
    const auto compressed = zstdCompress("some reasonably long plaintext to compress for this test");
    // Chop off the tail: a genuinely incomplete frame.
    const auto truncated = compressed.substr(0, compressed.size() / 2);

    const auto result = zstdDecode(truncated, 1024);

    ASSERT_TRUE(std::holds_alternative<ZstdDecodeError>(result));
    EXPECT_EQ(std::get<ZstdDecodeError>(result), ZstdDecodeError::Malformed);
}

TEST(ZstdDecoder, GzipStreamFedToZstdIsRejected)
{
    // A gzip-compressed stream must NOT be silently accepted by the zstd decoder: this is a
    // barrier for the HTTP `Content-Encoding: zstd` contract, and a client that mislabels its
    // encoding should fail closed, not be silently accepted via format sniffing.
    const auto gzipStream = remoted::testutil::gzipCompress("not zstd, just gzip");

    const auto result = zstdDecode(gzipStream, 1024);

    ASSERT_TRUE(std::holds_alternative<ZstdDecodeError>(result));
    EXPECT_EQ(std::get<ZstdDecodeError>(result), ZstdDecodeError::Malformed);
}

TEST(ZstdDecoder, DecompressedSizeExceedingLimitIsRejected)
{
    const std::string plain(1000, 'a'); // compresses very well (highly repetitive)
    const auto compressed = zstdCompress(plain);

    const auto result = zstdDecode(compressed, 10); // far below the real decompressed size

    ASSERT_TRUE(std::holds_alternative<ZstdDecodeError>(result));
    EXPECT_EQ(std::get<ZstdDecodeError>(result), ZstdDecodeError::TooLarge);
}

TEST(ZstdDecoder, DecompressedSizeExactlyAtLimitSucceeds)
{
    const std::string plain(100, 'b');
    const auto compressed = zstdCompress(plain);

    const auto result = zstdDecode(compressed, plain.size()); // exact fit, not "size - 1"

    ASSERT_TRUE(std::holds_alternative<std::string>(result));
    EXPECT_EQ(std::get<std::string>(result), plain);
}
