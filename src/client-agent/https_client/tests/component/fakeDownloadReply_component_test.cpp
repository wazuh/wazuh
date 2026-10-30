/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * The fake manager's /download reply shapes (#38514), checked against a streaming zstd decoder used
 * the way libcurl uses one: fed whatever arrives, with no end-of-frame check. The download tests read
 * meaning into each shape (a corrupt frame is a decode error, a truncated one is not), so that meaning
 * is pinned here rather than assumed.
 */

#include "fakeDownloadReply.hpp"

#include <gtest/gtest.h>

#include <zstd.h>

#include <memory>
#include <optional>
#include <string>

namespace
{
    /// Eight zstd blocks, so half a frame still holds whole blocks to decode.
    constexpr size_t CONFIG_BYTES = 1024 * 1024;

    /// What a decoder fed `frame` gives back, or nullopt when it reports an error.
    std::optional<std::string> decodeLikeCurl(const std::string& frame)
    {
        const std::unique_ptr<ZSTD_DStream, size_t (*)(ZSTD_DStream*)> dstream {ZSTD_createDStream(), ZSTD_freeDStream};
        std::string plain;
        std::string chunk(16 * 1024, '\0');
        ZSTD_inBuffer in {frame.data(), frame.size(), 0};

        for (;;)
        {
            ZSTD_outBuffer out {chunk.data(), chunk.size(), 0};

            if (ZSTD_isError(ZSTD_decompressStream(dstream.get(), &out, &in)))
            {
                return std::nullopt;
            }

            plain.append(chunk.data(), out.pos);

            if (in.pos == in.size && out.pos < out.size)
            {
                return plain;
            }
        }
    }

    void expectDecodesTo(const std::string& blob, const std::string& frame)
    {
        const auto decoded = decodeLikeCurl(frame);
        ASSERT_TRUE(decoded.has_value());
        EXPECT_TRUE(*decoded == blob) << "decoded " << decoded->size() << " of " << blob.size() << " bytes";
    }
} // namespace

TEST(FakeDownloadReplyTest, OffersZstdReadsTheCodingList)
{
    EXPECT_TRUE(offersZstd("zstd"));
    EXPECT_TRUE(offersZstd("gzip, ZSTD"));
    EXPECT_TRUE(offersZstd("zstd;q=1"));
    EXPECT_FALSE(offersZstd(""));
    EXPECT_FALSE(offersZstd("gzip"));
    EXPECT_FALSE(offersZstd("zstdx, x-zstd"));
}

TEST(FakeDownloadReplyTest, ARequestThatDidNotOfferZstdGetsThePlainBlobWhateverTheReply)
{
    const std::string blob = mergedConfigText(CONFIG_BYTES);

    for (const auto reply :
            {
                DownloadReply::Plain, DownloadReply::Zstd, DownloadReply::ZstdCorrupt,
                DownloadReply::ZstdTruncatedFrame, DownloadReply::ZstdUnterminated
            })
    {
        const DownloadBody body = shapeDownloadBody(blob, reply, /*offeredZstd=*/false);
        EXPECT_EQ(blob, body.bytes);
        EXPECT_FALSE(body.zstdEncoded);
        EXPECT_TRUE(body.terminated);
    }
}

TEST(FakeDownloadReplyTest, APlainReplyStaysPlainWhenZstdWasOffered)
{
    const std::string blob = mergedConfigText(CONFIG_BYTES);
    const DownloadBody body = shapeDownloadBody(blob, DownloadReply::Plain, /*offeredZstd=*/true);

    EXPECT_EQ(blob, body.bytes);
    EXPECT_FALSE(body.zstdEncoded);
}

TEST(FakeDownloadReplyTest, AZstdReplyIsOneFrameThatDecodesBackToTheBlob)
{
    const std::string blob = mergedConfigText(CONFIG_BYTES);
    const DownloadBody body = shapeDownloadBody(blob, DownloadReply::Zstd, /*offeredZstd=*/true);

    EXPECT_TRUE(body.zstdEncoded);
    EXPECT_TRUE(body.terminated);
    EXPECT_LT(body.bytes.size(), blob.size() / 10);
    EXPECT_EQ(ZSTD_findFrameCompressedSize(body.bytes.data(), body.bytes.size()), body.bytes.size());
    expectDecodesTo(blob, body.bytes);
}

TEST(FakeDownloadReplyTest, ACorruptReplyFailsToDecode)
{
    const DownloadBody body = shapeDownloadBody(mergedConfigText(CONFIG_BYTES), DownloadReply::ZstdCorrupt, /*offeredZstd=*/true);

    EXPECT_TRUE(body.zstdEncoded);
    EXPECT_FALSE(decodeLikeCurl(body.bytes).has_value());
}

TEST(FakeDownloadReplyTest, ATruncatedReplyDecodesWithoutErrorToAShorterPrefix)
{
    const std::string blob = mergedConfigText(CONFIG_BYTES);
    const DownloadBody body = shapeDownloadBody(blob, DownloadReply::ZstdTruncatedFrame, /*offeredZstd=*/true);
    const auto decoded = decodeLikeCurl(body.bytes);

    EXPECT_TRUE(body.terminated);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_FALSE(decoded->empty());
    EXPECT_LT(decoded->size(), blob.size());
    EXPECT_EQ(0u, blob.compare(0, decoded->size(), *decoded));
}

TEST(FakeDownloadReplyTest, AnUnterminatedReplyIsAWholeFrameWhoseStreamStopsEarly)
{
    const std::string blob = mergedConfigText(CONFIG_BYTES);
    const DownloadBody body = shapeDownloadBody(blob, DownloadReply::ZstdUnterminated, /*offeredZstd=*/true);

    EXPECT_FALSE(body.terminated);
    expectDecodesTo(blob, body.bytes);
}
