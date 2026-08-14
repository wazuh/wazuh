/*
 * Wazuh remoted module (C++ worker bridge) - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "decoding/bodyDecoder.hpp"
#include "fakeHttpServer.hpp"
#include "gzipTestHelper.hpp"
#include "zstdTestHelper.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <memory>
#include <string>

using remoted::auth::AuthError;
using remoted::auth::Payload;
using remoted::decoding::ContentEncoding;
using remoted::decoding::parseContentEncoding;
using remoted::decoding::BodyDecoder;
using remoted::testutil::FakeHttpServer;
using remoted::testutil::zstdCompress;

namespace
{
    // A Payload over caller-owned bytes, like the one AuthGateway hands the decoder (a view into
    // the transport's request buffer, kept alive by a shared_ptr).
    Payload payloadOver(const std::shared_ptr<std::string>& bytes)
    {
        return Payload {*bytes, bytes};
    }
} // namespace

// ---------------------------------------------------------------------------
// Passthrough and encoding selection
// ---------------------------------------------------------------------------

TEST(BodyDecoderTest, EmptyContentEncodingLeavesThePayloadUntouched)
{
    FakeHttpServer server;
    const BodyDecoder decoder {server, /*enabled=*/true};

    auto bytes = std::make_shared<std::string>("plain uncompressed body");
    auto payload = payloadOver(bytes);

    EXPECT_EQ(decoder.decode(ContentEncoding::None, payload), AuthError::None);
    EXPECT_EQ(payload.bytes(), "plain uncompressed body");
    // Nothing was charged: an uncompressed body needs no decoding memory at all.
    EXPECT_EQ(server.m_budget.inFlightCount(), 0U);
}

TEST(BodyDecoderTest, ZstdBodyIsDecompressed)
{
    FakeHttpServer server;
    const BodyDecoder decoder {server, /*enabled=*/true};

    const std::string plain = R"(H {"wazuh":{"agent":{"id":"1"}}})";
    auto bytes = std::make_shared<std::string>(zstdCompress(plain));
    auto payload = payloadOver(bytes);

    EXPECT_EQ(decoder.decode(ContentEncoding::Zstd, payload), AuthError::None);
    EXPECT_EQ(payload.bytes(), plain);
}

TEST(BodyDecoderTest, UnsupportedEncodingIsRejectedAndThePayloadLeftAlone)
{
    FakeHttpServer server;
    const BodyDecoder decoder {server, /*enabled=*/true};

    auto bytes = std::make_shared<std::string>("some-body");
    auto payload = payloadOver(bytes);

    EXPECT_EQ(decoder.decode(ContentEncoding::Unsupported, payload), AuthError::UnsupportedContentEncoding);
    EXPECT_EQ(payload.bytes(), "some-body"); // rejected, so left as-is
}

TEST(BodyDecoderTest, AGzipBodyIsNeverDecodedEvenThoughItIsAValidGzipStream)
{
    // gzip was deliberately dropped in favor of zstd-only support. Mislabeling it as zstd must fail
    // closed on the frame check rather than be accepted via format sniffing -- and labeling it
    // honestly gets it rejected by the parser (see ParseContentEncoding.GzipIsUnsupported).
    FakeHttpServer server;
    const BodyDecoder decoder {server, /*enabled=*/true};

    auto bytes = std::make_shared<std::string>(remoted::testutil::gzipCompress("some payload"));
    auto payload = payloadOver(bytes);

    EXPECT_EQ(decoder.decode(ContentEncoding::Zstd, payload), AuthError::MalformedContentEncoding);
}

// ---------------------------------------------------------------------------
// Header parsing: which encoding a raw header value maps to
//
// Parsing lives at the edge (parseContentEncoding), so it is tested on its own rather than through
// a decoder that would need a compressed fixture just to exercise a string comparison.
// ---------------------------------------------------------------------------

TEST(ParseContentEncoding, AbsentHeaderIsNone)
{
    EXPECT_EQ(parseContentEncoding(""), ContentEncoding::None);
}

TEST(ParseContentEncoding, ZstdIsRecognizedCaseInsensitively)
{
    EXPECT_EQ(parseContentEncoding("zstd"), ContentEncoding::Zstd);
    EXPECT_EQ(parseContentEncoding("ZSTD"), ContentEncoding::Zstd);
    EXPECT_EQ(parseContentEncoding("ZsTd"), ContentEncoding::Zstd);
}

TEST(ParseContentEncoding, GzipIsUnsupported)
{
    // Not a typo-tolerance case: gzip is a real encoding this build intentionally does not implement.
    EXPECT_EQ(parseContentEncoding("gzip"), ContentEncoding::Unsupported);
    EXPECT_EQ(parseContentEncoding("GZIP"), ContentEncoding::Unsupported);
}

TEST(ParseContentEncoding, AnythingElseIsUnsupported)
{
    EXPECT_EQ(parseContentEncoding("br"), ContentEncoding::Unsupported);
    EXPECT_EQ(parseContentEncoding("deflate"), ContentEncoding::Unsupported);
    EXPECT_EQ(parseContentEncoding("identity"), ContentEncoding::Unsupported);
    EXPECT_EQ(parseContentEncoding("zstd, gzip"), ContentEncoding::Unsupported); // no multi-codec support
    EXPECT_EQ(parseContentEncoding("zst"), ContentEncoding::Unsupported);        // prefix is not a match
    EXPECT_EQ(parseContentEncoding("zstdd"), ContentEncoding::Unsupported);      // nor is a superstring
}

TEST(BodyDecoderTest, ZstdIsUnsupportedWhenDisabled)
{
    FakeHttpServer server;
    const BodyDecoder decoder {server, /*enabled=*/false};

    auto bytes = std::make_shared<std::string>(zstdCompress("some payload"));
    auto payload = payloadOver(bytes);

    // Same rejection as any unknown encoding -- no separate code path for "turned off".
    EXPECT_EQ(decoder.decode(ContentEncoding::Zstd, payload), AuthError::UnsupportedContentEncoding);
}

// ---------------------------------------------------------------------------
// Malformed input
// ---------------------------------------------------------------------------

TEST(BodyDecoderTest, BodyThatIsNotAZstdFrameIsMalformed)
{
    FakeHttpServer server;
    const BodyDecoder decoder {server, /*enabled=*/true};

    auto bytes = std::make_shared<std::string>("definitely not a zstd frame");
    auto payload = payloadOver(bytes);

    EXPECT_EQ(decoder.decode(ContentEncoding::Zstd, payload), AuthError::MalformedContentEncoding);
}

TEST(BodyDecoderTest, TruncatedFrameIsMalformed)
{
    FakeHttpServer server;
    const BodyDecoder decoder {server, /*enabled=*/true};

    const auto full = zstdCompress("some reasonably long plaintext to compress for this test");
    auto bytes = std::make_shared<std::string>(full.substr(0, full.size() / 2));
    auto payload = payloadOver(bytes);

    EXPECT_EQ(decoder.decode(ContentEncoding::Zstd, payload), AuthError::MalformedContentEncoding);
}

// ---------------------------------------------------------------------------
// Memory accounting against the in-flight budget
// ---------------------------------------------------------------------------

TEST(BodyDecoderTest, DecodedBytesStayChargedUntilThePayloadIsDropped)
{
    // The decoded bytes are a REAL reservation held for as long as the payload is, not a figure
    // checked once and forgotten.
    constexpr std::size_t kBudget = 100000;
    constexpr std::size_t kPlainSize = 50000;
    FakeHttpServer server {kBudget};
    const BodyDecoder decoder {server, /*enabled=*/true};

    const std::string plain(kPlainSize, 'x');
    auto bytes = std::make_shared<std::string>(zstdCompress(plain));

    {
        auto payload = payloadOver(bytes);
        ASSERT_EQ(decoder.decode(ContentEncoding::Zstd, payload), AuthError::None);
        ASSERT_EQ(payload.bytes().size(), kPlainSize);

        // Only the OUTPUT is still charged: the decoder's own buffers were released as soon as
        // decoding finished (zstd had already freed them), so this is kPlainSize and not double it.
        EXPECT_EQ(server.m_budget.availableBytes(), kBudget - kPlainSize);
    }
    // Payload dropped -> reservation released with it.
    EXPECT_EQ(server.m_budget.availableBytes(), kBudget);
    EXPECT_EQ(server.m_budget.inFlightCount(), 0U);
}

TEST(BodyDecoderTest, OutputNotFittingTheBudgetIsTooLarge)
{
    // Tiny budget, highly compressible body: the wire bytes fit easily but the decoded output
    // doesn't, so it is refused while decoding rather than after materializing in full.
    FakeHttpServer server {100};
    const BodyDecoder decoder {server, /*enabled=*/true};

    const std::string plain(1000, 'a');
    auto bytes = std::make_shared<std::string>(zstdCompress(plain));
    ASSERT_LT(bytes->size(), 100U);
    auto payload = payloadOver(bytes);

    EXPECT_EQ(decoder.decode(ContentEncoding::Zstd, payload), AuthError::BodyTooLarge);
    // Refused: nothing stays charged, and the payload still holds the original wire bytes.
    EXPECT_EQ(server.m_budget.availableBytes(), 100U);
    EXPECT_EQ(payload.bytes(), *bytes);
}

TEST(BodyDecoderTest, FrameNeedingMoreBuffersThanTheBudgetHasIsTooLarge)
{
    // A frame declares its own memory requirement in its header. This one needs ~256 KiB of decoder
    // buffers; the budget has 1 KiB, so it is refused up front -- before any output is produced.
    FakeHttpServer server {1024};
    const BodyDecoder decoder {server, /*enabled=*/true};

    const std::string plain(256 * 1024, 'a');
    auto bytes = std::make_shared<std::string>(zstdCompress(plain));
    ASSERT_LT(bytes->size(), 1024U); // the compressed body itself is tiny
    auto payload = payloadOver(bytes);

    EXPECT_EQ(decoder.decode(ContentEncoding::Zstd, payload), AuthError::BodyTooLarge);
    EXPECT_EQ(server.m_budget.availableBytes(), 1024U);
}

TEST(BodyDecoderTest, AmpleBudgetAllowsTheSameLargeFrame)
{
    // Mirror of the test above with room to spare: the same frame must decode fine. Together they
    // show the outcome tracks available capacity, not anything intrinsic to the frame.
    FakeHttpServer server;
    const BodyDecoder decoder {server, /*enabled=*/true};

    const std::string plain(256 * 1024, 'a');
    auto bytes = std::make_shared<std::string>(zstdCompress(plain));
    auto payload = payloadOver(bytes);

    EXPECT_EQ(decoder.decode(ContentEncoding::Zstd, payload), AuthError::None);
    EXPECT_EQ(payload.bytes().size(), plain.size());
}
