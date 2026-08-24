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
using remoted::decoding::BodyDecoder;
using remoted::decoding::ContentEncoding;
using remoted::decoding::parseContentEncoding;
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
        // And the decoded body's reservation was promoted to carry the request's identity: the
        // request counts as exactly ONE resident request, not one per reservation the decode took.
        // (No wire admission reservation exists in this unit test, so the 1 is the promotion's.)
        EXPECT_EQ(server.m_budget.inFlightCount(), 1U);
        EXPECT_EQ(server.m_budget.rejectedTotal(), 0U);
    }
    // Payload dropped -> reservation released with it, and the request count with the reservation.
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
    // This 413 is the caller's answer to an ADMITTED request: it must not register as a budget
    // shed (remoted.server.budget.rejected.total) nor linger in the in-flight request count.
    EXPECT_EQ(server.m_budget.rejectedTotal(), 0U);
    EXPECT_EQ(server.m_budget.inFlightCount(), 0U);
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
    // A refused WINDOW reservation must not register as a budget shed: the transport never turned
    // anyone away -- the request was admitted and answered 413, which already counts in
    // remoted.auth.reject.body_too_large.
    EXPECT_EQ(server.m_budget.rejectedTotal(), 0U);
    EXPECT_EQ(server.m_budget.inFlightCount(), 0U);
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

// ---------------------------------------------------------------------------
// maxDecodedSize -- a SEPARATE, smaller self-imposed ceiling on top of the shared in-flight
// budget, for routes (namely /enroll's Open mode) where an unauthenticated peer can reach
// decode() at all. Regression guard: without this, a small, highly-compressed frame could hold as
// much of the SHARED budget as it has room for, not just the tiny amount this route ever
// legitimately needs.
// ---------------------------------------------------------------------------

TEST(BodyDecoderTest, MaxDecodedSizeRejectsOutputThatWouldExceedItEvenWithBudgetToSpare)
{
    // A huge shared budget -- the shared-budget checks above would all pass easily -- but a tiny
    // self-imposed cap. The cap alone must be what rejects this, proving it is enforced
    // independently of (and can be stricter than) the shared budget.
    FakeHttpServer server {10U * 1024U * 1024U};
    constexpr std::size_t kMaxDecodedSize = 1024;
    const BodyDecoder decoder {server, /*enabled=*/true, kMaxDecodedSize};

    const std::string plain(kMaxDecodedSize + 1, 'a'); // one byte over the cap
    auto bytes = std::make_shared<std::string>(zstdCompress(plain));
    auto payload = payloadOver(bytes);

    EXPECT_EQ(decoder.decode(ContentEncoding::Zstd, payload), AuthError::BodyTooLarge);
    // Refused before ever charging the shared budget for it.
    EXPECT_EQ(server.m_budget.availableBytes(), 10U * 1024U * 1024U);
}

TEST(BodyDecoderTest, MaxDecodedSizeAllowsOutputAtOrUnderTheCap)
{
    FakeHttpServer server {10U * 1024U * 1024U};
    constexpr std::size_t kMaxDecodedSize = 1024;
    const BodyDecoder decoder {server, /*enabled=*/true, kMaxDecodedSize};

    const std::string plain(kMaxDecodedSize, 'a'); // exactly at the cap
    auto bytes = std::make_shared<std::string>(zstdCompress(plain));
    auto payload = payloadOver(bytes);

    EXPECT_EQ(decoder.decode(ContentEncoding::Zstd, payload), AuthError::None);
    EXPECT_EQ(payload.bytes().size(), kMaxDecodedSize);
}

TEST(BodyDecoderTest, DefaultMaxDecodedSizeOfZeroMeansNoExtraCapBeyondTheSharedBudget)
{
    // The default (no third constructor argument) must behave exactly as it did before this
    // parameter existed -- every other test in this file relies on that already; this test states
    // it explicitly for a body large enough that a mistakenly-nonzero default would reject it.
    FakeHttpServer server;
    const BodyDecoder decoder {server, /*enabled=*/true};

    const std::string plain(256 * 1024, 'a');
    auto bytes = std::make_shared<std::string>(zstdCompress(plain));
    auto payload = payloadOver(bytes);

    EXPECT_EQ(decoder.decode(ContentEncoding::Zstd, payload), AuthError::None);
}

TEST(BodyDecoderTest, MaxDecodedSizeAcceptsASmallStreamingCompressedBodyWithNoDeclaredSize)
{
    // Regression guard for the exact shape /enroll sees. A frame that declares no decompressed
    // size takes zstdDecode()'s block-growth path, whose first growth request is a full 64 KiB
    // regardless of how little the body really decodes to. With a cap smaller than that step
    // (kMaxEnrollBodySize is 16 KiB) every such request used to come back BodyTooLarge -> 413,
    // so an agent compressing its enrollment body on the fly could never enroll at all, while the
    // same body compressed one-shot went through. The cap has to bound real decoded size, not the
    // growth step.
    FakeHttpServer server {10U * 1024U * 1024U};
    constexpr std::size_t kMaxDecodedSize = 16U * 1024U;
    const BodyDecoder decoder {server, /*enabled=*/true, kMaxDecodedSize};

    const std::string plain = R"({"name":"agent1","version":"5.0.0"})";
    auto bytes = std::make_shared<std::string>(remoted::testutil::zstdCompressWithoutDeclaredSize(plain));
    auto payload = payloadOver(bytes);

    EXPECT_EQ(decoder.decode(ContentEncoding::Zstd, payload), AuthError::None);
    EXPECT_EQ(payload.bytes(), plain);
}

TEST(BodyDecoderTest, MaxDecodedSizeStillRejectsAnOverCapBodyWithNoDeclaredSize)
{
    // The other half: accepting the small streaming case must not have turned the cap off for the
    // block-growth path.
    FakeHttpServer server {10U * 1024U * 1024U};
    constexpr std::size_t kMaxDecodedSize = 16U * 1024U;
    const BodyDecoder decoder {server, /*enabled=*/true, kMaxDecodedSize};

    const std::string plain(kMaxDecodedSize * 8, 'a');
    auto bytes = std::make_shared<std::string>(remoted::testutil::zstdCompressWithoutDeclaredSize(plain));
    auto payload = payloadOver(bytes);

    EXPECT_EQ(decoder.decode(ContentEncoding::Zstd, payload), AuthError::BodyTooLarge);
}
