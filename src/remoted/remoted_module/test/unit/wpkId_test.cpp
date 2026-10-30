/*
 * Wazuh remoted module: signed WPK download identifier tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "auth/wpkId.hpp"
#include "endpoints/downloadEndpoint.hpp"
#include "jwt/base64Url.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

using namespace remoted::auth;
using remoted::endpoints::download::isValidWpkFilename;

namespace
{
    struct Vector
    {
        const char* clusterKey;
        std::uint32_t subject;
        const char* taskId;
        std::int64_t now;
        int ttl;
        const char* id;
    };

    // Frozen outputs of the reference codec (wpkid_ref.py, V1-V3).
    constexpr Vector kV1 {"0123456789abcdefABCDEFGHIJKLMNOP",
                          1,
                          "815a10ac-7b2e-a8a8-e137-f3edd8046a38",
                          1793098550,
                          600,
                          "wpk1.AAAAAWrghY6BWhCsey6oqOE38-3YBGo4YuKOMLVYGj_34xXog1CLbA.wpk"};
    constexpr Vector kV2 {"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
                          4294967295U,
                          "ffffffff-ffff-ffff-ffff-ffffffffffff",
                          0,
                          60,
                          "wpk1._____wAAADz_____________________A5mFj1hzUINXzjIh8PmNSQ.wpk"};
    constexpr Vector kV3 {"fd3350b86d239654e34866ab3c4988a8",
                          1234,
                          "2d6a55b2-b99f-d3df-f07e-e64d2f08dc54",
                          2000000000,
                          3600,
                          "wpk1.AAAE0nc1ohAtalWyuZ_T3_B-5k0vCNxUa38xACSwPHMeWjwiHoBtfQ.wpk"};

    constexpr std::string_view kPrefix = "wpk1.";
    constexpr std::string_view kSuffix = ".wpk";
    constexpr std::size_t kIdLength = 63;
    constexpr std::size_t kBodyBytes = 40;

    WpkIdCodec makeCodec(const Vector& v)
    {
        auto codec = WpkIdCodec::fromClusterKey(v.clusterKey, std::chrono::seconds {v.ttl});
        EXPECT_TRUE(codec.has_value());
        return std::move(*codec);
    }

    TaskIdBytes taskOf(const Vector& v)
    {
        const auto task = parseTaskId(v.taskId);
        EXPECT_TRUE(task.has_value());
        return *task;
    }

    std::uint32_t expOf(const Vector& v)
    {
        return static_cast<std::uint32_t>(v.now + v.ttl);
    }

    std::string bodyOf(const std::string& id)
    {
        return id.substr(kPrefix.size(), id.size() - kPrefix.size() - kSuffix.size());
    }

    std::string wrap(const std::string& body)
    {
        return std::string(kPrefix) + body + std::string(kSuffix);
    }

    std::string decodeBody(const std::string& id)
    {
        const auto raw = jwt_profile::v1::base64UrlDecodeCanonical(bodyOf(id));
        EXPECT_TRUE(raw.has_value());
        return *raw;
    }

    std::string encodeBody(const std::string& raw)
    {
        return wrap(jwt_profile::v1::base64UrlEncode(raw));
    }
} // namespace

TEST(WpkIdTest, IssueMatchesFrozenVectors)
{
    for (const Vector* v : {&kV1, &kV2, &kV3})
    {
        const auto codec = makeCodec(*v);
        const auto id = codec.issue(v->subject, taskOf(*v), v->now);
        ASSERT_TRUE(id.has_value()) << v->id;
        EXPECT_EQ(*id, v->id);
        EXPECT_EQ(id->size(), kIdLength);
        EXPECT_TRUE(isValidWpkFilename(*id)) << *id;
    }
}

TEST(WpkIdTest, VerifyRoundTrip)
{
    for (const Vector* v : {&kV1, &kV2, &kV3})
    {
        const auto codec = makeCodec(*v);
        const auto id = codec.issue(v->subject, taskOf(*v), v->now);
        ASSERT_TRUE(id.has_value());
        const auto task = codec.verify(*id, v->subject, static_cast<std::int64_t>(expOf(*v)) - 1);
        ASSERT_TRUE(task.has_value()) << *id;
        EXPECT_EQ(*task, taskOf(*v));
        EXPECT_EQ(formatTaskId(*task), v->taskId);
    }
}

TEST(WpkIdTest, RejectsOtherSubject)
{
    const auto codec = makeCodec(kV1);
    EXPECT_TRUE(codec.verify(kV1.id, kV1.subject, kV1.now).has_value());
    EXPECT_FALSE(codec.verify(kV1.id, kV1.subject + 1, kV1.now).has_value());
    EXPECT_FALSE(codec.verify(kV1.id, 0, kV1.now).has_value());
    EXPECT_FALSE(codec.verify(kV1.id, 0x01000001u, kV1.now).has_value());

    // Subjects that differ only in their high bytes.
    const auto codecV2 = makeCodec(kV2);
    EXPECT_TRUE(codecV2.verify(kV2.id, kV2.subject, kV2.now).has_value());
    EXPECT_FALSE(codecV2.verify(kV2.id, 0x7FFFFFFFu, kV2.now).has_value());
    EXPECT_FALSE(codecV2.verify(kV2.id, 0xFFFFFF00u, kV2.now).has_value());
}

TEST(WpkIdTest, RoundTripsTheSubjectExtremes)
{
    const auto codec = makeCodec(kV1);
    const auto task = taskOf(kV1);
    constexpr std::uint32_t kMax = std::numeric_limits<std::uint32_t>::max();

    const auto low = codec.issue(0, task, kV1.now);
    const auto high = codec.issue(kMax, task, kV1.now);
    ASSERT_TRUE(low.has_value());
    ASSERT_TRUE(high.has_value());

    EXPECT_TRUE(codec.verify(*low, 0, kV1.now).has_value());
    EXPECT_FALSE(codec.verify(*low, 1, kV1.now).has_value());
    EXPECT_FALSE(codec.verify(*low, kMax, kV1.now).has_value());

    EXPECT_TRUE(codec.verify(*high, kMax, kV1.now).has_value());
    EXPECT_FALSE(codec.verify(*high, kMax - 1, kV1.now).has_value());
    EXPECT_FALSE(codec.verify(*high, 0, kV1.now).has_value());
}

TEST(WpkIdTest, RejectsAtAndAfterExpiry)
{
    const auto codec = makeCodec(kV1);
    const std::int64_t exp = expOf(kV1);
    EXPECT_TRUE(codec.verify(kV1.id, kV1.subject, exp - 1).has_value());
    EXPECT_FALSE(codec.verify(kV1.id, kV1.subject, exp).has_value());
    EXPECT_FALSE(codec.verify(kV1.id, kV1.subject, exp + 1).has_value());
}

TEST(WpkIdTest, RejectsOtherKey)
{
    const auto other = makeCodec(kV3);
    EXPECT_FALSE(other.verify(kV1.id, kV1.subject, kV1.now).has_value());
    EXPECT_TRUE(makeCodec(kV1).verify(kV1.id, kV1.subject, kV1.now).has_value());
}

TEST(WpkIdTest, RejectsTamperedBytes)
{
    const auto codec = makeCodec(kV1);
    const std::string raw = decodeBody(kV1.id);
    ASSERT_EQ(raw.size(), kBodyBytes);
    ASSERT_TRUE(codec.verify(encodeBody(raw), kV1.subject, kV1.now).has_value());

    for (std::size_t i = 0; i < kBodyBytes; ++i)
    {
        std::string altered = raw;
        altered[i] = static_cast<char>(altered[i] ^ 0x01);
        const auto id = encodeBody(altered);
        ASSERT_EQ(id.size(), kIdLength);
        EXPECT_FALSE(codec.verify(id, kV1.subject, kV1.now).has_value()) << "byte " << i;
    }
}

TEST(WpkIdTest, RejectsNonCanonicalBase64Url)
{
    const auto codec = makeCodec(kV1);
    ASSERT_TRUE(codec.verify(kV1.id, kV1.subject, kV1.now).has_value());

    // 54 chars carry 40 bytes; the last char has 4 unused low bits, set one of them.
    constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string body = bodyOf(kV1.id);
    ASSERT_EQ(body.size(), 54U);
    const auto sextet = alphabet.find(body.back());
    ASSERT_NE(sextet, std::string_view::npos);
    ASSERT_EQ(sextet & 0x0F, 0U);
    body.back() = alphabet[sextet | 0x01];

    const auto dirty = wrap(body);
    ASSERT_EQ(dirty.size(), kIdLength);
    ASSERT_NE(dirty, std::string(kV1.id));
    // A lenient decoder would read the same 40 bytes, so the tag would match.
    ASSERT_TRUE(jwt_profile::v1::isBase64UrlAlphabet(body));
    EXPECT_FALSE(jwt_profile::v1::isCanonicalBase64Url(body));
    EXPECT_FALSE(codec.verify(dirty, kV1.subject, kV1.now).has_value());
}

TEST(WpkIdTest, RejectsWrongLength)
{
    const auto codec = makeCodec(kV1);
    const std::string raw = decodeBody(kV1.id);

    EXPECT_FALSE(codec.verify(encodeBody(raw.substr(0, kBodyBytes - 1)), kV1.subject, kV1.now).has_value());
    EXPECT_FALSE(codec.verify(encodeBody(raw + 'A'), kV1.subject, kV1.now).has_value());
    EXPECT_FALSE(codec.verify(encodeBody(raw.substr(0, 24)), kV1.subject, kV1.now).has_value());
    EXPECT_FALSE(codec.verify(wrap(""), kV1.subject, kV1.now).has_value());
    EXPECT_FALSE(codec.verify("", kV1.subject, kV1.now).has_value());
    EXPECT_FALSE(codec.verify(std::string(kV1.id) + "A", kV1.subject, kV1.now).has_value());
}

TEST(WpkIdTest, RejectsWrongPrefixOrSuffix)
{
    const auto codec = makeCodec(kV1);
    const std::string body = bodyOf(kV1.id);

    EXPECT_FALSE(codec.verify("wpk2." + body + ".wpk", kV1.subject, kV1.now).has_value());
    EXPECT_FALSE(codec.verify("WPK1." + body + ".wpk", kV1.subject, kV1.now).has_value());
    EXPECT_FALSE(codec.verify("wpk1." + body + ".WPK", kV1.subject, kV1.now).has_value());
    EXPECT_FALSE(codec.verify("wpk1." + body + ".wpx", kV1.subject, kV1.now).has_value());
    EXPECT_FALSE(codec.verify("wpk1." + body + "xwpk", kV1.subject, kV1.now).has_value());
    EXPECT_FALSE(codec.verify("wpk1x" + body + ".wpk", kV1.subject, kV1.now).has_value());
    EXPECT_FALSE(codec.verify("xxxxx" + body + ".wpk", kV1.subject, kV1.now).has_value());
    EXPECT_FALSE(codec.verify("wpk1." + body + "xxxx", kV1.subject, kV1.now).has_value());
    EXPECT_FALSE(codec.verify(body, kV1.subject, kV1.now).has_value());
}

TEST(WpkIdTest, LooksLikeWpkIdEdgeCases)
{
    EXPECT_FALSE(looksLikeWpkId("wpk1.wpk"));
    EXPECT_FALSE(looksLikeWpkId(""));
    EXPECT_FALSE(looksLikeWpkId("wazuh-agent-4.9.0.wpk"));

    const std::string noSuffix = std::string(kV1.id).substr(0, kIdLength - kSuffix.size()) + "zzzz";
    ASSERT_EQ(noSuffix.size(), kIdLength);
    EXPECT_FALSE(looksLikeWpkId(noSuffix));

    for (const Vector* v : {&kV1, &kV2, &kV3})
    {
        EXPECT_TRUE(looksLikeWpkId(v->id));
    }
}

TEST(WpkIdTest, IssueRejectsExpOverflow)
{
    const auto codec = makeCodec(kV1);
    const std::int64_t max = std::numeric_limits<std::uint32_t>::max();

    // exp == UINT32_MAX still fits 32 bits.
    EXPECT_TRUE(codec.issue(kV1.subject, taskOf(kV1), max - kV1.ttl).has_value());
    EXPECT_FALSE(codec.issue(kV1.subject, taskOf(kV1), max - kV1.ttl + 1).has_value());
    EXPECT_FALSE(codec.issue(kV1.subject, taskOf(kV1), max).has_value());
    EXPECT_FALSE(codec.issue(kV1.subject, taskOf(kV1), std::numeric_limits<std::int64_t>::max()).has_value());
    EXPECT_FALSE(codec.issue(kV1.subject, taskOf(kV1), -1).has_value());
    EXPECT_FALSE(codec.issue(kV1.subject, taskOf(kV1), std::numeric_limits<std::int64_t>::min()).has_value());
}

TEST(WpkIdTest, VerifyRejectsNegativeNow)
{
    const auto codec = makeCodec(kV2);
    ASSERT_TRUE(codec.verify(kV2.id, kV2.subject, 0).has_value());
    EXPECT_FALSE(codec.verify(kV2.id, kV2.subject, -1).has_value());
    EXPECT_FALSE(codec.verify(kV2.id, kV2.subject, std::numeric_limits<std::int64_t>::min()).has_value());
}

TEST(WpkIdTest, TaskIdRoundTrip)
{
    for (const char* text : {"815a10ac-7b2e-a8a8-e137-f3edd8046a38",
                             "ffffffff-ffff-ffff-ffff-ffffffffffff",
                             "00000000-0000-0000-0000-000000000000",
                             "2d6a55b2-b99f-d3df-f07e-e64d2f08dc54"})
    {
        const auto bytes = parseTaskId(text);
        ASSERT_TRUE(bytes.has_value()) << text;
        EXPECT_EQ(formatTaskId(*bytes), text);
    }

    const auto bytes = parseTaskId("815a10ac-7b2e-a8a8-e137-f3edd8046a38");
    ASSERT_TRUE(bytes.has_value());
    EXPECT_EQ((*bytes)[0], 0x81);
    EXPECT_EQ((*bytes)[1], 0x5a);
    EXPECT_EQ((*bytes)[15], 0x38);
}

TEST(WpkIdTest, TaskIdRejectsMalformed)
{
    EXPECT_FALSE(parseTaskId("").has_value());
    EXPECT_FALSE(parseTaskId("815A10AC-7B2E-A8A8-E137-F3EDD8046A38").has_value());
    EXPECT_FALSE(parseTaskId("815a10ac7-b2e-a8a8-e137-f3edd8046a38").has_value());
    EXPECT_FALSE(parseTaskId("815a10ac-7b2ea-8a8-e137-f3edd8046a38").has_value());
    EXPECT_FALSE(parseTaskId("815a10ac7b2ea8a8e137f3edd8046a38").has_value());
    EXPECT_FALSE(parseTaskId("815a10ac-7b2e-a8a8-e137-f3edd8046a3").has_value());
    EXPECT_FALSE(parseTaskId("815a10ac-7b2e-a8a8-e137-f3edd8046a380").has_value());
    EXPECT_FALSE(parseTaskId("815a10ac-7b2e-a8a8-e137-f3edd8046a3g").has_value());
    EXPECT_FALSE(parseTaskId("815a10ac-7b2e-a8a8-e137-f3edd8046a3 ").has_value());
    EXPECT_FALSE(parseTaskId("{815a10ac-7b2e-a8a8-e137-f3edd8046a38}").has_value());
}

TEST(WpkIdTest, FromClusterKeyRejectsEmpty)
{
    EXPECT_FALSE(WpkIdCodec::fromClusterKey("", std::chrono::seconds {600}).has_value());
}

TEST(WpkIdTest, FromClusterKeyRejectsUndefinedOrShort)
{
    const std::chrono::seconds ttl {600};
    EXPECT_FALSE(WpkIdCodec::fromClusterKey("undefined", ttl).has_value());
    EXPECT_FALSE(WpkIdCodec::fromClusterKey(std::string(31, 'a'), ttl).has_value());
    EXPECT_FALSE(WpkIdCodec::fromClusterKey(std::string(33, 'a'), ttl).has_value());
    EXPECT_FALSE(WpkIdCodec::fromClusterKey(std::string(31, 'a') + "-", ttl).has_value());
    EXPECT_FALSE(WpkIdCodec::fromClusterKey(std::string(31, 'a') + " ", ttl).has_value());
    EXPECT_FALSE(WpkIdCodec::fromClusterKey(std::string(31, 'a') + "_", ttl).has_value());
    // Two non-ASCII bytes ("\xC3\xA9") plus 30 ASCII ones make 32 bytes, none outside [A-Za-z0-9] allowed.
    EXPECT_FALSE(WpkIdCodec::fromClusterKey(std::string("\xC3\xA9") + std::string(30, 'a'), ttl).has_value());
    EXPECT_FALSE(WpkIdCodec::fromClusterKey(std::string(31, 'a') + "\xFF", ttl).has_value());
    EXPECT_FALSE(WpkIdCodec::fromClusterKey(std::string(31, 'a') + std::string(1, '\0'), ttl).has_value());

    EXPECT_TRUE(WpkIdCodec::fromClusterKey(std::string(32, 'a'), ttl).has_value());
}

TEST(WpkIdTest, FromClusterKeyRejectsNonPositiveTtl)
{
    EXPECT_FALSE(WpkIdCodec::fromClusterKey(kV1.clusterKey, std::chrono::seconds {0}).has_value());
    EXPECT_FALSE(WpkIdCodec::fromClusterKey(kV1.clusterKey, std::chrono::seconds {-1}).has_value());
    EXPECT_TRUE(WpkIdCodec::fromClusterKey(kV1.clusterKey, std::chrono::seconds {1}).has_value());
}

TEST(WpkIdTest, EffectiveTtlDefaultsAndPassesThrough)
{
    EXPECT_EQ(effectiveWpkIdTtl(0), std::chrono::seconds {600});
    EXPECT_EQ(effectiveWpkIdTtl(-1), std::chrono::seconds {600});
    EXPECT_EQ(effectiveWpkIdTtl(60), std::chrono::seconds {60});
    EXPECT_EQ(effectiveWpkIdTtl(900), std::chrono::seconds {900});
}
