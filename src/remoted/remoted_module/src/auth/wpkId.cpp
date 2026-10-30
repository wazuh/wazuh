/*
 * Wazuh remoted module: signed WPK download identifiers
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wpkId.hpp"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <utility>

#include <openssl/crypto.h>

#include "jwt/base64Url.hpp"
#include "jwt/enrollKeyDerivation.hpp"
#include "jwt/hmacSha256.hpp"

namespace remoted::auth
{

    namespace
    {
        constexpr std::string_view kPrefix = "wpk1.";
        constexpr std::string_view kSuffix = ".wpk";
        constexpr std::string_view kTagDomain = "WAZUH-WPK-ID\n1\n";
        constexpr std::size_t kTaskIdChars = 36;
        constexpr std::size_t kClusterKeyChars = 32;
        constexpr std::size_t kClaimsBytes = 4 + 4 + std::tuple_size_v<TaskIdBytes>;
        constexpr std::size_t kTagBytes = 16;
        constexpr std::size_t kPayloadBytes = kClaimsBytes + kTagBytes;
        // base64url of 40 bytes is 54 characters, unpadded.
        constexpr std::size_t kIdChars = kPrefix.size() + 54 + kSuffix.size();
        constexpr std::chrono::seconds kDefaultTtl {600};

        using Claims = std::array<std::uint8_t, kClaimsBytes>;

        constexpr bool isDashPosition(std::size_t i)
        {
            return i == 8 || i == 13 || i == 18 || i == 23;
        }

        int hexValue(char c)
        {
            if (c >= '0' && c <= '9')
            {
                return c - '0';
            }
            if (c >= 'a' && c <= 'f')
            {
                return c - 'a' + 10;
            }
            return -1;
        }

        bool isAlnum(char c)
        {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        }

        void putBigEndian32(std::uint8_t* out, std::uint32_t value)
        {
            out[0] = static_cast<std::uint8_t>(value >> 24);
            out[1] = static_cast<std::uint8_t>(value >> 16);
            out[2] = static_cast<std::uint8_t>(value >> 8);
            out[3] = static_cast<std::uint8_t>(value);
        }

        std::uint32_t getBigEndian32(const std::uint8_t* in)
        {
            return (static_cast<std::uint32_t>(in[0]) << 24) | (static_cast<std::uint32_t>(in[1]) << 16) |
                   (static_cast<std::uint32_t>(in[2]) << 8) | static_cast<std::uint32_t>(in[3]);
        }

        /// HMAC-SHA256(key, kTagDomain || claims); false on any OpenSSL failure.
        bool computeTag(const jwt_profile::v1::SecureBytes& key,
                        const std::uint8_t* claims,
                        jwt_profile::v1::HmacSha256Digest& digest)
        {
            std::array<char, kTagDomain.size() + kClaimsBytes> message {};
            std::copy(kTagDomain.begin(), kTagDomain.end(), message.begin());
            std::copy(claims, claims + kClaimsBytes, message.begin() + kTagDomain.size());
            return jwt_profile::v1::hmacSha256(key, std::string_view {message.data(), message.size()}, digest);
        }
    } // namespace

    std::optional<TaskIdBytes> parseTaskId(std::string_view text)
    {
        if (text.size() != kTaskIdChars)
        {
            return std::nullopt;
        }
        TaskIdBytes out {};
        std::size_t byte = 0;
        for (std::size_t i = 0; i < text.size();)
        {
            if (isDashPosition(i))
            {
                if (text[i] != '-')
                {
                    return std::nullopt;
                }
                ++i;
                continue;
            }
            const int high = hexValue(text[i]);
            const int low = hexValue(text[i + 1]);
            if (high < 0 || low < 0)
            {
                return std::nullopt;
            }
            out[byte++] = static_cast<std::uint8_t>((high << 4) | low);
            i += 2;
        }
        return out;
    }

    std::string formatTaskId(const TaskIdBytes& taskId)
    {
        constexpr char kHex[] = "0123456789abcdef";
        std::string out;
        out.reserve(kTaskIdChars);
        for (std::size_t i = 0; i < taskId.size(); ++i)
        {
            if (isDashPosition(out.size()))
            {
                out.push_back('-');
            }
            out.push_back(kHex[taskId[i] >> 4]);
            out.push_back(kHex[taskId[i] & 0x0f]);
        }
        return out;
    }

    bool looksLikeWpkId(std::string_view resourceId)
    {
        return resourceId.size() >= kPrefix.size() + kSuffix.size() &&
               resourceId.substr(0, kPrefix.size()) == kPrefix &&
               resourceId.substr(resourceId.size() - kSuffix.size()) == kSuffix;
    }

    std::chrono::seconds effectiveWpkIdTtl(int configured)
    {
        return configured <= 0 ? kDefaultTtl : std::chrono::seconds {configured};
    }

    std::optional<WpkIdCodec> WpkIdCodec::fromClusterKey(std::string_view clusterKey, std::chrono::seconds ttl)
    {
        if (clusterKey.size() != kClusterKeyChars || !std::all_of(clusterKey.begin(), clusterKey.end(), isAlnum) ||
            ttl.count() <= 0)
        {
            return std::nullopt;
        }
        try
        {
            auto key = jwt_profile::v1::enroll::deriveWpkIdKey(clusterKey);
            if (!key)
            {
                return std::nullopt;
            }
            return WpkIdCodec(std::move(*key), ttl);
        }
        catch (...)
        {
            return std::nullopt;
        }
    }

    WpkIdCodec::WpkIdCodec(jwt_profile::v1::SecureBytes key, std::chrono::seconds ttl)
        : m_key(std::move(key))
        , m_ttl(ttl)
    {
    }

    std::optional<std::string>
    WpkIdCodec::issue(std::uint32_t subject, const TaskIdBytes& taskId, std::int64_t now) const
    {
        constexpr std::int64_t kMaxExp = std::numeric_limits<std::uint32_t>::max();
        const std::int64_t ttl = m_ttl.count();
        if (now < 0 || ttl > kMaxExp || now > kMaxExp - ttl)
        {
            return std::nullopt;
        }

        std::array<std::uint8_t, kPayloadBytes> payload {};
        putBigEndian32(payload.data(), subject);
        putBigEndian32(payload.data() + 4, static_cast<std::uint32_t>(now + ttl));
        std::copy(taskId.begin(), taskId.end(), payload.begin() + 8);

        jwt_profile::v1::HmacSha256Digest digest {};
        if (!computeTag(m_key, payload.data(), digest))
        {
            return std::nullopt;
        }
        std::copy(digest.begin(), digest.begin() + kTagBytes, payload.begin() + kClaimsBytes);

        try
        {
            std::string id {kPrefix};
            id += jwt_profile::v1::base64UrlEncode(payload.data(), payload.size());
            id += kSuffix;
            return id;
        }
        catch (...)
        {
            return std::nullopt;
        }
    }

    std::optional<TaskIdBytes> WpkIdCodec::verify(std::string_view id, std::uint32_t subject, std::int64_t now) const
    {
        if (id.size() != kIdChars || !looksLikeWpkId(id))
        {
            return std::nullopt;
        }
        try
        {
            const auto payload = jwt_profile::v1::base64UrlDecodeCanonical(
                id.substr(kPrefix.size(), id.size() - kPrefix.size() - kSuffix.size()));
            if (!payload || payload->size() != kPayloadBytes)
            {
                return std::nullopt;
            }
            const auto* bytes = reinterpret_cast<const std::uint8_t*>(payload->data());

            jwt_profile::v1::HmacSha256Digest digest {};
            if (!computeTag(m_key, bytes, digest) || CRYPTO_memcmp(digest.data(), bytes + kClaimsBytes, kTagBytes) != 0)
            {
                return std::nullopt;
            }
            const std::int64_t exp = getBigEndian32(bytes + 4);
            if (getBigEndian32(bytes) != subject || now < 0 || now >= exp)
            {
                return std::nullopt;
            }
            TaskIdBytes taskId {};
            std::copy(bytes + 8, bytes + kClaimsBytes, taskId.begin());
            return taskId;
        }
        catch (...)
        {
            return std::nullopt;
        }
    }

} // namespace remoted::auth
