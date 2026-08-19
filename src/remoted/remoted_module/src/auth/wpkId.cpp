/*
 * Wazuh remoted module - signed WPK identifiers (PoC for #38283)
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wpkId.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <sys/stat.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <vector>

namespace remoted::auth
{
    namespace
    {
        // Domain separation, the same reason the canonical request string carries "WAZUH-REQUEST".
        constexpr std::string_view kMacLabel {"WAZUH-WPK-ID\n1\n"};
        constexpr std::string_view kHkdfInfo {"WAZUH-WPK-ID-v1"};

        constexpr std::string_view kB64 {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"};

        std::string b64UrlEncode(const std::uint8_t* d, std::size_t n)
        {
            std::string out;
            out.reserve(((n + 2) / 3) * 4);
            for (std::size_t i = 0; i < n; i += 3)
            {
                const std::size_t left = n - i;
                const std::uint32_t b = (static_cast<std::uint32_t>(d[i]) << 16) |
                                        (left > 1 ? static_cast<std::uint32_t>(d[i + 1]) << 8 : 0U) |
                                        (left > 2 ? static_cast<std::uint32_t>(d[i + 2]) : 0U);
                out.push_back(kB64[(b >> 18) & 0x3FU]);
                out.push_back(kB64[(b >> 12) & 0x3FU]);
                if (left > 1)
                {
                    out.push_back(kB64[(b >> 6) & 0x3FU]);
                }
                if (left > 2)
                {
                    out.push_back(kB64[b & 0x3FU]);
                }
            }
            return out;
        }

        bool b64UrlDecode(std::string_view t, std::vector<std::uint8_t>& out)
        {
            auto val = [](char c) -> int
            {
                if (c >= 'A' && c <= 'Z') return c - 'A';
                if (c >= 'a' && c <= 'z') return c - 'a' + 26;
                if (c >= '0' && c <= '9') return c - '0' + 52;
                if (c == '-') return 62;
                if (c == '_') return 63;
                return -1;
            };
            if (t.size() % 4 == 1)
            {
                return false;
            }
            out.clear();
            std::uint32_t acc {0};
            int bits {0};
            for (const char c : t)
            {
                const int v = val(c);
                if (v < 0)
                {
                    return false;
                }
                acc = (acc << 6) | static_cast<std::uint32_t>(v);
                bits += 6;
                if (bits >= 8)
                {
                    bits -= 8;
                    out.push_back(static_cast<std::uint8_t>((acc >> bits) & 0xFFU));
                }
            }
            return true;
        }

        void putBe32(std::vector<std::uint8_t>& o, std::uint32_t v)
        {
            o.push_back(static_cast<std::uint8_t>(v >> 24));
            o.push_back(static_cast<std::uint8_t>(v >> 16));
            o.push_back(static_cast<std::uint8_t>(v >> 8));
            o.push_back(static_cast<std::uint8_t>(v));
        }

        std::uint32_t readBe32(const std::uint8_t* d)
        {
            return (static_cast<std::uint32_t>(d[0]) << 24) | (static_cast<std::uint32_t>(d[1]) << 16) |
                   (static_cast<std::uint32_t>(d[2]) << 8) | static_cast<std::uint32_t>(d[3]);
        }

        std::vector<std::uint8_t> serialize(const WpkIdClaims& c)
        {
            std::vector<std::uint8_t> p;
            p.reserve(kClaimBytes);
            putBe32(p, c.subject);
            putBe32(p, c.expiresAt);
            p.insert(p.end(), c.taskId.begin(), c.taskId.end());
            return p;
        }

        /// HMAC-SHA256 over the domain label and the claims, truncated to kTagBytes.
        bool tagFor(const std::array<std::uint8_t, 32>& key,
                    const std::vector<std::uint8_t>& claims,
                    std::uint8_t* out)
        {
            std::vector<std::uint8_t> message;
            message.reserve(kMacLabel.size() + claims.size());
            message.insert(message.end(), kMacLabel.begin(), kMacLabel.end());
            message.insert(message.end(), claims.begin(), claims.end());

            unsigned int len {0};
            std::uint8_t full[EVP_MAX_MD_SIZE];
            if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), message.data(), message.size(), full,
                     &len) == nullptr ||
                len < kTagBytes)
            {
                return false;
            }
            std::memcpy(out, full, kTagBytes);
            return true;
        }

        /**
         * @brief `<cluster><key>` from the manager configuration.
         *
         * Scoped to the cluster block deliberately: `<https>` carries a `<key>` too, holding the
         * path to remoted's TLS private key, and a first-match parse would derive from a filename.
         */
        std::string readClusterKey(const std::string& configPath)
        {
            std::ifstream file(configPath);
            if (!file.is_open())
            {
                return {};
            }
            std::stringstream buffer;
            buffer << file.rdbuf();
            const std::string xml = buffer.str();

            const auto clusterOpen = xml.find("<cluster>");
            if (clusterOpen == std::string::npos)
            {
                return {};
            }
            const auto clusterClose = xml.find("</cluster>", clusterOpen);
            const auto keyOpen = xml.find("<key>", clusterOpen);
            if (keyOpen == std::string::npos || (clusterClose != std::string::npos && keyOpen > clusterClose))
            {
                return {};
            }
            const auto valueStart = keyOpen + std::strlen("<key>");
            const auto keyClose = xml.find("</key>", valueStart);
            if (keyClose == std::string::npos)
            {
                return {};
            }
            std::string value = xml.substr(valueStart, keyClose - valueStart);
            const auto first = value.find_first_not_of(" \t\r\n");
            const auto last = value.find_last_not_of(" \t\r\n");
            return first == std::string::npos ? std::string {} : value.substr(first, last - first + 1);
        }

        bool hkdfSha256(const std::string& secret, std::array<std::uint8_t, 32>& out)
        {
            EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
            if (kdf == nullptr)
            {
                return false;
            }
            EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
            EVP_KDF_free(kdf);
            if (ctx == nullptr)
            {
                return false;
            }

            OSSL_PARAM params[4];
            params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>("SHA256"), 0);
            params[1] =
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<char*>(secret.data()), secret.size());
            params[2] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_INFO, const_cast<char*>(kHkdfInfo.data()), kHkdfInfo.size());
            params[3] = OSSL_PARAM_construct_end();

            const bool ok = EVP_KDF_derive(ctx, out.data(), out.size(), params) == 1;
            EVP_KDF_CTX_free(ctx);
            return ok;
        }
    } // namespace

    bool looksLikeSignedId(std::string_view value)
    {
        return value.size() > kIdPrefix.size() + kIdSuffix.size() &&
               value.compare(0, kIdPrefix.size(), kIdPrefix) == 0 &&
               value.compare(value.size() - kIdSuffix.size(), kIdSuffix.size(), kIdSuffix) == 0;
    }

    std::string taskIdToString(const std::array<std::uint8_t, 16>& raw)
    {
        char buffer[37];
        std::snprintf(buffer,
                      sizeof(buffer),
                      "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                      raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                      raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]);
        return std::string {buffer};
    }

    bool WpkIdKey::Fingerprint::operator==(const Fingerprint& o) const noexcept
    {
        return present == o.present && dev == o.dev && ino == o.ino && size == o.size && mtimeSec == o.mtimeSec &&
               mtimeNsec == o.mtimeNsec;
    }

    WpkIdKey::WpkIdKey(std::string configPath, int recheckIntervalSeconds)
        : m_configPath {std::move(configPath)}
        , m_recheckIntervalSeconds {recheckIntervalSeconds}
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        refreshLocked();
    }

    void WpkIdKey::refreshLocked() const
    {
        const auto nowSec =
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch())
                .count();
        if (m_everChecked && m_recheckIntervalSeconds > 0 && nowSec - m_lastCheckMonotonicSec < m_recheckIntervalSeconds)
        {
            return;
        }
        m_lastCheckMonotonicSec = nowSec;
        m_everChecked = true;

        Fingerprint current;
        struct stat info
        {
        };
        if (::stat(m_configPath.c_str(), &info) == 0)
        {
            current.present = true;
            current.dev = static_cast<std::uint64_t>(info.st_dev);
            current.ino = static_cast<std::uint64_t>(info.st_ino);
            current.size = static_cast<std::uint64_t>(info.st_size);
            current.mtimeSec = static_cast<std::int64_t>(info.st_mtim.tv_sec);
            current.mtimeNsec = static_cast<std::int64_t>(info.st_mtim.tv_nsec);
        }
        if (current == m_fingerprint)
        {
            return;
        }

        m_fingerprint = current;
        m_usable = false;
        m_key.fill(0);

        const std::string clusterKey = readClusterKey(m_configPath);
        if (clusterKey.empty() || clusterKey == kRefusedClusterKey)
        {
            return;
        }
        m_usable = hkdfSha256(clusterKey, m_key);
    }

    bool WpkIdKey::usable() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        refreshLocked();
        return m_usable;
    }

    std::string WpkIdKey::sign(const WpkIdClaims& claims) const
    {
        std::array<std::uint8_t, 32> key {};
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            refreshLocked();
            if (!m_usable)
            {
                return {};
            }
            key = m_key;
        }

        const std::vector<std::uint8_t> body = serialize(claims);
        std::uint8_t tag[kTagBytes];
        if (!tagFor(key, body, tag))
        {
            return {};
        }

        std::vector<std::uint8_t> blob;
        blob.reserve(kClaimBytes + kTagBytes);
        blob.insert(blob.end(), body.begin(), body.end());
        blob.insert(blob.end(), tag, tag + kTagBytes);

        return std::string {kIdPrefix} + b64UrlEncode(blob.data(), blob.size()) + std::string {kIdSuffix};
    }

    bool WpkIdKey::verify(std::string_view value,
                          std::uint32_t authenticatedAgent,
                          std::uint64_t now,
                          WpkIdClaims& out) const
    {
        if (!looksLikeSignedId(value))
        {
            return false;
        }

        std::array<std::uint8_t, 32> key {};
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            refreshLocked();
            if (!m_usable)
            {
                return false;
            }
            key = m_key;
        }

        std::vector<std::uint8_t> blob;
        if (!b64UrlDecode(value.substr(kIdPrefix.size(), value.size() - kIdPrefix.size() - kIdSuffix.size()), blob) ||
            blob.size() != kClaimBytes + kTagBytes)
        {
            return false;
        }

        const std::vector<std::uint8_t> body(blob.begin(), blob.begin() + kClaimBytes);
        std::uint8_t expected[kTagBytes];
        if (!tagFor(key, body, expected))
        {
            return false;
        }
        // Constant-time: never leak how much of a tag matched.
        if (CRYPTO_memcmp(expected, blob.data() + kClaimBytes, kTagBytes) != 0)
        {
            return false;
        }

        out.subject = readBe32(body.data());
        out.expiresAt = readBe32(body.data() + 4);
        std::memcpy(out.taskId.data(), body.data() + 8, out.taskId.size());

        // The authenticated identity wins, never the value the client supplied.
        return out.subject == authenticatedAgent && now < static_cast<std::uint64_t>(out.expiresAt);
    }

    const WpkIdKey& wpkIdKey()
    {
        static const WpkIdKey instance {WpkIdKey::kDefaultConfigPath};
        return instance;
    }

} // namespace remoted::auth
