/*
 * Wazuh shared modules - JWT profile library
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/// @file enrollKeyDerivation.hpp
/// HKDF-SHA256 of an enrollment secret into a `wazuh-enroll+jwt` HS256 key (jwtEnrollProfileV1.hpp).
/// One construction, three `info` labels -- the domain separator that keeps the three keys unrelated
/// even when fed the same bytes:
///   deriveEnrollKey(password)        "WAZUH-ENROLL-JWT-KEY"   -- the shared key (no `kid`); manager
///                                    (PasswordKeySource) and agent (EnrollSigner) share it, so the two
///                                    can never drift. Unchanged since #38582.
///   deriveEnrollTokenKey(secret16)   "WAZUH-ENROLL-TOKEN-KEY" -- `kid` = enrollment token id (#38993)
///   deriveReenrollKey(secret32)      "WAZUH-REENROLL-KEY"     -- `kid` = canonical agent id (#38993)
/// authd replicates the token derivation in C (src/shared/src/enrollment_token.c); the frozen vectors
/// (testVectors.hpp, jwt_vectors.json) pin that both sides agree byte for byte.
/// OpenSSL 3 EVP_KDF; header-only like the rest of this library.

#pragma once

#include "jwt/jwtEnrollProfileV1.hpp"
#include "jwt/jwtProfileV1.hpp"
#include "jwt/secureBytes.hpp"

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

namespace jwt_profile::v1::enroll
{
    namespace detail
    {
        /// Longest `info` label this file uses, plus the version byte; a static_assert per label keeps
        /// the buffer honest.
        constexpr std::size_t kMaxInfoBytes = 32;
        static_assert(kHkdfInfoLabel.size() < kMaxInfoBytes);
        static_assert(kHkdfTokenInfoLabel.size() < kMaxInfoBytes);
        static_assert(kHkdfReenrollInfoLabel.size() < kMaxInfoBytes);

        /// @brief HKDF-SHA256(IKM = ikm, salt = 32 x 0x00, info = infoLabel || kHkdfInfoVersion, L = 32).
        /// nullopt for an empty IKM (a KDF over empty IKM must never yield a "valid" key) or on any
        /// provider failure (HKDF unavailable, FIPS restrictions, allocation) -- fail closed, never throws.
        inline std::optional<SecureBytes>
        deriveHkdf(const std::uint8_t* ikm, std::size_t ikmLen, std::string_view infoLabel) noexcept
        {
            if (ikm == nullptr || ikmLen == 0)
            {
                return std::nullopt;
            }

            struct KdfFree
            {
                void operator()(EVP_KDF* k) const noexcept
                {
                    EVP_KDF_free(k);
                }
            };
            struct CtxFree
            {
                void operator()(EVP_KDF_CTX* c) const noexcept
                {
                    EVP_KDF_CTX_free(c);
                }
            };
            const std::unique_ptr<EVP_KDF, KdfFree> kdf {EVP_KDF_fetch(nullptr, "HKDF", nullptr)};
            if (!kdf)
            {
                return std::nullopt;
            }
            const std::unique_ptr<EVP_KDF_CTX, CtxFree> ctx {EVP_KDF_CTX_new(kdf.get())};
            if (!ctx)
            {
                return std::nullopt;
            }

            std::array<std::uint8_t, kMaxInfoBytes> info {};
            for (std::size_t i = 0; i < infoLabel.size(); ++i)
            {
                info[i] = static_cast<std::uint8_t>(infoLabel[i]);
            }
            info[infoLabel.size()] = kHkdfInfoVersion;
            const std::size_t infoLen = infoLabel.size() + 1;
            std::array<std::uint8_t, kHkdfSaltBytes> salt {}; // all zero
            char digest[] = "SHA2-256";
            int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;

            const OSSL_PARAM params[] = {
                OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<std::uint8_t*>(ikm), ikmLen),
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt.data(), salt.size()),
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info.data(), infoLen),
                OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
                OSSL_PARAM_construct_end()};

            SecureBytes key(kKeyBytes);
            if (EVP_KDF_derive(ctx.get(), key.data(), key.size(), params) != 1)
            {
                return std::nullopt;
            }
            return key;
        }
    } // namespace detail

    /// @brief Derives the 32-byte shared key from the enrollment password. nullopt for an empty
    /// password (the callers already reject it) or on any provider failure -- fail closed, never throws.
    inline std::optional<SecureBytes> deriveEnrollKey(std::string_view password) noexcept
    {
        if (password.empty())
        {
            return std::nullopt;
        }
        return detail::deriveHkdf(
            reinterpret_cast<const std::uint8_t*>(password.data()), password.size(), kHkdfInfoLabel);
    }

    /// @brief Derives the HS256 key of an enrollment token from its 16-byte secret (the second half
    /// of the token's `key` field). Any other secret size is nullopt: the size is part of the format.
    inline std::optional<SecureBytes> deriveEnrollTokenKey(const SecureBytes& secret) noexcept
    {
        if (secret.size() != kTokenSecretBytes)
        {
            return std::nullopt;
        }
        return detail::deriveHkdf(secret.data(), secret.size(), kHkdfTokenInfoLabel);
    }

    /// @brief Derives the HS256 key an agent re-enrolls with from its 32-byte reenroll_secret.
    /// Any other secret size is nullopt.
    inline std::optional<SecureBytes> deriveReenrollKey(const SecureBytes& secret) noexcept
    {
        if (secret.size() != kReenrollSecretBytes)
        {
            return std::nullopt;
        }
        return detail::deriveHkdf(secret.data(), secret.size(), kHkdfReenrollInfoLabel);
    }
} // namespace jwt_profile::v1::enroll
