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
/// HKDF-SHA256 of the enrollment password into the `wazuh-enroll+jwt` HS256 key (jwtEnrollProfileV1.hpp).
/// The one construction manager (PasswordKeySource) and agent (EnrollSigner) share, so the two can
/// never drift. OpenSSL 3 EVP_KDF; header-only like the rest of this library.

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
    /// @brief Derives the 32-byte key. nullopt for an empty password (the callers already reject
    /// it, but a KDF over empty IKM must never yield a "valid" key here) or on any provider
    /// failure (HKDF unavailable, FIPS restrictions, allocation) -- fail closed, never throws.
    inline std::optional<SecureBytes> deriveEnrollKey(std::string_view password) noexcept
    {
        if (password.empty())
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

        std::array<std::uint8_t, kHkdfInfoLabel.size() + 1> info {};
        for (std::size_t i = 0; i < kHkdfInfoLabel.size(); ++i)
        {
            info[i] = static_cast<std::uint8_t>(kHkdfInfoLabel[i]);
        }
        info[kHkdfInfoLabel.size()] = kHkdfInfoVersion;
        std::array<std::uint8_t, kHkdfSaltBytes> salt {}; // all zero
        char digest[] = "SHA2-256";
        int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;

        const OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<char*>(password.data()), password.size()),
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt.data(), salt.size()),
            OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info.data(), info.size()),
            OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
            OSSL_PARAM_construct_end()};

        SecureBytes key(kKeyBytes);
        if (EVP_KDF_derive(ctx.get(), key.data(), key.size(), params) != 1)
        {
            return std::nullopt;
        }
        return key;
    }
} // namespace jwt_profile::v1::enroll
