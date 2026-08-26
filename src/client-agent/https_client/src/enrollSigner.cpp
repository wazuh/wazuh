/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "enrollSigner.hpp"
#include "canonicalRequest.hpp"
#include "cmacPrimitive.hpp"

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <memory>

namespace
{
    using KdfPtr = std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)>;
    using KdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)>;

    constexpr size_t DERIVED_KEY_BYTES = 32; // AES-256-CBC-CMAC key length (#38438).
    constexpr size_t SHA256_DIGEST_BYTES = 32;

    // The literal info bytes from the #38438 contract: the ASCII string
    // "WAZUH-ENROLL-CMAC-KEY" followed by one 0x01 byte. This 0x01 is part of
    // `info` itself, not a description of HKDF-Expand's own block counter --
    // the algorithm still appends its own counter byte on top of this as
    // usual. Verified against the contract's own known-answer vector (password
    // "MyEnrollmentSecret123" derives to
    // 2ea29504f294bce5039bdb4fb78747dec59866204dc2588dc59f3b8cd5875a9e); see
    // enrollSigner_test.cpp.
    std::vector<uint8_t> hkdfInfo()
    {
        static const std::string literal = "WAZUH-ENROLL-CMAC-KEY";
        std::vector<uint8_t> info(literal.begin(), literal.end());
        info.push_back(0x01);
        return info;
    }
} // namespace

std::optional<std::vector<uint8_t>> EnrollSigner::deriveKey(const std::string& password)
{
    const KdfPtr kdf {EVP_KDF_fetch(nullptr, "HKDF", nullptr), EVP_KDF_free};

    if (!kdf)
    {
        return std::nullopt; // LCOV_EXCL_LINE: vendored provider always has HKDF.
    }

    KdfCtxPtr context {EVP_KDF_CTX_new(kdf.get()), EVP_KDF_CTX_free};

    if (!context)
    {
        return std::nullopt; // LCOV_EXCL_LINE: allocation failure only.
    }

    // RFC 5869: an omitted salt defaults to HashLen zero bytes; made explicit
    // here instead of relying on the provider's own defaulting for an absent
    // parameter.
    const std::vector<uint8_t> salt(SHA256_DIGEST_BYTES, 0);
    const std::vector<uint8_t> info = hkdfInfo();
    char digestName[] = "SHA256";

    const OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digestName, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<char*>(password.data()), password.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<uint8_t*>(salt.data()), salt.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<uint8_t*>(info.data()), info.size()),
        OSSL_PARAM_construct_end()};

    std::vector<uint8_t> derived(DERIVED_KEY_BYTES);

    if (EVP_KDF_derive(context.get(), derived.data(), derived.size(), params) != 1)
    {
        return std::nullopt;
    }

    return derived;
}

std::optional<EnrollSignedHeaders> EnrollSigner::sign(const std::string& password,
                                                      const std::string& method,
                                                      const std::string& target,
                                                      const uint8_t* body,
                                                      size_t bodyLength,
                                                      std::time_t timestamp)
{
    const auto key = deriveKey(password);

    if (!key)
    {
        return std::nullopt; // LCOV_EXCL_LINE: HKDF cannot fail for a non-empty password.
    }

    const auto canonical = buildEnrollCanonicalRequest(method, target, timestamp, body, bodyLength);
    const auto digest = cmacHex(*key, canonical.data(), canonical.size());

    if (!digest)
    {
        return std::nullopt; // LCOV_EXCL_LINE: CMAC cannot fail for a validated 32-byte key.
    }

    EnrollSignedHeaders headers;
    headers.protocolVersion = "protocol-version: 1";
    headers.authorization = "Authorization: WazuhEnroll " + std::to_string(timestamp) + ":" + *digest;
    return headers;
}
