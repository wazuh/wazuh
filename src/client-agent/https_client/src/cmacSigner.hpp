/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_CMAC_SIGNER_HPP
#define _HC_CMAC_SIGNER_HPP

#include "keyProvider.hpp"

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

/// The two auth headers of one signed attempt (#37732):
///   protocol-version: 1
///   Authorization: Wazuh <agent-id>:<unix-ts>:<mac>
struct SignedHeaders
{
    std::string protocolVersion;
    std::string authorization;
};

/// Signs one attempt. The 300 s timestamp window means callers must sign
/// every retry freshly; RetrySender enforces that.
class ISigner
{
    public:
        virtual ~ISigner() = default;

        virtual std::optional<SignedHeaders> sign(const std::string& method, const std::string& target,
                                                  const uint8_t* body, size_t bodyLength,
                                                  std::time_t timestamp) const = 0;

        /// File-backed bodies (spooled /stateful sessions): the MAC is computed
        /// incrementally over the file so peak memory stays flat.
        virtual std::optional<SignedHeaders> signFile(const std::string& method,
                                                      const std::string& target,
                                                      const std::string& bodyFilePath,
                                                      std::time_t timestamp) const = 0;
};

/// AES-CMAC over the canonical request via OpenSSL 3 EVP_MAC (the vendored
/// crypto; no new dependency).
class CmacSigner final : public ISigner
{
    public:
        CmacSigner(std::string agentId, const IKeyProvider& keyProvider);

        std::optional<SignedHeaders> sign(const std::string& method, const std::string& target,
                                          const uint8_t* body, size_t bodyLength,
                                          std::time_t timestamp) const override;

        std::optional<SignedHeaders> signFile(const std::string& method, const std::string& target,
                                              const std::string& bodyFilePath,
                                              std::time_t timestamp) const override;

        /// AES-CMAC(key, message) as 32 lowercase hex chars. Exposed so tests can
        /// pin the RFC 4493 vectors directly.
        static std::optional<std::string> macHex(const std::vector<uint8_t>& key,
                                                 const uint8_t* message, size_t messageLength);

    private:
        SignedHeaders makeHeaders(std::time_t timestamp, const std::string& macHexDigest) const;

        std::string m_agentId;
        const IKeyProvider& m_keyProvider;
};

#endif // _HC_CMAC_SIGNER_HPP
