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

#ifndef _HC_KEY_PROVIDER_HPP
#define _HC_KEY_PROVIDER_HPP

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

/// Source of the HS256 key the `wazuh-agent+jwt` bearer is signed with.
class IKeyProvider
{
    public:
        virtual ~IKeyProvider() = default;
        /// The 32-byte key, or nullopt when the material is unusable.
        virtual std::optional<std::vector<uint8_t>> signingKey() const = 0;
};

/**
 * @brief Decodes the signing key from the configured credential material.
 *
 * The recipe (the manager's keystore applies the same one): the client.keys
 * secret is exactly 64 lowercase hex chars, decoded verbatim into the 32 key
 * bytes -- never hashed, never used as ASCII. Anything else is unusable and
 * the agent must re-enroll. The key is swappable at runtime (setKey) after a
 * re-enrollment, so signingKey() is guarded; ISigner stays const-reference.
 */
class ConfigKeyProvider final : public IKeyProvider
{
    public:
        explicit ConfigKeyProvider(std::string keyHex);
        std::optional<std::vector<uint8_t>> signingKey() const override;

        /// Replaces the key when the given hex is a valid 64-hex secret.
        /// Returns false (keeping the previous key) otherwise.
        bool setKey(const std::string& keyHex);

    private:
        mutable std::mutex m_mutex;
        std::string m_keyHex;
};

#endif // _HC_KEY_PROVIDER_HPP
