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

/// Source of the AES-CMAC signing key.
class IKeyProvider
{
    public:
        virtual ~IKeyProvider() = default;
        /// The 16-byte AES-128 key, or nullopt when the material is unusable.
        virtual std::optional<std::vector<uint8_t>> cmacKey() const = 0;
};

/**
 * @brief Derives the CMAC key from the configured credential material.
 *
 * The recipe (settled by the manager's resolver): the client.keys hex is
 * decoded verbatim, cipher chosen by byte length (16/24/32 -> AES-128/192/
 * 256). The key is swappable at runtime (setKey) after a re-enrollment, so
 * cmacKey() is guarded; the ISigner interface stays const-reference.
 */
class ConfigKeyProvider final : public IKeyProvider
{
    public:
        explicit ConfigKeyProvider(std::string keyHex);
        std::optional<std::vector<uint8_t>> cmacKey() const override;

        /// Replaces the key when the given hex decodes to a valid AES length.
        /// Returns false (keeping the previous key) otherwise.
        bool setKey(const std::string& keyHex);

    private:
        mutable std::mutex m_mutex;
        std::string m_keyHex;
};

#endif // _HC_KEY_PROVIDER_HPP
