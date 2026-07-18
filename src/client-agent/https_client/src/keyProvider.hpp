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
 * The exact key-derivation recipe is an open point of the #37732 contract
 * (raw client.keys value vs the legacy MD5 mix vs a dedicated derived key).
 * This class is the single place that decision lands: today the material is
 * taken as the key itself in hex; when the recipe is settled only this
 * implementation changes.
 */
class ConfigKeyProvider final : public IKeyProvider
{
    public:
        explicit ConfigKeyProvider(std::string keyHex);
        std::optional<std::vector<uint8_t>> cmacKey() const override;

    private:
        std::string m_keyHex;
};

#endif // _HC_KEY_PROVIDER_HPP
