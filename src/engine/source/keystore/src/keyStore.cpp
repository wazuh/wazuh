/*
 * Wazuh keystore
 * Copyright (C) 2015, Wazuh Inc.
 * February 1, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <map>

#include <base/logging.hpp>
#include <base/utils/evpHelper.hpp>
#include <base/utils/keyValueFile.hpp>

#include "keyStore.hpp"

constexpr auto KS_VALUE_SEPARATOR {':'};                   // Default separator for key-value pairs.
constexpr auto KS_VERSION {"1"};                           // Keystore version.
constexpr auto KS_VERSION_FIELD {"keystore-version"};      // Field name for the version.
constexpr auto KS_KEY_FIELD {"keystore-key-length"};       // Field name for the key length.
constexpr auto KS_KEY_SIZE {base::utils::CIPHER_KEY_SIZE}; // Default key length.
constexpr auto KS_IV_FIELD {"keystore-iv-length"};         // Field name for the IV length.
constexpr auto KS_IV_SIZE {base::utils::CIPHER_IV_SIZE};   // Default IV length.

std::map<std::string, std::string> METADATA_FIELDS = {{KS_VERSION_FIELD, KS_VERSION},
                                                      {KS_KEY_FIELD, std::to_string(KS_KEY_SIZE)},
                                                      {KS_IV_FIELD, std::to_string(KS_IV_SIZE)}};

static void checkKeyStoreVersion(base::utils::KeyValueFile& keyStore)
{
    auto checkFieldLambda = [&](const std::string& field, const std::string& value)
    {
        std::string keyStoreValue;
        if (!keyStore.get(field, keyStoreValue))
        {
            keyStore.put(field, value);
        }
        else
        {
            if (keyStoreValue != value)
            {
                throw std::runtime_error("Invalid keystore version or key/iv size");
            }
        }
    };

    for (const auto& [field, value] : METADATA_FIELDS)
    {
        checkFieldLambda(field, value);
    }
}

static void sanitizeKey(const std::string& key)
{
    for (const auto& [field, _] : METADATA_FIELDS)
    {
        if (key == field)
        {
            throw std::runtime_error("Cannot use reserved field name as key");
        }
    }
}

void Keystore::put(const std::string& key, const std::string& value, const std::string& keyStorePath)
{
    std::vector<char> encryptedValue;

    sanitizeKey(key);

    auto keyStore = base::utils::KeyValueFile(keyStorePath, KS_VALUE_SEPARATOR);
    checkKeyStoreVersion(keyStore);

    base::utils::EVPHelper().encryptAES256(value, encryptedValue);
    keyStore.put(key, encryptedValue);
}

/**
 * Get the key value in the specified column family.
 *
 * @param key The key to be inserted or updated.
 * @param value The corresponding value to be returned.
 * @param keyStorePath The path to the key store file.
 */
bool Keystore::get(const std::string& key, std::string& value, const std::string& keyStorePath)
{
    std::string encryptedValue;

    auto keyStore = base::utils::KeyValueFile(keyStorePath, KS_VALUE_SEPARATOR);

    checkKeyStoreVersion(keyStore);

    if (keyStore.get(key, encryptedValue))
    {
        std::vector<char> encryptedValueVec(encryptedValue.begin(), encryptedValue.end());
        base::utils::EVPHelper().decryptAES256(encryptedValueVec, value);
        return true;
    }

    return false;
}
