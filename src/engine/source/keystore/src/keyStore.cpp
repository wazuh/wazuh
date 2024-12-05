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

#include <base/logging.hpp>
#include <base/utils/evpHelper.hpp>
#include <base/utils/keyValueFile.hpp>

#include "keyStore.hpp"

constexpr auto KS_VALUE_SEPARATOR {':'}; // Default separator for key-value pairs.

/**
 * @brief Insert or update a key-value pair in the keystore.
 *
 * @param key The key to be inserted or updated.
 * @param value The value to be inserted or updated.
 * @param keyStorePath The path to the key store file.
 */
void Keystore::put(const std::string& key, const std::string& value, const std::string& keyStorePath)
{
    std::vector<char> encryptedValue;
    auto keyStore = base::utils::KeyValueFile(keyStorePath, KS_VALUE_SEPARATOR);

    base::utils::EVPHelper().encryptAES256(value, encryptedValue);
    keyStore.put(key, encryptedValue);
}

/**
 * Get the a value from the keystore.
 *
 * @param key The key to be retrieved.
 * @param value The returned value. Won't be modified if the key is not found.
 * @param keyStorePath The path to the key store file.
 */
bool Keystore::get(const std::string& key, std::string& value, const std::string& keyStorePath)
{
    std::vector<char> encryptedValueVec;

    auto keyStore = base::utils::KeyValueFile(keyStorePath, KS_VALUE_SEPARATOR);

    if (keyStore.get(key, encryptedValueVec))
    {
        base::utils::EVPHelper().decryptAES256(encryptedValueVec, value);
        return true;
    }

    return false;
}
