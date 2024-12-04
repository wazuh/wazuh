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

constexpr auto KS_VALUE_SEPARATOR {':'};                   // Default separator for key-value pairs.

void Keystore::put(const std::string& key, const std::string& value, const std::string& keyStorePath)
{
    std::vector<char> encryptedValue;
    auto keyStore = base::utils::KeyValueFile(keyStorePath, KS_VALUE_SEPARATOR);

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

    if (keyStore.get(key, encryptedValue))
    {
        std::vector<char> encryptedValueVec(encryptedValue.begin(), encryptedValue.end());
        base::utils::EVPHelper().decryptAES256(encryptedValueVec, value);
        return true;
    }

    return false;
}
