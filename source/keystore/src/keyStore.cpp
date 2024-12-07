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

#include "keyStore.hpp"

constexpr auto KS_VALUE_SEPARATOR {':'}; // Default separator for key-value pairs.

/**
 * @brief Verifies if the file exists and creates it with the right permissions.
 *
 * @param filePath Path to the keystore.
 */
void Keystore::fileCreate(const std::string& filePath)
{
    // Create file and update permissions only if it does not exist
    if (!std::filesystem::exists(filePath))
    {
        std::ofstream file(filePath);
        if (!file.is_open())
        {
            throw std::runtime_error("Error creating key-value file due to: " + std::string(strerror(errno)));
        }
        file.close();
        std::filesystem::permissions(filePath,
                                     std::filesystem::perms::owner_read | std::filesystem::perms::owner_write
                                         | std::filesystem::perms::group_read);
    }
}

/**
 * @brief Reads the content from the file and decrypts it.
 *
 * @param filePath File path.
 * @return base::utils::KeyValue A key-value object.
 */
base::utils::KeyValue Keystore::readAndDecrypt(const std::string& filePath)
{
    std::ifstream file(filePath, std::ifstream::binary);
    if (!file.is_open())
    {
        throw std::runtime_error("Error opening key-value file due to: " + std::string(strerror(errno)));
    }

    std::vector<char> buffer(std::istreambuf_iterator<char>(file), {});
    file.close();

    std::string decryptedKeystoreStr;
    if (!buffer.empty())
    {
        base::utils::EVPHelper().decryptAES256(buffer, decryptedKeystoreStr);
    }

    return base::utils::KeyValue(decryptedKeystoreStr, KS_VALUE_SEPARATOR);
}

/**
 * @brief Insert or update a key-value pair in the keystore.
 *
 * @param key The key to be inserted or updated.
 * @param value The value to be inserted or updated.
 * @param keyStorePath The path to the key store file.
 */
void Keystore::put(const std::string& key, const std::string& value, const std::string& keyStorePath)
{
    fileCreate(keyStorePath);
    auto keyValue = readAndDecrypt(keyStorePath);
    keyValue.put(key, value);

    std::vector<char> encryptedKeystore;
    base::utils::EVPHelper().encryptAES256(keyValue.dumpMap(), encryptedKeystore);

    std::ofstream outFile(keyStorePath, std::ios_base::trunc | std::ios_base::binary);
    if (!outFile.is_open())
    {
        throw std::runtime_error("Error opening key store file due to: " + std::string(strerror(errno)));
    }

    outFile.write(encryptedKeystore.data(), encryptedKeystore.size());
    outFile.close();
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
    fileCreate(keyStorePath);
    auto keyValue = readAndDecrypt(keyStorePath);

    return keyValue.get(key, value);
}
