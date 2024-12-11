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

#include <fstream>

#include <base/logging.hpp>
#include <base/utils/evpHelper.hpp>

#include "keyStore.hpp"

constexpr auto KS_VALUE_SEPARATOR {':'}; // Default separator for key-value pairs.

void Keystore::fileCreate(const std::filesystem::path& keyStorePath)
{
    // Create file and update permissions only if it does not exist
    if (!std::filesystem::exists(keyStorePath))
    {
        if (!std::filesystem::exists(keyStorePath.parent_path()))
        {
            throw std::runtime_error("The parent directory of the key store file '"
                                     + std::string(keyStorePath.filename()) + "' does not exist.");
        }

        std::ofstream file(keyStorePath.filename());
        if (!file.is_open())
        {
            throw std::runtime_error("Error creating key store file due to: " + std::string(strerror(errno)));
        }
        file.close();
        std::filesystem::permissions(keyStorePath.filename(),
                                     std::filesystem::perms::owner_read | std::filesystem::perms::owner_write
                                         | std::filesystem::perms::group_read);
    }
}

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
        if (buffer.size() <= (base::utils::CIPHER_KEY_SIZE + base::utils::CIPHER_IV_SIZE))
        {
            throw std::runtime_error("Invalid key store file encryption.");
        }
        base::utils::EVPHelper().decryptAES256(buffer, decryptedKeystoreStr);
    }

    return base::utils::KeyValue(decryptedKeystoreStr, KS_VALUE_SEPARATOR);
}

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

bool Keystore::get(const std::string& key, std::string& value, const std::string& keyStorePath)
{
    fileCreate(keyStorePath);
    auto keyValue = readAndDecrypt(keyStorePath);

    return keyValue.get(key, value);
}
