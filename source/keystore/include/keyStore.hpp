/*
 * Wazuh keystore
 * Copyright (C) 2015, Wazuh Inc.
 * January 24, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _KEYSTORE_HPP
#define _KEYSTORE_HPP

#include <string>

#include <base/utils/keyValue.hpp>

// Database constants, based on the keystore path.
constexpr auto KEYSTORE_PATH {"/etc/wazuh-server/client.keystore"};

class Keystore final
{
private:
    /**
     * @brief Verifies if the file exists and creates it with the right permissions.
     *
     * @param keyStorePath Path to the keystore.
     */
    static void fileCreate(const std::filesystem::path& keyStorePath);

    /**
     * @brief Reads the content from the file and decrypts it.
     *
     * @param filePath File path.
     * @return base::utils::KeyValue A key-value object.
     */
    static base::utils::KeyValue readAndDecrypt(const std::string& filePath);

public:
    Keystore() = default;

    /**
     * Insert or update a key-value pair in the keystore.
     *
     * @param key The key to be inserted or updated.
     * @param value The corresponding value.
     * @param keyStorePath The path to the database file.
     */
    static void put(const std::string& key, const std::string& value, const std::string& keyStorePath = KEYSTORE_PATH);

    /**
     * Get the value from the keystore.
     *
     * @param key The key of the value to be retrieved.
     * @param value The corresponding value to be returned.
     * @param keyStorePath The path to the database file.
     *
     * @return true If the key is found.
     * @return false If the key is not found.
     */
    static bool get(const std::string& key, std::string& value, const std::string& keyStorePath = KEYSTORE_PATH);
};

#endif // _KEYSTORE_HPP
