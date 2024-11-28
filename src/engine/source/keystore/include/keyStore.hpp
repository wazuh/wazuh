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

// Database constants, based on the keystore path.
constexpr auto KEYSTORE_PATH {"/var/lib/wazuh-server/keystore"};

class Keystore final
{

public:
    Keystore() = default;

    /**
     * Insert or update a key-value pair in the specified column family.
     *
     * @param columnFamily The target column family.
     * @param key The key to be inserted or updated.
     * @param value The corresponding value.
     * @param databasePath The path to the database file.
     */
    static void put(const std::string& columnFamily,
                    const std::string& key,
                    const std::string& value,
                    const std::string& databasePath = KEYSTORE_PATH);

    /**
     * Get the key value in the specified column family.
     *
     * @param columnFamily The target column family.
     * @param key The key to be inserted or updated.
     * @param value The corresponding value to be returned.
     * @param databasePath The path to the database file.
     */
    static void get(const std::string& columnFamily,
                    const std::string& key,
                    std::string& value,
                    const std::string& databasePath = KEYSTORE_PATH);
};

#endif // _KEYSTORE_HPP
