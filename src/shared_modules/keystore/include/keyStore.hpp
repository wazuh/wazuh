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
#include <string_view>

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
     */
    static void put(const std::string& columnFamily, const std::string& key, const std::string& value, std::string_view logTag = "");

    /**
     * Get the key value in the specified column family.
     *
     * @param columnFamily The target column family.
     * @param key The key to be inserted or updated.
     * @param value The corresponding value to be returned.
     * @param logTag Optional parent log tag; "keystore" is appended automatically.
     */
    static void get(const std::string& columnFamily, const std::string& key, std::string& value, std::string_view logTag = "");

    /**
     * Get the key value in the specified column family.
     *
     * @param columnFamily The target column family.
     * @param key The key to be inserted or updated.
     * @param logTag Optional parent log tag; "keystore" is appended automatically.
     * @return The corresponding value to be returned.
     */
    static std::string get(const std::string& columnFamily, const std::string& key, std::string_view logTag = "");
};

#endif // _KEYSTORE_HPP
