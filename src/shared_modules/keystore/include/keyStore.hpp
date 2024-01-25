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

#ifndef _KEYSTORE_H
#define _KEYSTORE_H

#include <string>

#include "rocksDBWrapper.hpp"
// #include "rsaHelper.hpp" // INCLUDE WHEN IT'S READY

constexpr auto DATABASE_PATH {"queue/keystore"};

class Keystore
{
public:
    /**
     * Insert or update a key-value pair in the specified column family.
     *
     * @param columnFamily The target column family.
     * @param key The key to be inserted or updated.
     * @param value The corresponding value.
     */
    void put(const std::string& columnFamily, const std::string& key, const std::string& value);

    /**
     * Get the key value in the specified column family.
     *
     * @param columnFamily The target column family.
     * @param key The key to be inserted or updated.
     * @param value The corresponding value to be returned.
     */
    void get(const std::string& columnFamily, const std::string& key, rocksdb::PinnableSlice& value);
};

#endif // _KEYSTORE_H
