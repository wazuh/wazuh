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

#include "keyStore.hpp"
#include "loggerHelper.h"
#include "rsaHelper.hpp"

constexpr auto KS_NAME {"keystore"};

void Keystore::put(const std::string& columnFamily, const std::string& key, const std::string& value)
{
    std::string encryptedValue;

    // Encrypt value
    Utils::rsaEncrypt(CERTIFICATE_FILE, value, encryptedValue, true);

    // Insert to DB
    Utils::RocksDBWrapper keystoreDB = Utils::RocksDBWrapper(DATABASE_PATH, false);

    if (!keystoreDB.columnExists(columnFamily))
    {
        keystoreDB.createColumn(columnFamily);
    }

    keystoreDB.put(key, rocksdb::Slice(encryptedValue), columnFamily);
}

void Keystore::get(const std::string& columnFamily, const std::string& key, std::string& value)
{
    std::string encryptedValue;

    // Get from DB
    Utils::RocksDBWrapper keystoreDB = Utils::RocksDBWrapper(DATABASE_PATH, false);

    if (!keystoreDB.columnExists(columnFamily))
    {
        keystoreDB.createColumn(columnFamily);
    }

    if (keystoreDB.get(key, encryptedValue, columnFamily))
    {
        // Decrypt value
        Utils::rsaDecrypt(PRIVATE_KEY_FILE, encryptedValue, value);
    }
}
