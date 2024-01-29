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
#include "rsaHelper.hpp"
#include "loggerHelper.h"

constexpr auto KS_NAME {"keystore"};

void Keystore::put(const std::string& columnFamily, const std::string& key, const std::string& value)
{
    std::string encryptedValue;

    try
    {
        // Encrypt value
        Utils::rsaEncrypt(CERTIFICATE_FILE, value, encryptedValue, true);

        // Insert to DB
        Utils::RocksDBWrapper keystoreDB = Utils::RocksDBWrapper(DATABASE_PATH, false);

        if (!keystoreDB.columnExists(columnFamily)) {
            keystoreDB.createColumn(columnFamily);
        }

        keystoreDB.put(key, rocksdb::Slice(encryptedValue), columnFamily);
    }
    catch (std::exception& e)
    {
        logError(KS_NAME, "%s", e.what());
        throw std::runtime_error(e.what());
    }
}

void Keystore::get(const std::string& columnFamily, const std::string& key, std::string& value)
{
    std::string encryptedValue;

    try
    {        
        // Get from DB
        Utils::RocksDBWrapper keystoreDB = Utils::RocksDBWrapper(DATABASE_PATH, false);

        if(!keystoreDB.columnExists(columnFamily)) {
            std::string msg = "Column '" + columnFamily + "' does not exists at the database.";
            logError(KS_NAME, msg.c_str());
            throw std::runtime_error(msg);
        }

        if (!keystoreDB.get(key, encryptedValue, columnFamily)) {
            std::string msg = "Could not find key '" + key + " at column '" + columnFamily + "'.";
            logError(KS_NAME, msg.c_str());
            throw std::runtime_error(msg);
        }
        else {
            logDebug2(KS_NAME, "Successfully retrieved the value from key '%s' at column '%s'.", key, columnFamily);
        }
        
        // Decrypt value
        Utils::rsaDecrypt(PRIVATE_KEY_FILE, encryptedValue, value);
    }
    catch(std::exception& e)
    {
        logError(KS_NAME, "%s", e.what());
        throw std::runtime_error(e.what());
    }
}
