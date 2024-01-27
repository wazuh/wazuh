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

    // Get from DB
    try
    {
        Utils::RocksDBWrapper keystoreDB = Utils::RocksDBWrapper(DATABASE_PATH, false);

        if(!keystoreDB.columnExists(columnFamily)) {
            char msg[100];
            sprintf(msg, "Column %d does not exists in the database.", columnFamily.c_str());
            logError(KS_NAME, msg);
            throw std::runtime_error(msg);
        }

        if (!keystoreDB.get(key, encryptedValue, columnFamily)) {
            char msg[100];
            sprintf(msg, "Could not find key '%s' in column '%s'.", key, columnFamily);
            logError(KS_NAME, msg);
            throw std::runtime_error(msg);
        }
        else {
            logDebug2(KS_NAME, "Successfully retrieved the value from key '%s' in column '%s'.", key, columnFamily);
        }
    }
    catch(std::exception& e)
    {
        logError(KS_NAME, "%s", e.what());
        throw std::runtime_error(e.what());
    }
    
    // Decrypt value
    try
    {
        int decrypted_len = Utils::rsaDecrypt(PRIVATE_KEY_FILE, encryptedValue, value);
    }
    catch (std::exception& e)
    {
        logError(KS_NAME, "%s", e.what());
        throw std::runtime_error(e.what());
    }
}
