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

#include "loggerHelper.h"
#include "rocksDBWrapper.hpp"
#include "rsaHelper.hpp"

constexpr auto DATABASE_PATH {"queue/keystore"};
constexpr auto PRIVATE_KEY_FILE {"etc/sslmanager.key"};
constexpr auto CERTIFICATE_FILE {"etc/sslmanager.cert"};

constexpr auto KS_NAME {"keystore"};
template<typename TRSAPrimitive = RSAHelper<>>
class TKeystore final
{

public:
    TKeystore() = default;

    /**
     * Insert or update a key-value pair in the specified column family.
     *
     * @param columnFamily The target column family.
     * @param key The key to be inserted or updated.
     * @param value The corresponding value.
     */
    static void put(const std::string& columnFamily, const std::string& key, const std::string& value)
    {
        std::string encryptedValue;

        if (!std::filesystem::exists(CERTIFICATE_FILE))
        {
            logWarn(KS_NAME, "No certificate was found.");
            return;
        }
        // Encrypt value
        TRSAPrimitive().rsaEncrypt(CERTIFICATE_FILE, value, encryptedValue, true);

        // Insert to DB
        Utils::RocksDBWrapper keystoreDB = Utils::RocksDBWrapper(DATABASE_PATH, false);

        if (!keystoreDB.columnExists(columnFamily))
        {
            keystoreDB.createColumn(columnFamily);
        }

        keystoreDB.put(key, rocksdb::Slice(encryptedValue), columnFamily);
    }

    /**
     * Get the key value in the specified column family.
     *
     * @param columnFamily The target column family.
     * @param key The key to be inserted or updated.
     * @param value The corresponding value to be returned.
     */
    static void get(const std::string& columnFamily, const std::string& key, std::string& value)
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
            if (!std::filesystem::exists(PRIVATE_KEY_FILE))
            {
                logWarn(KS_NAME, "No private key was found.");
                return;
            }
            // Decrypt value
            TRSAPrimitive().rsaDecrypt(PRIVATE_KEY_FILE, encryptedValue, value);
        }
    }
};

using Keystore = TKeystore<>;

#endif // _KEYSTORE_HPP
