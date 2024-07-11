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

#include "evpHelper.hpp"
#include "loggerHelper.h"
#include "rocksDBWrapper.hpp"
#include "rsaHelper.hpp"

constexpr auto DATABASE_PATH {"queue/keystore"};
constexpr auto PRIVATE_KEY_FILE {"etc/keystore.key"};
constexpr auto CERTIFICATE_FILE {"etc/keystore.cert"};
constexpr auto KS_NAME {"keystore"};
constexpr auto KS_VERSION {"2"};
constexpr auto VERSION_FIELD {"version"};

template<typename TRSAPrimitive = RSAHelper<>, typename TEVPHelper = EVPHelper<>>
class TKeystore final
{
    static void upgrade(Utils::RocksDBWrapper& keystoreDB, const std::string& columnFamily)
    {
        std::string versionValue;
        std::string rawValue;

        if (!keystoreDB.get(VERSION_FIELD, versionValue, columnFamily))
        {
            for (const auto& [key, value] : keystoreDB.begin(columnFamily))
            {
                std::string encryptedRSAValue;
                std::vector<char> encryptedValue;
                // if the key exist, it means that the keystore needs to be upgraded.
                if (keystoreDB.get(key, encryptedRSAValue, columnFamily))
                {
                    logInfo(KS_NAME, "Upgrading keystore to version: ", KS_VERSION);
                }

                if (!std::filesystem::exists(PRIVATE_KEY_FILE))
                {
                    logWarn(KS_NAME, "No private key was found.");
                    return;
                }

                // Decrypt value
                TRSAPrimitive().rsaDecrypt(PRIVATE_KEY_FILE, encryptedRSAValue, rawValue);

                TEVPHelper().encrypt(rawValue, encryptedValue);

                keystoreDB.put(key, rocksdb::Slice(encryptedValue.data(), encryptedValue.size()), columnFamily);
            }
            keystoreDB.put(VERSION_FIELD, KS_VERSION, columnFamily);
        }
    }

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
        std::vector<char> encryptedValue;

        // Encrypt value
        TEVPHelper().encrypt(value, encryptedValue);

        // Insert to DB
        auto keystoreDB = Utils::RocksDBWrapper(DATABASE_PATH, false);

        if (!keystoreDB.columnExists(columnFamily))
        {
            keystoreDB.createColumn(columnFamily);
        }

        keystoreDB.put(key, rocksdb::Slice(encryptedValue.data(), encryptedValue.size()), columnFamily);
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
        auto keystoreDB = Utils::RocksDBWrapper(DATABASE_PATH, false);

        if (!keystoreDB.columnExists(columnFamily))
        {
            keystoreDB.createColumn(columnFamily);
        }

        upgrade(keystoreDB, columnFamily);

        if (keystoreDB.get(key, encryptedValue, columnFamily))
        {
            std::vector<char> encryptedValueVec(encryptedValue.begin(), encryptedValue.end());
            TEVPHelper().decrypt(encryptedValueVec, value);
        }
    }
};

using Keystore = TKeystore<>;

#endif // _KEYSTORE_HPP
