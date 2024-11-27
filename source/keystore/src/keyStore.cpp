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

#include <base/logging.hpp>
#include <base/utils/evpHelper.hpp>
#include <base/utils/rocksDBWrapper.hpp>
#include <base/utils/rsaHelper.hpp>

#include "keyStore.hpp"

// Database constants, based on the keystore path.
constexpr auto DATABASE_PATH {"/var/lib/wazuh-server/keystore"};

// KS_VERSION is the current version of the keystore. Used to identify the version of the keystore in the database.
// KS_VERSION_FIELD is the field used to store the version of the keystore in the database.
constexpr auto KS_VERSION {"1"};
constexpr auto KS_VERSION_FIELD {"version"};

static void upgrade(utils::rocksdb::RocksDBWrapper& keystoreDB, const std::string& columnFamily)
{
    std::string versionValue;

    // If the version field does not exist, it means that the keystore has not been upgraded yet.
    if (!keystoreDB.get(KS_VERSION_FIELD, versionValue, columnFamily))
    {
        try
        {
            // Upgrade all keys
            for (const auto& [key, value] : keystoreDB.begin(columnFamily))
            {
            }
        }
        catch (const std::exception& exception)
        {
            // If the upgrade fails, delete all keys and log the error.
            keystoreDB.deleteAll(columnFamily);
            LOG_WARNING("Keystore upgrade failed, re-run the tool again for all keys to save them. Error: {}",
                        exception.what());
        }
    }

    // If the version is different from the current version, update it.
    // If the upgrade fails, the version is set to the current version, because all keys have been deleted.
    // If the upgrade is successful, the version is set to the current version, because versionValue is empty.
    // If the version is the same, do nothing.
    if (versionValue != KS_VERSION)
    {
        keystoreDB.put(KS_VERSION_FIELD, KS_VERSION, columnFamily);
    }
}

void Keystore::put(const std::string& columnFamily, const std::string& key, const std::string& value)
{
    std::vector<char> encryptedValue;

    EVPHelper().encryptAES256(value, encryptedValue);

    auto keystoreDB = utils::rocksdb::RocksDBWrapper(DATABASE_PATH, false);

    if (!keystoreDB.columnExists(columnFamily))
    {
        keystoreDB.createColumn(columnFamily);
    }
    // Upgrade the keystore if necessary and insert the key-value pair, to get all keys encrypted with the same
    // algorithm. If the version field does not exist, it means that the keystore has not been upgraded yet. If the
    // version is different from the current version, update it. If the upgrade fails, the version is set to the current
    // version, because all keys have been deleted.
    upgrade(keystoreDB, columnFamily);

    // Insert the key-value pair using AES encryption.
    keystoreDB.put(key, rocksdb::Slice(encryptedValue.data(), encryptedValue.size()), columnFamily);
}

/**
 * Get the key value in the specified column family.
 *
 * @param columnFamily The target column family.
 * @param key The key to be inserted or updated.
 * @param value The corresponding value to be returned.
 */
void Keystore::get(const std::string& columnFamily, const std::string& key, std::string& value)
{
    std::string encryptedValue;

    auto keystoreDB = utils::rocksdb::RocksDBWrapper(DATABASE_PATH, false);

    if (!keystoreDB.columnExists(columnFamily))
    {
        keystoreDB.createColumn(columnFamily);
    }

    // Upgrade the keystore if necessary and get the key-value pair, to get all keys encrypted with the same algorithm.
    upgrade(keystoreDB, columnFamily);

    // Get the key-value pair using AES decryption.
    if (keystoreDB.get(key, encryptedValue, columnFamily))
    {
        std::vector<char> encryptedValueVec(encryptedValue.begin(), encryptedValue.end());
        EVPHelper().decryptAES256(encryptedValueVec, value);
    }
}
