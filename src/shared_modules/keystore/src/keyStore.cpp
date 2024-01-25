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

#include <array>

void Keystore::put(const std::string& columnFamily, const std::string& key, const std::string& value)
{
    // Convert to array
    std::array<unsigned char,128> valueArray;
    int i = 0;
    for(auto& chars : value){
        valueArray[i] = chars;
        i++;
    }
    valueArray[i] = '\0';

    std::array<unsigned char,256> encryptedValueArray;

    // Get key from file
    std::string keyString;
    
    std::ifstream keyFile(CERTIFICATE_FILE);
    if (!keyFile.is_open())
    {
        throw std::runtime_error("Could not open key file: " + std::string(CERTIFICATE_FILE));
    }
    else
    {
        std::string line;
        while ( std::getline (keyFile,line) )
        {
            keyString.append(line);
        }
        keyFile.close();
    }


    // // Encrypt value
    int result = Utils::rsaEncrypt(keyString, valueArray, encryptedValueArray);

    // Convert to string/Slice
    std::string encryptedValue(encryptedValueArray.begin(), encryptedValueArray.end());

    // Insert to DB
    Utils::RocksDBWrapper keystoreDB = Utils::RocksDBWrapper(DATABASE_PATH, false);

    if (!keystoreDB.columnExists(columnFamily)) {
        keystoreDB.createColumn(columnFamily);
    }

    keystoreDB.put(key, rocksdb::Slice(encryptedValue), columnFamily);

    // std::cout << "Original: " << value << std::endl << "Encrypted: " << encryptedValue << std::endl; // DEBUG MUST DELETE

}

void Keystore::get(const std::string& columnFamily, const std::string& key, rocksdb::PinnableSlice& value)
{
}
