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

#include <vector>

namespace Utils{void rsaEncrypt(const std::string& key, std::vector<char>& input, std::vector<char>& output){
    for(auto& inputs : input){
        output.push_back(inputs + 5);
    }
};} //MOCK FUNCTION DELETE WHEN IT'S READY


void Keystore::put(const std::string& columnFamily, const std::string& key, const std::string& value)
{
    //Convert to vector
    std::vector<char> valueVector(value.begin(), value.end());

    std::vector<char> encryptedValueVector;

    // Get key from file
    std::string keyCert;
    
    std::ifstream keyFile(KEYFILE);
    if (!keyFile.is_open())
    {
        // throw std::runtime_error("Could not open key file: " + std::string(KEYFILE));    // UNCOMMENT LATER
        keyCert = "KEY";   // DELETE LATER
    }
    else
    {
        std::string line;
        while ( std::getline (keyFile,line) )
        {
            keyCert.append(line);
        }
        keyFile.close();
    }


    // Encrypt value
    Utils::rsaEncrypt(keyCert, valueVector, encryptedValueVector);

    // Convert to string/Slice
    std::string encryptedValue(encryptedValueVector.begin(), encryptedValueVector.end());

    // Insert to DB
    Utils::RocksDBWrapper keystoreDB = Utils::RocksDBWrapper(DATABASE_PATH, false);

    if (!keystoreDB.columnExists(columnFamily)) {
        keystoreDB.createColumn(columnFamily);
    }

    keystoreDB.put(key, rocksdb::Slice(encryptedValue), columnFamily);

    // std::cout << "Original: " << value << std::endl << "Encrypted: " << encryptedValue << std::endl; //MOCK, MUST DELETE

}

void Keystore::get(const std::string& columnFamily, const std::string& key, rocksdb::PinnableSlice& value)
{
}
