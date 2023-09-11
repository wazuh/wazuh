/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * September 9, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROCKS_DB_WRAPPER_HPP
#define _ROCKS_DB_WRAPPER_HPP

#include <iostream>
#include <rocksdb/db.h>
#include <string>

namespace Utils
{
    /**
     * @brief Wrapper class for RocksDB.
     *
     */
    class RocksDBWrapper
    {
    public:
        explicit RocksDBWrapper(const std::string& dbPath)
        {
            rocksdb::Options options;
            options.create_if_missing = true;
            rocksdb::DB* dbRawPtr;
            const auto status {rocksdb::DB::Open(options, dbPath, &dbRawPtr)};
            if (!status.ok())
            {
                throw std::runtime_error("Failed to open RocksDB database");
            }
            // Assigns the raw pointer to the unique_ptr. When db goes out of scope, it will automatically delete the
            // allocated RocksDB instance.
            m_db.reset(dbRawPtr);
        }

        /**
         * @brief Put a key-value pair in the database.
         *
         * @param key Key to put.
         * @param value Value to put.
         *
         * @note If the key already exists, the value will be overwritten.
         */
        void put(const std::string& key, const std::string& value)
        {
            if (key.empty() || value.empty())
            {
                throw std::invalid_argument("Key or value is empty");
            }

            const auto status {m_db->Put(rocksdb::WriteOptions(), key, value)};
            if (!status.ok())
            {
                throw std::runtime_error("Error putting data: " + status.ToString());
            }
        }

        /**
         * @brief Get a value from the database.
         *
         * @param key Key to get.
         * @param value Value to get
         */
        void get(const std::string& key, std::string& value)
        {
            const auto status {m_db->Get(rocksdb::ReadOptions(), key, &value)};
            if (status.IsNotFound())
            {
                throw std::invalid_argument("Key not found: " + key);
            }
            else if (!status.ok())
            {
                throw std::runtime_error("Error getting data: " + status.ToString());
            }
        }

        /**
         * @brief Delete a key-value pair from the database.
         *
         * @param key Key to delete.
         */
        void delete_(const std::string& key) // NOLINT
        {
            const auto status {m_db->Delete(rocksdb::WriteOptions(), key)};
            if (!status.ok())
            {
                throw std::runtime_error("Error deleting data: " + status.ToString());
            }
        }

        /**
         * @brief Get the last key-value pair from the database.
         *
         * @return std::pair<std::string, std::string> Last key-value pair.
         */
        std::pair<std::string, std::string> getLastKeyValue()
        {
            std::string lastKey {};
            std::string lastValue {};
            std::unique_ptr<rocksdb::Iterator> it(m_db->NewIterator(rocksdb::ReadOptions()));
            for (it->SeekToLast(); it->Valid(); it->Prev())
            {
                lastKey = it->key().ToString();
                lastValue = it->value().ToString();
                break;
            }
            return {lastKey, lastValue};
        }

        /**
         * @brief Delete all key-value pairs from the database.
         */
        void deleteAll()
        {
            rocksdb::WriteBatch batch;
            std::unique_ptr<rocksdb::Iterator> it(m_db->NewIterator(rocksdb::ReadOptions()));
            for (it->SeekToFirst(); it->Valid(); it->Next())
            {
                batch.Delete(it->key());
            }
            const auto status {m_db->Write(rocksdb::WriteOptions(), &batch)};
            if (!status.ok())
            {
                throw std::runtime_error("Error deleting data: " + status.ToString());
            }
        }

        /**
         * @brief Get an iterator pointing to the key-value pair with the given key.
         *
         * @return std::unique_ptr<rocksdb::Iterator> Iterator pointing to the key-value pair with the given key.
         */
        std::unique_ptr<rocksdb::Iterator> seek(const std::string& key)
        {
            rocksdb::ReadOptions read_options;
            std::unique_ptr<rocksdb::Iterator> it(m_db->NewIterator(read_options));
            it->Seek(key);

            if (it->Valid() && it->key().ToString() == key)
            {
                return it;
            }
            throw std::invalid_argument("Key not found: " + key);
        }

    private:
        std::unique_ptr<rocksdb::DB> m_db {};
    };
} // namespace Utils

#endif // _ROCKS_DB_WRAPPER_HPP
