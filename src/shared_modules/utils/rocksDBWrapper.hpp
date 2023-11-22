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

#include "rocksDBIterator.hpp"
#include <filesystem>
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
        explicit RocksDBWrapper(const std::string& dbPath, bool useBzipCompress = false)
        {
            rocksdb::Options options;
            options.create_if_missing = true;
            if (useBzipCompress)
            {
                options.compression = rocksdb::kBZip2Compression;
            }
            rocksdb::DB* dbRawPtr;

            // Create directories recursively if they do not exist
            std::filesystem::create_directories(std::filesystem::path(dbPath));

            const auto status {rocksdb::DB::Open(options, dbPath, &dbRawPtr)};
            if (!status.ok())
            {
                throw std::runtime_error("Failed to open RocksDB database. Reason: " + std::string {status.getState()});
            }
            // Assigns the raw pointer to the unique_ptr. When db goes out of scope, it will automatically delete the
            // allocated RocksDB instance.
            m_db.reset(dbRawPtr);
        }

        /**
         * @brief Move constructor.
         *
         * @param other Other instance.
         */
        RocksDBWrapper(RocksDBWrapper&& other) noexcept
            : m_db {std::move(other.m_db)}
        {
        }

        /**
         * @brief Move assignment operator.
         *
         * @param other Other instance.
         * @return RocksDBWrapper&
         */
        RocksDBWrapper& operator=(RocksDBWrapper&& other) noexcept
        {
            if (this != &other)
            {
                m_db = std::move(other.m_db);
            }
            return *this;
        }

        /**
         * @brief Put a key-value pair in the database.
         * @param key Key to put.
         * @param value Value to put.
         * @note If the key already exists, the value will be overwritten.
         */
        void put(const std::string& key, const rocksdb::Slice& value)
        {
            if (key.empty())
            {
                throw std::invalid_argument("Key is empty");
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
         * @param value Value to get (std::string).
         *
         * @return bool True if the operation was successful.
         * @return bool False if the key was not found.
         *
         */
        bool get(const std::string& key, std::string& value)
        {
            if (key.empty())
            {
                throw std::invalid_argument("Key is empty");
            }

            const auto status {m_db->Get(rocksdb::ReadOptions(), key, &value)};
            if (status.IsNotFound())
            {
                return false;
            }
            else if (!status.ok())
            {
                throw std::runtime_error("Error getting data: " + status.ToString());
            }
            return true;
        }

        /**
         * @brief Get a value from the database.
         *
         * @param key Key to get.
         * @param value Value to get (rocksdb::PinnableSlice).
         *
         * @return bool True if the operation was successful.
         * @return bool False if the key was not found.
         */

        bool get(const std::string& key, rocksdb::PinnableSlice& value)
        {
            if (key.empty())
            {
                throw std::invalid_argument("Key is empty");
            }

            const auto status {m_db->Get(rocksdb::ReadOptions(), m_db->DefaultColumnFamily(), key, &value)};
            if (status.IsNotFound())
            {
                return false;
            }
            else if (!status.ok())
            {
                throw std::runtime_error("Error getting data: " + status.ToString());
            }
            return true;
        }

        /**
         * @brief Delete a key-value pair from the database.
         *
         * @param key Key to delete.
         */
        void delete_(const std::string& key) // NOLINT
        {
            if (key.empty())
            {
                throw std::invalid_argument("Key is empty");
            }

            const auto status {m_db->Delete(rocksdb::WriteOptions(), key)};
            if (!status.ok())
            {
                throw std::runtime_error("Error deleting data: " + status.ToString());
            }
        }

        /**
         * @brief Get the last key-value pair from the database.
         *
         * @return std::pair<std::string, rocksdb::Slice> Last key-value pair.
         *
         * @note The first element of the pair is the key, the second element is the value.
         */
        std::pair<std::string, rocksdb::Slice> getLastKeyValue()
        {
            std::unique_ptr<rocksdb::Iterator> it(m_db->NewIterator(rocksdb::ReadOptions()));

            it->SeekToLast();
            if (it->Valid())
            {
                return {it->key().ToString(), it->value()};
            }

            throw std::runtime_error {"Error getting last key-value pair"};
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
         * @brief Seek to specific key.
         * @param key Key to seek.
         * @return RocksDBIterator Iterator to the database.
         */
        RocksDBIterator seek(std::string_view key)
        {
            return {std::shared_ptr<rocksdb::Iterator>(m_db->NewIterator(rocksdb::ReadOptions())), key};
        }

        /**
         * @brief Get an iterator to the database.
         * @return RocksDBIterator Iterator to the database.
         */
        RocksDBIterator begin()
        {
            return RocksDBIterator {std::shared_ptr<rocksdb::Iterator>(m_db->NewIterator(rocksdb::ReadOptions()))};
        }

        /**
         * @brief Get an iterator to the end of the database.
         * @return const RocksDBIterator Iterator to the end of the database.
         */
        const RocksDBIterator& end()
        {
            static const RocksDBIterator END_ITERATOR;
            return END_ITERATOR;
        }

        /**
         * @brief Compacts the key range in the RocksDB database.
         *
         * This function triggers compaction for the entire key range in the RocksDB
         * database. Compaction helps to reduce the storage space used by the database
         * and improve its performance by eliminating unnecessary data.
         *
         * @note This function uses default compact range options.
         *
         * @see rocksdb::CompactRangeOptions
         */
        void compactDatabase()
        {
            // Create compact range options with default settings
            rocksdb::CompactRangeOptions compactOptions;

            // Perform compaction for the entire key range
            m_db->CompactRange(compactOptions, nullptr, nullptr);
        }

    private:
        std::unique_ptr<rocksdb::DB> m_db {};
    };
} // namespace Utils

#endif // _ROCKS_DB_WRAPPER_HPP
