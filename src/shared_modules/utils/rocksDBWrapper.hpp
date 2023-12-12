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
#include <unordered_map>

#define ROCKSDB_DEFAULT_COLUMN rocksdb::kDefaultColumnFamilyName.c_str()

namespace Utils
{
    /**
     * @brief Wrapper class for RocksDB.
     *
     */
    class RocksDBWrapper
    {
    public:
        explicit RocksDBWrapper(const std::string& dbPath, const std::vector<std::string>& columnFamilies = {})
        {
            rocksdb::Options options;
            options.create_if_missing = true;
            options.create_missing_column_families = true;
            rocksdb::DB* dbRawPtr;

            // Create directories recursively if they do not exist
            std::filesystem::create_directories(std::filesystem::path(dbPath));

            rocksdb::Status status;

            if (columnFamilies.empty())
            {
                status = rocksdb::DB::Open(options, dbPath, &dbRawPtr);
            }
            else
            {
                m_columnFamiliesDescriptors.emplace_back(
                    rocksdb::ColumnFamilyDescriptor(rocksdb::kDefaultColumnFamilyName, rocksdb::ColumnFamilyOptions()));

                for (const auto& columnFamily : columnFamilies)
                {
                    m_columnFamiliesDescriptors.emplace_back(
                        rocksdb::ColumnFamilyDescriptor(columnFamily, rocksdb::ColumnFamilyOptions()));
                }
                status =
                    rocksdb::DB::Open(options, dbPath, m_columnFamiliesDescriptors, &m_columnFamilyHandles, &dbRawPtr);

                for (const auto& handle : m_columnFamilyHandles)
                {
                    m_columnFamiliesHandlesMap[handle->GetName()] = handle;
                }
            }

            if (!status.ok())
            {
                throw std::runtime_error("Failed to open RocksDB database");
            }
            // Assigns the raw pointer to the unique_ptr. When db goes out of scope, it will automatically delete the
            // allocated RocksDB instance.
            m_db.reset(dbRawPtr);
        }

        ~RocksDBWrapper()
        {
            for (const auto& handle : m_columnFamilyHandles)
            {
                m_db->DestroyColumnFamilyHandle(handle);
            }
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
         * @brief Put a key-value pair in the database in a specific column family.
         *
         * @param columnFamily Column family to write.
         * @param key Key to put.
         * @param value Value to put.
         */
        void put(const std::string& columnFamily, const std::string& key, const rocksdb::Slice& value)
        {
            if (key.empty() || columnFamily.empty())
            {
                throw std::invalid_argument("Key or column family is empty");
            }

            const auto status {
                m_db->Put(rocksdb::WriteOptions(), m_columnFamiliesHandlesMap.at(columnFamily), key, value)};

            if (!status.ok())
            {
                throw std::runtime_error("Error putting data: " + status.ToString());
            }
        }

        /**
         * @brief Put key-value pairs in the database in batch.
         *
         * @param keyValueVector Vector of pairs containing the key and value.
         */
        void put(const std::vector<std::pair<std::string, rocksdb::Slice>>& keyValueVector)
        {
            rocksdb::WriteBatch batch;
            for (const auto& pair : keyValueVector)
            {
                batch.Put(pair.first, pair.second);
            }

            const auto status {m_db->Write(rocksdb::WriteOptions(), &batch)};
            if (!status.ok())
            {
                throw std::runtime_error("Error executing batch put: " + status.ToString());
            }
        }

        /**
         * @brief Put key-value pairs in the database for specific column families in batch.
         *
         * @param columnKeyValueVector Vector of tuples containing the column family, key and value.
         */
        void put(const std::vector<std::tuple<std::string, std::string, rocksdb::Slice>>& columnKeyValueVector)
        {
            rocksdb::WriteBatch batch;
            for (const auto& tuple : columnKeyValueVector)
            {
                batch.Put(m_columnFamiliesHandlesMap.at(std::get<0>(tuple)), std::get<1>(tuple), std::get<2>(tuple));
            }

            const auto status {m_db->Write(rocksdb::WriteOptions(), &batch)};
            if (!status.ok())
            {
                throw std::runtime_error("Error executing batch put: " + status.ToString());
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
         * @brief Get a value from the database with a specific column family.
         *
         * @param columnFamily Column family to read.
         * @param key Key to get.
         * @param value Value to get (rocksdb::PinnableSlice).
         * @return true True if the operation was successful.
         * @return false False if the key was not found.
         */
        bool get(const std::string& columnFamily, const std::string& key, rocksdb::PinnableSlice& value)
        {
            if (key.empty() || columnFamily.empty())
            {
                throw std::invalid_argument("Key or column family is empty");
            }

            const auto status {
                m_db->Get(rocksdb::ReadOptions(), m_columnFamiliesHandlesMap.at(columnFamily), key, &value)};
            if (status.IsNotFound())
            {
                std::cerr << "Key not found: " << key << '\n';
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
         * @brief Delete a key-value pair from the database for an specific column family,
         *
         * @param key Column family to delete the value from.
         * @param key Key to delete.
         */
        void delete_(const std::string columnFamily, const std::string& key) // NOLINT
        {
            if (key.empty() || columnFamily.empty())
            {
                throw std::invalid_argument("Key or column family is empty");
            }

            const auto status {m_db->Delete(rocksdb::WriteOptions(), m_columnFamiliesHandlesMap.at(columnFamily), key)};
            if (!status.ok())
            {
                throw std::runtime_error("Error deleting data: " + status.ToString());
            }
        }

        /**
         * @brief Delete many keys from the database in batch.
         *
         * @param keys Vector of keys to delete.
         */
        void delete_(const std::vector<std::string>& keys)
        {
            rocksdb::WriteBatch batch;
            for (const auto& key : keys)
            {
                batch.Delete(key);
            }

            const auto status {m_db->Write(rocksdb::WriteOptions(), &batch)};
            if (!status.ok())
            {
                throw std::runtime_error("Error executing batch delete: " + status.ToString());
            }
        }

        /**
         * @brief Delete many keys from the database in batch for specific column families.
         *
         * @param columnKeyVector Vector of pairs containing the column family and key to delete.
         */
        void delete_(const std::vector<std::pair<std::string, std::string>>& columnKeyVector)
        {
            rocksdb::WriteBatch batch;
            for (const auto& pair : columnKeyVector)
            {
                batch.Delete(m_columnFamiliesHandlesMap.at(pair.first), pair.second);
            }

            const auto status {m_db->Write(rocksdb::WriteOptions(), &batch)};
            if (!status.ok())
            {
                throw std::runtime_error("Error executing batch delete: " + status.ToString());
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
         * @brief Seek to specific key in a specific column family.
         *
         * @param columnFamily Column family to seek.
         * @param key Key to seek.
         * @return RocksDBIterator Iterator to the database.
         */
        RocksDBIterator seek(const std::string& columnFamily, std::string_view key)
        {
            return {std::shared_ptr<rocksdb::Iterator>(
                        m_db->NewIterator(rocksdb::ReadOptions(), m_columnFamiliesHandlesMap.at(columnFamily))),
                    key};
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
         * @brief Get an iterator to the database for a column family.
         * @param columnFamily Column family to seek.
         * @return RocksDBIterator Iterator to the database.
         */
        RocksDBIterator begin(const std::string& columnFamily)
        {
            return RocksDBIterator {std::shared_ptr<rocksdb::Iterator>(m_db->NewIterator(
                                        rocksdb::ReadOptions(), m_columnFamiliesHandlesMap.at(columnFamily))),
                                    ""};
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

    private:
        std::unique_ptr<rocksdb::DB> m_db {};
        std::unordered_map<std::string, rocksdb::ColumnFamilyHandle*> m_columnFamiliesHandlesMap;
        std::vector<rocksdb::ColumnFamilyDescriptor> m_columnFamiliesDescriptors;
        std::vector<rocksdb::ColumnFamilyHandle*> m_columnFamilyHandles;
    };
} // namespace Utils

#endif // _ROCKS_DB_WRAPPER_HPP
