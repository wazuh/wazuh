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
#include <algorithm>
#include <filesystem>
#include <memory>
#include <rocksdb/db.h>
#include <stdexcept>
#include <string>
#include <vector>

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
            std::vector<rocksdb::ColumnFamilyDescriptor> columnsDescriptors;
            const std::filesystem::path databasePath {dbPath};

            // Create directories recursively if they do not exist
            std::filesystem::create_directories(databasePath);

            // Get a list of the existing columns descriptors.
            const auto DB_FILE {databasePath / "CURRENT"};
            if (std::filesystem::exists(DB_FILE))
            {
                // Read columns names.
                std::vector<std::string> columnsNames;
                const auto listStatus {rocksdb::DB::ListColumnFamilies(options, dbPath, &columnsNames)};
                if (!listStatus.ok())
                {
                    throw std::runtime_error("Failed to list columns: " + std::string {listStatus.getState()});
                }

                // Create a set of column descriptors. This includes the default column.
                for (auto& columnName : columnsNames)
                {
                    columnsDescriptors.push_back(
                        rocksdb::ColumnFamilyDescriptor(std::move(columnName), rocksdb::ColumnFamilyOptions()));
                }
            }
            else
            {
                // Database doesn't exist: Set just the default column descriptor.
                columnsDescriptors.push_back(
                    rocksdb::ColumnFamilyDescriptor(rocksdb::kDefaultColumnFamilyName, rocksdb::ColumnFamilyOptions()));
            }

            // Open database with a list of columns descriptors.
            const auto status {rocksdb::DB::Open(options, dbPath, columnsDescriptors, &m_columnsHandles, &dbRawPtr)};
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
         * @brief Class destructor. Frees column family handles.
         *
         */
        ~RocksDBWrapper()
        {
            std::for_each(m_columnsHandles.begin(),
                          m_columnsHandles.end(),
                          [this](rocksdb::ColumnFamilyHandle* handle)
                          {
                              // Default column should not be freed.
                              if (rocksdb::kDefaultColumnFamilyName != handle->GetName())
                              {
                                  const auto status {m_db->DestroyColumnFamilyHandle(handle)};
                                  if (!status.ok())
                                  {
                                      throw std::runtime_error {"Failed to free RocksDB column family: " +
                                                                std::string {status.getState()}};
                                  }
                              }
                          });
        }

        /**
         * @brief Creates a new column family in the database.
         *
         * @note The column handle created is also added to the handles list to be then accessible by other methods.
         *
         * @param columnName Name of the new column.
         */
        void createColumn(const std::string& columnName)
        {
            if (columnName.empty())
            {
                throw std::invalid_argument {"Column name is empty"};
            }

            rocksdb::ColumnFamilyHandle* pColumnFamily;
            const auto status {m_db->CreateColumnFamily(rocksdb::ColumnFamilyOptions(), columnName, &pColumnFamily)};
            if (!status.ok())
            {
                throw std::runtime_error {"Couldn't create column family: " + std::string {status.getState()}};
            }

            m_columnsHandles.push_back(pColumnFamily);
        }

        /**
         * @brief Checks whether a column exists in the database or not.
         *
         * @param columnName Name of the column.
         * @return true If the column exists.
         * @return false If the column doesn't exists.
         */
        bool columnExists(const std::string& columnName) const
        {
            if (columnName.empty())
            {
                throw std::invalid_argument {"Column name is empty"};
            }

            const auto columnMatch {[&columnName](const rocksdb::ColumnFamilyHandle* handle)
                                    {
                                        return columnName == handle->GetName();
                                    }};

            return std::find_if(m_columnsHandles.begin(), m_columnsHandles.end(), columnMatch) !=
                   m_columnsHandles.end();
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
         * @param columnName Column name where the put will be performed. If empty, the default column will be used.
         *
         * @note If the key already exists, the value will be overwritten.
         */
        void put(const std::string& key, const rocksdb::Slice& value, const std::string& columnName = "")
        {
            if (key.empty())
            {
                throw std::invalid_argument("Key is empty");
            }

            const auto status {m_db->Put(rocksdb::WriteOptions(), getColumnFamilyHandle(columnName), key, value)};
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
         * @param columnName Column name from where to get. If empty, the default column will be used.
         *
         * @return bool True if the operation was successful.
         * @return bool False if the key was not found.
         *
         */
        bool get(const std::string& key, std::string& value, const std::string& columnName = "")
        {
            if (key.empty())
            {
                throw std::invalid_argument("Key is empty");
            }

            const auto status {m_db->Get(rocksdb::ReadOptions(), getColumnFamilyHandle(columnName), key, &value)};
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
         * @param columnName Column name from where to get. If empty, the default column will be used.
         *
         * @return std::pair<std::string, rocksdb::Slice> Last key-value pair.
         *
         * @note The first element of the pair is the key, the second element is the value.
         */
        std::pair<std::string, rocksdb::Slice> getLastKeyValue(const std::string& columnName = "")
        {
            std::unique_ptr<rocksdb::Iterator> it(
                m_db->NewIterator(rocksdb::ReadOptions(), getColumnFamilyHandle(columnName)));

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
         * and improve its performance by eliminating unnecessary data. This function
         * is similar to compactDatabase() but, first enable the option of use the
         * kBZip2Compression compression type.
         *
         * @note This function uses default compact range options.
         *
         * @see rocksdb::CompactRangeOptions
         */
        void compactDatabaseUsingBzip2()
        {
            auto status = m_db->SetOptions({{"compression", "kBZip2Compression"}});
            if (!status.ok())
            {
                throw std::runtime_error("Failed to set 'kBZip2Compression' option");
            }

            // Create compact range options with kForceOptimized settings
            rocksdb::CompactRangeOptions compactOptions;
            compactOptions.bottommost_level_compaction = rocksdb::BottommostLevelCompaction::kForceOptimized;

            // Perform compaction for the entire key range
            m_db->CompactRange(compactOptions, nullptr, nullptr);
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
        std::vector<rocksdb::ColumnFamilyHandle*> m_columnsHandles {}; ///< List of column handles.

        /**
         * @brief Returns the column family handle identified by its name.
         *
         * @param columnName Name of the column family. If empty, the default handle is returned.
         * @return rocksdb::ColumnFamilyHandle* Column family handle pointer.
         */
        rocksdb::ColumnFamilyHandle* getColumnFamilyHandle(const std::string& columnName)
        {
            if (columnName.empty())
            {
                return m_db->DefaultColumnFamily();
            }

            const auto columnMatch {[&columnName](const rocksdb::ColumnFamilyHandle* handle)
                                    {
                                        return columnName == handle->GetName();
                                    }};

            if (const auto it {std::find_if(m_columnsHandles.begin(), m_columnsHandles.end(), columnMatch)};
                it != m_columnsHandles.end())
            {
                return *it;
            }

            throw std::runtime_error {"Couldn't find column family: '" + columnName + "'"};
        }
    };
} // namespace Utils

#endif // _ROCKS_DB_WRAPPER_HPP
