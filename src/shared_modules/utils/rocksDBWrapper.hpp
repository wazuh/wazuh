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
#include "stringHelper.h"
#include <algorithm>
#include <filesystem>
#include <memory>
#include <rocksdb/db.h>
#include <rocksdb/utilities/transaction.h>
#include <rocksdb/utilities/transaction_db.h>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace Utils
{
    class RocksDBTransaction;
    class IRocksDBWrapper
    {
    public:
        virtual void put(const std::string& key, const rocksdb::Slice& value, const std::string& columnName) = 0;
        virtual void put(const std::string& key, const rocksdb::Slice& value) = 0;
        virtual void delete_(const std::string& key, const std::string& columnName) = 0; // NOLINT
        virtual void delete_(const std::string& key) = 0;                                // NOLINT
        virtual void commit() = 0;
        virtual bool get(const std::string& key, rocksdb::PinnableSlice& value, const std::string& columnName) = 0;
        virtual bool get(const std::string& key, rocksdb::PinnableSlice& value) = 0;
        virtual void createColumn(const std::string& columnName) = 0;
        virtual bool columnExists(const std::string& columnName) const = 0;
        virtual void deleteAll() = 0;
        virtual void flush() = 0;
        virtual std::vector<std::string> getAllColumns() = 0;
        virtual RocksDBIterator seek(std::string_view key, const std::string& columnName = "") = 0; // NOLINT

        virtual ~IRocksDBWrapper() = default;
    };

    /**
     * @brief Wrapper class for RocksDB.
     *
     */
    class RocksDBWrapper : public IRocksDBWrapper
    {
        /**
         * @brief Initializes the RocksDB instance.
         */
        void initialize()
        {
            rocksdb::Options options;
            options.create_if_missing = true;
            options.keep_log_file_num = 1;
            options.info_log_level = rocksdb::InfoLogLevel::FATAL_LEVEL;
            options.max_open_files = 200;

            rocksdb::TransactionDB* dbRawPtr;
            std::vector<rocksdb::ColumnFamilyDescriptor> columnsDescriptors;
            const std::filesystem::path databasePath {m_path};

            // Create directories recursively if they do not exist
            std::filesystem::create_directories(databasePath);

            // Get a list of the existing columns descriptors.
            const auto databaseFile {databasePath / "CURRENT"};
            if (std::filesystem::exists(databaseFile))
            {
                // Read columns names.
                std::vector<std::string> columnsNames;
                const auto listStatus {rocksdb::TransactionDB::ListColumnFamilies(options, m_path, &columnsNames)};
                if (!listStatus.ok())
                {
                    throw std::runtime_error("Failed to list columns: " + std::string {listStatus.getState()});
                }

                // Create a set of column descriptors. This includes the default column.
                for (auto& columnName : columnsNames)
                {
                    columnsDescriptors.emplace_back(columnName, rocksdb::ColumnFamilyOptions());
                }
            }
            else
            {
                // Database doesn't exist: Set just the default column descriptor.
                columnsDescriptors.emplace_back(rocksdb::kDefaultColumnFamilyName, rocksdb::ColumnFamilyOptions());
            }

            // Open database with a list of columns descriptors.
            const auto status {rocksdb::TransactionDB::Open(
                options, rocksdb::TransactionDBOptions(), m_path, columnsDescriptors, &m_columnsHandles, &dbRawPtr)};
            if (!status.ok())
            {
                throw std::runtime_error("Failed to open RocksDB database. Reason: " + std::string {status.getState()});
            }
            // Assigns the raw pointer to the unique_ptr. When db goes out of scope, it will automatically delete the
            // allocated RocksDB instance.
            m_db.reset(dbRawPtr);
        }

        /**
         * @brief Frees column family handles.
         */
        void destroyColumnFamilyHandles()
        {
            std::for_each(m_columnsHandles.begin(),
                          m_columnsHandles.end(),
                          [this](rocksdb::ColumnFamilyHandle* handle)
                          {
                              const auto status {m_db->DestroyColumnFamilyHandle(handle)};
                              if (!status.ok())
                              {
                                  std::cerr
                                      << "Failed to free RocksDB column family: " + std::string {status.getState()}
                                      << std::endl;
                              }
                          });
        }

    public:
        explicit RocksDBWrapper(std::string dbPath, const bool enableWal = true)
            : m_enableWal {enableWal}
            , m_path {std::move(dbPath)}
        {
            initialize();
        }

        /**
         * @brief Reopen the database.
         */
        void reopen()
        {
            destroyColumnFamilyHandles();
            m_db.reset();
            initialize();
        }

        /**
         * @brief Class destructor. Frees column family handles.
         *
         * @note The documentation of the lib clearly states that we should not free the default column family handler
         * but not freeing it ends up on memory leaks and ASAN errors. OTOH, no problems seem to appear freeing it.
         *
         */
        ~RocksDBWrapper() override
        {
            destroyColumnFamilyHandles();
        };

        /**
         * @brief Put a key-value pair in the database.
         * @param key Key to put.
         * @param value Value to put.
         * @param columnName Column name where the put will be performed. If empty, the default column will be used.
         *
         * @note If the key already exists, the value will be overwritten.
         */
        void put(const std::string& key, const rocksdb::Slice& value, const std::string& columnName) override
        {
            if (key.empty())
            {
                throw std::invalid_argument("Key is empty");
            }

            rocksdb::WriteOptions writeOptions;
            writeOptions.disableWAL = !m_enableWal;

            const auto status {m_db->Put(writeOptions, getColumnFamilyHandle(columnName), key, value)};
            if (!status.ok())
            {
                throw std::runtime_error("Error putting data: " + status.ToString());
            }
        }

        /**
         * @brief Put a key-value pair in the database.
         * @param key Key to put.
         * @param value Value to put.
         *
         * @note If the key already exists, the value will be overwritten.
         */
        void put(const std::string& key, const rocksdb::Slice& value) override
        {
            put(key, value, "");
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
         * @param columnName Column name from where to get. If empty, the default column will be used.
         *
         * @return bool True if the operation was successful.
         * @return bool False if the key was not found.
         */

        bool get(const std::string& key, rocksdb::PinnableSlice& value, const std::string& columnName) override
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

        bool get(const std::string& key, rocksdb::PinnableSlice& value) override
        {
            return get(key, value, "");
        }

        /**
         * @brief Delete a key-value pair from the database.
         *
         * @param key Key to delete.
         * @param columnName Column name from where to delete. If empty, the default column will be used.
         */
        void delete_(const std::string& key, const std::string& columnName) override // NOLINT
        {
            if (key.empty())
            {
                throw std::invalid_argument("Key is empty");
            }

            rocksdb::WriteOptions writeOptions;
            writeOptions.disableWAL = !m_enableWal;

            const auto status {m_db->Delete(writeOptions, getColumnFamilyHandle(columnName), key)};
            if (!status.ok())
            {
                throw std::runtime_error("Error deleting data: " + status.ToString());
            }
        }

        /**
         * @brief Delete a key-value pair from the database.
         *
         * @param key Key to delete.
         */
        void delete_(const std::string& key) override // NOLINT
        {
            delete_(key, "");
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
         * @brief Seek to specific key.
         * @param key Key to seek.
         * @return RocksDBIterator Iterator to the database.
         */
        RocksDBIterator seek(std::string_view key, const std::string& columnName = "") override // NOLINT
        {
            return {std::shared_ptr<rocksdb::Iterator>(
                        m_db->NewIterator(rocksdb::ReadOptions(), getColumnFamilyHandle(columnName))),
                    key};
        }

        /**
         * @brief Get an iterator to the database.
         * @return RocksDBIterator Iterator to the database.
         */
        RocksDBIterator begin(const std::string& columnName = "")
        {
            RocksDBIterator rocksDBIterator(std::shared_ptr<rocksdb::Iterator>(m_db->NewIterator(
                                                rocksdb::ReadOptions(), getColumnFamilyHandle(columnName))),
                                            "");
            rocksDBIterator.begin();
            return rocksDBIterator;
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

        /**
         * @brief Initialize transaction.
         * @return RocksDBTransaction Transaction object.
         */
        std::unique_ptr<RocksDBTransaction> createTransaction()
        {
            return std::make_unique<RocksDBTransaction>(this);
        }

        void commit() override
        {
            throw std::runtime_error("Not implemented");
        }

        /**
         * @brief Creates a new column family in the database.
         *
         * @note The column handle created is also added to the handles list to be then accessible by other methods.
         *
         * @param columnName Name of the new column.
         */
        void createColumn(const std::string& columnName) override
        {
            if (columnName.empty())
            {
                throw std::invalid_argument {"Column name is empty"};
            }

            rocksdb::ColumnFamilyHandle* pColumnFamily;
            rocksdb::ColumnFamilyOptions columnFamilyOptions;
            const auto status {m_db->CreateColumnFamily(columnFamilyOptions, columnName, &pColumnFamily)};
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
        bool columnExists(const std::string& columnName) const override
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
         * @brief Get all the column family names of the DB.
         *
         * @return std::vector<std::string>
         */
        std::vector<std::string> getAllColumns() override
        {
            std::vector<std::string> columnsNames;
            rocksdb::Options options;
            const auto listStatus {rocksdb::TransactionDB::ListColumnFamilies(options, m_path, &columnsNames)};
            if (!listStatus.ok())
            {
                throw std::runtime_error("Failed to list columns: " + std::string {listStatus.getState()});
            }
            return columnsNames;
        }

        /**
         * @brief Delete all key-value pairs from the database.
         */
        void deleteAll() override
        {
            auto it = m_columnsHandles.begin();
            std::vector<std::string> columnsNames;

            while (it != m_columnsHandles.end())
            {
                if ((*it)->GetName() != rocksdb::kDefaultColumnFamilyName)
                {
                    auto status = m_db->DropColumnFamily(*it);
                    if (!status.ok())
                    {
                        throw std::runtime_error("Error deleting data: " + status.ToString());
                    }
                    columnsNames.push_back((*it)->GetName());

                    status = m_db->DestroyColumnFamilyHandle(*it);
                    if (!status.ok())
                    {
                        std::cerr << "Failed to free RocksDB column family: " + std::string {status.getState()}
                                  << std::endl;
                    }

                    it = m_columnsHandles.erase(it);
                }
                else
                {
                    rocksdb::WriteBatch batch;
                    std::unique_ptr<rocksdb::Iterator> itDefault(m_db->NewIterator(rocksdb::ReadOptions(), *it));
                    for (itDefault->SeekToFirst(); itDefault->Valid(); itDefault->Next())
                    {
                        batch.Delete(*it, itDefault->key());
                    }

                    auto status = m_db->Write(rocksdb::WriteOptions(), &batch);
                    if (!status.ok())
                    {
                        throw std::runtime_error("Error deleting data: " + status.ToString());
                    }

                    ++it;
                }
            }

            for (const auto& columnName : columnsNames)
            {
                createColumn(columnName);
            }
        }

        /**
         * @brief Delete all key-value pairs from specified column.
         * @param column The column to delete from.
         */
        void deleteAll(const std::string& columnName)
        {
            // Delete all data from the specified column
            const auto columnHandle = getColumnFamilyHandle(columnName);
            if (columnHandle->GetName() != rocksdb::kDefaultColumnFamilyName)
            {
                auto status = m_db->DropColumnFamily(columnHandle);
                if (!status.ok())
                {
                    throw std::runtime_error("Error deleting data: " + status.ToString());
                }

                status = m_db->DestroyColumnFamilyHandle(columnHandle);
                if (!status.ok())
                {
                    std::cerr << "Failed to free RocksDB column family: " + std::string {status.getState()}
                              << std::endl;
                }

                m_columnsHandles.erase(std::remove(m_columnsHandles.begin(), m_columnsHandles.end(), columnHandle),
                                       m_columnsHandles.end());
                createColumn(columnName);
            }
            else
            {
                rocksdb::WriteBatch batch;
                std::unique_ptr<rocksdb::Iterator> itDefault(m_db->NewIterator(rocksdb::ReadOptions(), columnHandle));
                for (itDefault->SeekToFirst(); itDefault->Valid(); itDefault->Next())
                {
                    batch.Delete(columnHandle, itDefault->key());
                }

                auto status = m_db->Write(rocksdb::WriteOptions(), &batch);
                if (!status.ok())
                {
                    throw std::runtime_error("Error deleting data: " + status.ToString());
                }
            }
        }

        /**
         * @brief Delete all key-value pairs from the database.
         *
         * This method deletes all key-value pairs stored in the database. It iterates through all family columns
         * and uses a provided callback function to handle each deleted key. After deletion, it commits the changes
         * to the database.
         *
         * @param callback A callback function that takes a string reference representing the deleted key.
         *
         * @throws std::runtime_error if an error occurs during data deletion.
         */
        void deleteAll(const std::function<void(std::string&, std::string&)>& callback)
        {
            // Delete data from all family columns
            for (const auto& columnHandle : m_columnsHandles)
            {
                // Create an iterator for the current column family
                std::unique_ptr<rocksdb::Iterator> it(m_db->NewIterator(rocksdb::ReadOptions(), columnHandle));

                // Iterate through all key-value pairs in the column
                for (it->SeekToFirst(); it->Valid(); it->Next())
                {
                    auto keyStr = std::string(it->key().data(), it->key().size());
                    auto valueStr = it->value().ToString();

                    callback(keyStr, valueStr);

                    auto status = m_db->Delete(rocksdb::WriteOptions(), columnHandle, it->key());

                    if (!status.ok())
                    {
                        throw std::runtime_error("Error deleting data: " + status.ToString());
                    }
                }
            }
        }

        /**
         * @brief Delete all key-value pairs from the database.
         *
         * This method deletes all key-value pairs stored in the database for a specific column family.
         * Uses a provided callback function to handle each deleted key. After deletion, it commits the changes
         * to the database.
         *
         * @param callback A callback function that takes a string reference representing the deleted key.
         * @param columnName The column name to delete from.
         *
         * @throws std::runtime_error if an error occurs during data deletion.
         */
        void deleteAll(const std::function<void(std::string&, std::string&)>& callback, const std::string& columnName)
        {
            // Get the column family handle
            const auto columnHandle = getColumnFamilyHandle(columnName);

            // Create an iterator for the current column family
            std::unique_ptr<rocksdb::Iterator> it(m_db->NewIterator(rocksdb::ReadOptions(), columnHandle));

            for (it->SeekToFirst(); it->Valid(); it->Next())
            {
                auto keyStr = std::string(it->key().data(), it->key().size());
                auto valueStr = it->value().ToString();

                callback(keyStr, valueStr);

                auto status = m_db->Delete(rocksdb::WriteOptions(), columnHandle, it->key());

                if (!status.ok())
                {
                    throw std::runtime_error("Error deleting data: " + status.ToString());
                }
            }
        }

        /**
         * @brief Flushes the transaction.
         */
        void flush() override
        {
            const auto status {m_db->Flush(rocksdb::FlushOptions(), m_columnsHandles)};
            if (!status.ok())
            {
                throw std::runtime_error {"Failed to flush transaction: " + std::string {status.getState()}};
            }
        }

    private:
        std::unique_ptr<rocksdb::TransactionDB> m_db;               ///< RocksDB instance.
        std::vector<rocksdb::ColumnFamilyHandle*> m_columnsHandles; ///< List of column family handles.
        const bool m_enableWal;                                     ///< Whether to enable WAL or not.
        const std::string m_path;                                   ///< Location of the DB.

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
        friend class RocksDBTransaction;
    };

    /**
     * @brief Wrapper class for RocksDB transactions.
     *
     */
    class RocksDBTransaction final : public IRocksDBWrapper
    {
    public:
        /**
         * @brief Constructor.
         *
         * @param db RocksDB instance.
         */
        explicit RocksDBTransaction(RocksDBWrapper* dbWrapper)
            : m_dbWrapper {dbWrapper}
        {
            if (!m_dbWrapper)
            {
                throw std::runtime_error {"RocksDB instance is null"};
            }

            rocksdb::WriteOptions writeOptions;
            writeOptions.disableWAL = true;

            m_txn = std::unique_ptr<rocksdb::Transaction>(m_dbWrapper->m_db->BeginTransaction(writeOptions));
            if (!m_txn)
            {
                throw std::runtime_error {"Failed to begin transaction"};
            }
        }

        /**
         * @brief Destructor.
         * @note If the transaction has not been committed, it will be aborted.
         */
        ~RocksDBTransaction() override
        {
            if (!m_committed)
            {
                m_txn->Rollback();
            }
        }

        /**
         * @brief Put a key-value pair in the database.
         * @param key Key to put.
         * @param value Value to put.
         * @param columnName Column name where the put will be performed. If empty, the default column will be used.
         *
         * @note If the key already exists, the value will be overwritten.
         */
        void put(const std::string& key, const rocksdb::Slice& value, const std::string& columnName) override
        {
            const auto status {m_txn->Put(m_dbWrapper->getColumnFamilyHandle(columnName), key, value)};
            if (!status.ok())
            {
                throw std::runtime_error {"Failed to put key: " + std::string {status.getState()}};
            }
        }

        /**
         * @brief Put a key-value pair in the database.
         * @param key Key to put.
         * @param value Value to put.
         *
         * @note If the key already exists, the value will be overwritten.
         */
        void put(const std::string& key, const rocksdb::Slice& value) override
        {
            put(key, value, "");
        }

        /**
         * @brief Delete a key-value pair from the database.
         *
         * @param key Key to delete.
         * @param columnName Column name from where to delete. If empty, the default column will be used.
         */
        void delete_(const std::string& key, const std::string& columnName) override
        {
            const auto status {m_txn->Delete(m_dbWrapper->getColumnFamilyHandle(columnName), key)};
            if (!status.ok())
            {
                throw std::runtime_error {"Failed to delete key: " + std::string {status.getState()}};
            }
        }

        /**
         * @brief Delete a key-value pair from the database.
         *
         * @param key Key to delete.
         * @param columnName Column name from where to delete. If empty, the default column will be used.
         */
        void delete_(const std::string& key) override
        {
            delete_(key, "");
        }

        /**
         * @brief Get a value from the database.
         *
         * @param key Key to get.
         * @param value Value to get (rocksdb::PinnableSlice).
         * @param columnName Column name from where to get. If empty, the default column will be used.
         *
         * @return bool True if the operation was successful.
         * @return bool False if the key was not found.
         */

        bool get(const std::string& key, rocksdb::PinnableSlice& value, const std::string& columnName) override
        {
            if (key.empty())
            {
                throw std::invalid_argument("Key is empty");
            }

            const auto status {
                m_txn->Get(rocksdb::ReadOptions(), m_dbWrapper->getColumnFamilyHandle(columnName), key, &value)};
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

        bool get(const std::string& key, rocksdb::PinnableSlice& value) override
        {
            return get(key, value, "");
        }

        /**
         * @brief Commit the transaction.
         */
        void commit() override
        {
            const auto status {m_txn->Commit()};
            if (!status.ok())
            {
                throw std::runtime_error {"Failed to commit transaction: " + std::string {status.getState()}};
            }

            const auto statusFlush {m_dbWrapper->m_db->Flush(rocksdb::FlushOptions(), m_dbWrapper->m_columnsHandles)};
            if (!statusFlush.ok())
            {
                throw std::runtime_error {"Failed to flush transaction: " + std::string {statusFlush.getState()}};
            }

            m_committed = true;
        }

        /**
         * @brief Delete all key-value pairs from the database.
         */
        void deleteAll() override
        {
            m_dbWrapper->deleteAll();
        }

        /**
         * @brief Creates a new column family in the database.
         *
         * @note The column handle created is also added to the handles list to be then accessible by other methods.
         *
         * @param columnName Name of the new column.
         */
        void createColumn(const std::string& columnName) override
        {
            m_dbWrapper->createColumn(columnName);
        }

        /**
         * @brief Checks whether a column exists in the database or not.
         *
         * @param columnName Name of the column.
         * @return true If the column exists.
         * @return false If the column doesn't exists.
         */
        bool columnExists(const std::string& columnName) const override
        {
            return m_dbWrapper->columnExists(columnName);
        }

        /**
         * @brief Retrieves all the column families from the DB.
         *
         * @return std::vector<std::string> Vector of strings with all the column names.
         */
        std::vector<std::string> getAllColumns() override
        {
            return m_dbWrapper->getAllColumns();
        }

        /**
         * @brief Seek to specific key
         *
         * @param key Key to seek.
         * @param columnName Column family name.
         * @return RocksDBIterator  RocksDBIterator Iterator to the database.
         */
        RocksDBIterator seek(std::string_view key, const std::string& columnName = "") override // NOLINT
        {
            return m_dbWrapper->seek(key, columnName);
        }

        /**
         * @brief Flushes the transaction.
         */
        void flush() override
        {
            // This is only permited for atomic operations.
            throw std::runtime_error("Not implemented");
        }

    private:
        RocksDBWrapper* m_dbWrapper;                 ///< RocksDB instance.
        std::unique_ptr<rocksdb::Transaction> m_txn; ///< RocksDB transaction.
        bool m_committed {false};                    ///< Whether the transaction has been committed or not.
    };
} // namespace Utils

#endif // _ROCKS_DB_WRAPPER_HPP
