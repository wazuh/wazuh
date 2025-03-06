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

#include "loggerHelper.h"
#include "rocksDBColumnFamily.hpp"
#include "rocksDBIterator.hpp"
#include "rocksDBOptions.hpp"
#include <algorithm>
#include <filesystem>
#include <memory>
#include <rocksdb/db.h>
#include <rocksdb/filter_policy.h>
#include <rocksdb/table.h>
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
    template<typename T = rocksdb::DB>
    class TRocksDBWrapper : public IRocksDBWrapper
    {

    public:
        /**
         * @brief Constructor.
         *
         * @param dbPath Path to the RocksDB database.
         * @param enableWal Whether to enable WAL or not.
         * @param repairIfCorrupt Whether to repair the database if it is found corrupt while opening.
         *                        WARNING: this process might not recover all data.
         */
        explicit TRocksDBWrapper(std::string dbPath, const bool enableWal = true, const bool repairIfCorrupt = true)
            : m_enableWal {enableWal}
            , m_path {std::move(dbPath)}
        {
            m_readCache = rocksdb::NewLRUCache(16 * 1024 * 1024);
            m_writeManager = std::make_shared<rocksdb::WriteBufferManager>(128 * 1024 * 1024);

            rocksdb::Options options = RocksDBOptions::buildDBOptions(m_writeManager, m_readCache);
            rocksdb::ColumnFamilyOptions columnFamilyOptions = RocksDBOptions::buildColumnFamilyOptions(m_readCache);

            T* dbRawPtr;
            std::vector<rocksdb::ColumnFamilyDescriptor> columnsDescriptors;
            const std::filesystem::path databasePath {m_path};

            // Create directories recursively if they do not exist
            std::filesystem::create_directories(databasePath);

            // Get a list of the existing columns descriptors.
            if (const auto databaseFile {databasePath / "CURRENT"}; std::filesystem::exists(databaseFile))
            {
                // Read columns names.
                std::vector<std::string> columnsNames;
                if (auto listStatus {T::ListColumnFamilies(options, m_path, &columnsNames)}; !listStatus.ok())
                {
                    if (!repairIfCorrupt)
                    {
                        throw std::runtime_error("Failed to list columns, '" + m_path +
                                                 "' won't be repaired: " + std::string {listStatus.getState()});
                    }
                    repairDB(listStatus);
                    listStatus = T::ListColumnFamilies(options, m_path, &columnsNames);
                    if (!listStatus.ok())
                    {
                        throw std::runtime_error("Failed to list columns after repair: " +
                                                 std::string {listStatus.getState()});
                    }
                }

                // Create a set of column descriptors. This includes the default column.
                for (auto& columnName : columnsNames)
                {
                    columnsDescriptors.emplace_back(columnName, columnFamilyOptions);
                }
            }
            else
            {
                // Database doesn't exist: Set just the default column descriptor.
                columnsDescriptors.emplace_back(rocksdb::kDefaultColumnFamilyName, columnFamilyOptions);
            }

            // Create a vector of column handles.
            // This vector will be used to store the column handles created by the Open method and based on the
            // columnsDescriptors.
            std::vector<rocksdb::ColumnFamilyHandle*> columnHandles;
            columnHandles.reserve(columnsDescriptors.size());

            // Open database with a list of columns descriptors.
            // Compare if T is a rocksdb::DB or rocksdb::TransactionDB.
            if constexpr (std::is_same_v<T, rocksdb::DB>)
            {
                if (auto status {T::Open(options, m_path, columnsDescriptors, &columnHandles, &dbRawPtr)}; !status.ok())
                {
                    if (!repairIfCorrupt)
                    {
                        throw std::runtime_error("Failed to open RocksDB, '" + m_path +
                                                 "' won't be repaired: " + std::string {status.getState()});
                    }

                    repairDB(status);
                    status = T::Open(options, m_path, columnsDescriptors, &columnHandles, &dbRawPtr);
                    if (!status.ok())
                    {
                        throw std::runtime_error("Failed to open RocksDB database after repair. Reason: " +
                                                 std::string {status.getState()});
                    }
                }
            }
            else
            {
                if (auto status {T::Open(options,
                                         rocksdb::TransactionDBOptions(),
                                         m_path,
                                         columnsDescriptors,
                                         &columnHandles,
                                         &dbRawPtr)};
                    !status.ok())
                {
                    repairDB(status);
                    status = T::Open(options,
                                     rocksdb::TransactionDBOptions(),
                                     m_path,
                                     columnsDescriptors,
                                     &columnHandles,
                                     &dbRawPtr);
                    if (!status.ok())
                    {
                        throw std::runtime_error("Failed to open Transaction RocksDB database after repair. Reason: " +
                                                 std::string {status.getState()});
                    }
                }
            }
            // Assigns the raw pointer to the unique_ptr. When db goes out of scope, it will automatically delete
            // the allocated RocksDB instance.
            m_db.reset(dbRawPtr);

            // Create a RAII wrapper for each column handle.
            for (const auto& handle : columnHandles)
            {
                m_columnsInstances.emplace_back(m_db, handle);
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
            if (key.empty())
            {
                throw std::invalid_argument("Key is empty");
            }

            rocksdb::WriteOptions writeOptions;
            writeOptions.disableWAL = !m_enableWal;

            if (const auto status {
                    m_db->Put(writeOptions, getColumnFamilyBasedOnName(columnName).handle(), key, value)};
                !status.ok())
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

            if (const auto status {
                    m_db->Get(rocksdb::ReadOptions(), getColumnFamilyBasedOnName(columnName).handle(), key, &value)};
                status.IsNotFound())
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

            if (const auto status {
                    m_db->Get(rocksdb::ReadOptions(), getColumnFamilyBasedOnName(columnName).handle(), key, &value)};
                status.IsNotFound())
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

            const auto status {m_db->Delete(writeOptions, getColumnFamilyBasedOnName(columnName).handle(), key)};
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
                m_db->NewIterator(rocksdb::ReadOptions(), getColumnFamilyBasedOnName(columnName).handle()));

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
                        m_db->NewIterator(rocksdb::ReadOptions(), getColumnFamilyBasedOnName(columnName).handle())),
                    key};
        }

        /**
         * @brief Get an iterator to the database.
         * @return RocksDBIterator Iterator to the database.
         */
        RocksDBIterator begin(const std::string& columnName = "")
        {
            RocksDBIterator rocksDBIterator(
                std::shared_ptr<rocksdb::Iterator>(
                    m_db->NewIterator(rocksdb::ReadOptions(), getColumnFamilyBasedOnName(columnName).handle())),
                "");
            rocksDBIterator.begin();
            return rocksDBIterator;
        }

        /**
         * @brief Get an iterator to the end of the database.
         * @return const RocksDBIterator Iterator to the end of the database.
         */
        const RocksDBIterator& end() const
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
            if (const auto status = m_db->SetOptions({{"compression", "kBZip2Compression"}}); !status.ok())
            {
                throw std::runtime_error("Failed to set 'kBZip2Compression' option");
            }

            // Perform compaction for the entire key range
            m_db->CompactRange(rocksdb::CompactRangeOptions(), nullptr, nullptr);
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
            compactOptions.bottommost_level_compaction = rocksdb::BottommostLevelCompaction::kForceOptimized;

            // Perform compaction for the entire key range
            m_db->CompactRange(compactOptions, nullptr, nullptr);
        }

        /**
         * @brief Initialize transaction.
         * @return RocksDBTransaction Transaction object.
         */
        std::unique_ptr<IRocksDBWrapper> createTransaction()
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

            if (const auto status {m_db->CreateColumnFamily(
                    RocksDBOptions::buildColumnFamilyOptions(m_readCache), columnName, &pColumnFamily)};
                !status.ok())
            {
                throw std::runtime_error {"Couldn't create column family: " + std::string {status.getState()}};
            }
            m_columnsInstances.emplace_back(m_db, pColumnFamily);
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

            return std::find_if(m_columnsInstances.begin(),
                                m_columnsInstances.end(),
                                [&columnName](const ColumnFamilyRAII& handle)
                                { return columnName == handle->GetName(); }) != m_columnsInstances.end();
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
            if (const auto listStatus {rocksdb::TransactionDB::ListColumnFamilies(options, m_path, &columnsNames)};
                !listStatus.ok())
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
            std::vector<std::string> columnsNames;
            auto it = m_columnsInstances.begin();

            while (it != m_columnsInstances.end())
            {
                if ((*it)->GetName() != rocksdb::kDefaultColumnFamilyName)
                {
                    it->drop();
                    columnsNames.push_back((*it)->GetName());
                    it = m_columnsInstances.erase(it);
                }
                else
                {
                    rocksdb::WriteBatch batch;
                    std::unique_ptr<rocksdb::Iterator> itDefault(
                        m_db->NewIterator(rocksdb::ReadOptions(), it->handle()));

                    itDefault->SeekToFirst();
                    while (itDefault->Valid())
                    {
                        batch.Delete(it->handle(), itDefault->key());
                        itDefault->Next();
                    }

                    if (const auto status = m_db->Write(rocksdb::WriteOptions(), &batch); !status.ok())
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
            const auto& columnHandle = getColumnFamilyBasedOnName(columnName);
            if (columnHandle->GetName() != rocksdb::kDefaultColumnFamilyName)
            {
                // Find the column handle on the list and drop it
                const auto it =
                    std::find_if(m_columnsInstances.begin(),
                                 m_columnsInstances.end(),
                                 [&columnName](const auto& handle) { return columnName == handle->GetName(); });

                // Check if the column exists
                if (it != m_columnsInstances.end())
                {
                    it->drop();
                    m_columnsInstances.erase(it);

                    createColumn(columnName);
                }
            }
            else
            {
                rocksdb::WriteBatch batch;
                std::unique_ptr<rocksdb::Iterator> itDefault(
                    m_db->NewIterator(rocksdb::ReadOptions(), columnHandle.handle()));

                itDefault->SeekToFirst();
                while (itDefault->Valid())
                {
                    batch.Delete(columnHandle.handle(), itDefault->key());
                    itDefault->Next();
                }

                if (auto status = m_db->Write(rocksdb::WriteOptions(), &batch); !status.ok())
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
            for (const auto& columnHandle : m_columnsInstances)
            {
                // Create an iterator for the current column family
                std::unique_ptr<rocksdb::Iterator> it(m_db->NewIterator(rocksdb::ReadOptions(), columnHandle));

                // Iterate through all key-value pairs in the column
                it->SeekToFirst();
                while (it->Valid())
                {
                    auto keyStr = std::string(it->key().data(), it->key().size());
                    auto valueStr = it->value().ToString();

                    callback(keyStr, valueStr);

                    if (auto status = m_db->Delete(rocksdb::WriteOptions(), columnHandle, it->key()); !status.ok())
                    {
                        throw std::runtime_error("Error deleting data: " + status.ToString());
                    }
                    it->Next();
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
            const auto& columnHandle = getColumnFamilyBasedOnName(columnName);

            // Create an iterator for the current column family
            std::unique_ptr<rocksdb::Iterator> it(m_db->NewIterator(rocksdb::ReadOptions(), columnHandle.handle()));

            it->SeekToFirst();
            while (it->Valid())
            {
                auto keyStr = std::string(it->key().data(), it->key().size());
                auto valueStr = it->value().ToString();

                callback(keyStr, valueStr);

                if (auto status = m_db->Delete(rocksdb::WriteOptions(), columnHandle.handle(), it->key()); !status.ok())
                {
                    throw std::runtime_error("Error deleting data: " + status.ToString());
                }
                it->Next();
            }
        }

        /**
         * @brief Flushes the transaction.
         */
        void flush() override
        {
            for (const auto& columnFamily : m_columnsInstances)
            {
                if (const auto status {m_db->Flush(rocksdb::FlushOptions(), columnFamily.handle())}; !status.ok())
                {
                    throw std::runtime_error {"Failed to flush transaction: " + std::string {status.getState()}};
                }
            }
        }

    private:
        std::shared_ptr<T> m_db;                                     ///< RocksDB instance.
        std::vector<ColumnFamilyRAII> m_columnsInstances;            ///< List of column family.
        const bool m_enableWal;                                      ///< Whether to enable WAL or not.
        const std::string m_path;                                    ///< Location of the DB.
        std::shared_ptr<rocksdb::Cache> m_readCache;                 ///< Cache for read operations.
        std::shared_ptr<rocksdb::WriteBufferManager> m_writeManager; ///< Write buffer manager.

        /**
         * @brief Will try to repair the database if it is corrupt or throw exception if something failed.
         *
         * @param errorStatus The status of the failed operation.
         */
        void repairDB(const rocksdb::Status& errorStatus)
        {
            if (errorStatus.code() == rocksdb::Status::kIOError || errorStatus.code() == rocksdb::Status::kCorruption)
            {
                rocksdb::Options options;
                if (const auto repairStatus {rocksdb::RepairDB(m_path, options)}; !repairStatus.ok())
                {
                    throw std::runtime_error("Failed to repair RocksDB database. Reason: " +
                                             std::string {repairStatus.getState()});
                }
                logWarn(LOGGER_DEFAULT_TAG, "Database '%s' was repaired because it was corrupt.", m_path.c_str());
            }
            else
            {
                throw std::runtime_error("Failed to open RocksDB database, repair not tried because the error "
                                         "wasn't corruption. Code: " +
                                         std::to_string(errorStatus.code()) + " Reason: " + errorStatus.getState());
            }
        }

        /**
         * @brief Returns the column family handle identified by its name.
         *
         * @param columnName Name of the column family. If empty, the default handle is returned.
         * @return rocksdb::ColumnFamilyHandle* Column family handle pointer.
         */
        ColumnFamilyRAII& getColumnFamilyBasedOnName(const std::string& columnName)
        {
            auto columnNameFind {columnName};
            if (columnName.empty())
            {
                columnNameFind = rocksdb::kDefaultColumnFamilyName;
            }

            if (const auto it {std::find_if(m_columnsInstances.begin(),
                                            m_columnsInstances.end(),
                                            [&columnNameFind](const ColumnFamilyRAII& handle)
                                            { return columnNameFind == handle.handle()->GetName(); })};
                it != m_columnsInstances.end())
            {
                return *it;
            }

            throw std::runtime_error {"Couldn't find column family: '" + columnName + "'"};
        }

        auto createTransaction(const rocksdb::WriteOptions& writeOptions)
        {
            if constexpr (std::is_same_v<T, rocksdb::DB>)
            {
                throw std::runtime_error {"Transactions are only supported for rocksdb::TransactionDB"};
                return nullptr;
            }
            else
            {
                auto txn = m_db->BeginTransaction(writeOptions);
                if (!txn)
                {
                    throw std::runtime_error {"Failed to begin transaction"};
                }
                return txn;
            }
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
        explicit RocksDBTransaction(TRocksDBWrapper<>* dbWrapper)
            : m_dbWrapper {dbWrapper}
        {
            if (!m_dbWrapper)
            {
                throw std::runtime_error {"RocksDB instance is null"};
            }

            rocksdb::WriteOptions writeOptions;
            writeOptions.disableWAL = true;

            m_txn = std::unique_ptr<rocksdb::Transaction, std::function<void(rocksdb::Transaction*)>>(
                m_dbWrapper->createTransaction(writeOptions),
                [this](rocksdb::Transaction* txn)
                {
                    if (txn && !m_committed)
                    {
                        txn->Rollback();
                    }
                });
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
            const auto status {m_txn->Put(m_dbWrapper->getColumnFamilyBasedOnName(columnName).handle(), key, value)};
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
            const auto status {m_txn->Delete(m_dbWrapper->getColumnFamilyBasedOnName(columnName).handle(), key)};
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

            if (const auto status = m_txn->Get(
                    rocksdb::ReadOptions(), m_dbWrapper->getColumnFamilyBasedOnName(columnName).handle(), key, &value);
                status.IsNotFound())
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
            if (const auto status {m_txn->Commit()}; !status.ok())
            {
                throw std::runtime_error {"Failed to commit transaction: " + std::string {status.getState()}};
            }

            m_dbWrapper->flush();
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
        [[noreturn]] void flush() override
        {
            // This is only permited for atomic operations.
            throw std::runtime_error("Not implemented");
        }

    private:
        TRocksDBWrapper<>* m_dbWrapper; ///< RocksDB instance.
        std::unique_ptr<rocksdb::Transaction, std::function<void(rocksdb::Transaction*)>>
            m_txn;                ///< RocksDB transaction.
        bool m_committed {false}; ///< Whether the transaction has been committed or not.
    };
    using RocksDBWrapper = TRocksDBWrapper<>;
} // namespace Utils

#endif // _ROCKS_DB_WRAPPER_HPP
