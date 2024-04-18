/*
 * Wazuh Utils - rocksDB queue.
 * Copyright (C) 2015, Wazuh Inc.
 * April 9, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROCKSDB_QUEUE_CF_HPP
#define _ROCKSDB_QUEUE_CF_HPP

#include "rocksDBColumnFamily.hpp"
#include "rocksDBOptions.hpp"
#include "rocksdb/db.h"
#include "rocksdb/filter_policy.h"
#include "rocksdb/table.h"
#include <filesystem>
#include <stdexcept>
#include <string>

// RocksDB integration as queue
template<typename T, typename U = T>
class RocksDBQueueCF final
{
private:
    struct ColumnFamilyQueue : public Utils::ColumnFamilyRAII
    {
        uint64_t head = 0;
        uint64_t tail = 0;
        uint64_t size = 0;

        // Time from epoch + postpone time.
        std::chrono::time_point<std::chrono::system_clock> postponeTime;

        ColumnFamilyQueue(const std::shared_ptr<rocksdb::DB>& db, rocksdb::ColumnFamilyHandle* rawHandle)
            : Utils::ColumnFamilyRAII(db, rawHandle)
        {
        }
    };

    void dropColumn(std::string_view columnFamily)
    {
        if (const auto it = std::find_if(m_columnsInstances.begin(),
                                         m_columnsInstances.end(),
                                         [&columnFamily](const ColumnFamilyQueue& handle)
                                         { return columnFamily == handle->GetName(); });
            it != m_columnsInstances.end())
        {
            it->drop();
            m_columnsInstances.erase(it);
        }
    }

    void createColumn(std::string_view columnName)
    {
        if (columnName.empty())
        {
            throw std::invalid_argument {"Column name is empty"};
        }

        rocksdb::ColumnFamilyHandle* pColumnFamily;

        if (const auto status {m_db->CreateColumnFamily(
                Utils::RocksDBOptions::buildColumnFamilyOptions(m_readCache), columnName.data(), &pColumnFamily)};
            !status.ok())
        {
            throw std::runtime_error {"Couldn't create column family: " + std::string {status.getState()}};
        }
        auto& element = m_columnsInstances.emplace_back(m_db, pColumnFamily);
        element.head = 1;
        element.tail = 0;
    }

    bool columnExists(std::string_view columnName) const
    {
        if (columnName.empty())
        {
            throw std::invalid_argument {"Column name is empty"};
        }

        return std::find_if(m_columnsInstances.begin(),
                            m_columnsInstances.end(),
                            [&columnName](const ColumnFamilyQueue& handle)
                            { return columnName == handle->GetName(); }) != m_columnsInstances.end();
    }

    void initializeQueueData(ColumnFamilyQueue& element)
    {
        // RocksDB counter initialization.
        element.size = 0;

        auto it = std::unique_ptr<rocksdb::Iterator>(m_db->NewIterator(rocksdb::ReadOptions(), element.handle()));
        it->SeekToFirst();
        if (it->Valid())
        {
            const auto key = std::stoull(it->key().ToString());
            element.head = key;
            element.tail = key;
        }
        else
        {
            element.head = 1;
            element.tail = 0;
        }

        while (it->Valid())
        {
            const auto key = std::stoull(it->key().ToString());
            if (key > element.tail)
            {
                element.tail = key;
            }

            if (key < element.head)
            {
                element.head = key;
            }
            ++element.size;

            it->Next();
        }
    }

public:
    explicit RocksDBQueueCF(const std::string& path)
    {
        // RocksDB initialization.
        // Read cache is used to cache the data read from the disk.
        m_readCache = rocksdb::NewLRUCache(Utils::ROCKSDB_BLOCK_CACHE_SIZE);
        // Write buffer manager is used to manage the memory used for writing data to the disk.
        m_writeManager = std::make_shared<rocksdb::WriteBufferManager>(Utils::ROCKSDB_WRITE_BUFFER_MANAGER_SIZE);

        rocksdb::Options options = Utils::RocksDBOptions::buildDBOptions(m_writeManager, m_readCache);
        rocksdb::ColumnFamilyOptions columnFamilyOptions = Utils::RocksDBOptions::buildColumnFamilyOptions(m_readCache);

        rocksdb::DB* dbRawPtr;

        // Create directories recursively if they do not exist
        std::vector<rocksdb::ColumnFamilyDescriptor> columnsDescriptors;
        const std::filesystem::path databasePath {path};

        // Create directories recursively if they do not exist
        std::filesystem::create_directories(databasePath);

        // Get a list of the existing columns descriptors.
        if (const auto databaseFile {databasePath / "CURRENT"}; std::filesystem::exists(databaseFile))
        {
            // Read columns names.
            std::vector<std::string> columnsNames;
            if (const auto listStatus {rocksdb::DB::ListColumnFamilies(options, path, &columnsNames)}; !listStatus.ok())
            {
                throw std::runtime_error("Failed to list columns: " + std::string {listStatus.getState()});
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
        if (const auto status {rocksdb::DB::Open(options, path, columnsDescriptors, &columnHandles, &dbRawPtr)};
            !status.ok())
        {
            throw std::runtime_error("Failed to open RocksDB database. Reason: " + std::string {status.getState()});
        }

        // Assigns the raw pointer to the unique_ptr. When db goes out of scope, it will automatically delete the
        // allocated RocksDB instance.
        m_db.reset(dbRawPtr);

        // Create a RAII wrapper for each column handle.
        for (const auto& handle : columnHandles)
        {
            if (handle->GetName() != rocksdb::kDefaultColumnFamilyName)
            {
                auto& element = m_columnsInstances.emplace_back(m_db, handle);
                initializeQueueData(element);
            }
            else
            {
                // Close the default column handle.
                // The default column handle is not used in this class.
                if (const auto status {m_db->DestroyColumnFamilyHandle(handle)}; !status.ok())
                {
                    throw std::runtime_error("Failed to free RocksDB column family: " +
                                             std::string {status.getState()});
                }
            }
        }
    }

    void push(std::string_view columnFamily, const T& data)
    {
        if (!columnExists(columnFamily))
        {
            createColumn(columnFamily);
        }

        const auto it {std::find_if(m_columnsInstances.begin(),
                                    m_columnsInstances.end(),
                                    [&columnFamily](const ColumnFamilyQueue& handle)
                                    { return columnFamily == handle.handle()->GetName(); })};

        if (it != m_columnsInstances.end())
        {
            ++it->tail;
            if (const auto status = m_db->Put(rocksdb::WriteOptions(), it->handle(), std::to_string(it->tail), data);
                !status.ok())
            {
                throw std::runtime_error("Failed to enqueue element");
            }
            ++it->size;
        }
    }

    void pop(std::string_view columnFamily)
    {
        if (const auto it {std::find_if(m_columnsInstances.begin(),
                                        m_columnsInstances.end(),
                                        [&columnFamily](const ColumnFamilyQueue& handle)
                                        { return columnFamily == handle.handle()->GetName(); })};
            it != m_columnsInstances.end())
        {
            // RocksDB dequeue element.
            if (!m_db->Delete(rocksdb::WriteOptions(), it->handle(), std::to_string(it->head)).ok())
            {
                throw std::runtime_error("Failed to dequeue element, can't delete it");
            }

            ++it->head;
            --it->size;

            if (it->size == 0)
            {
                dropColumn(columnFamily);
            }
        }
        else
        {
            throw std::runtime_error("Couldn't find column family: " + std::string {columnFamily});
        }
    }

    uint64_t size(std::string_view columnName) const
    {
        if (const auto it {std::find_if(m_columnsInstances.begin(),
                                        m_columnsInstances.end(),
                                        [&columnName](const ColumnFamilyQueue& handle)
                                        { return columnName == handle.handle()->GetName(); })};
            it != m_columnsInstances.end())
        {
            return it->size;
        }

        return 0;
    }

    bool empty() const
    {
        // Empty calculation not considering the postponed columns.
        // Count if there is any column with elements.
        const auto currentSystemTime = std::chrono::system_clock::now();
        auto count =
            std::count_if(m_columnsInstances.begin(),
                          m_columnsInstances.end(),
                          [&](const ColumnFamilyQueue& handle) { return handle.postponeTime < currentSystemTime; });
        return count == 0;
    }

    const std::string& getAvailableColumn()
    {
        if (m_columnsInstances.empty())
        {
            throw std::runtime_error("No column family available");
        }

        // Only consider the columns that are not postponed.
        const auto currentSystemTime = std::chrono::system_clock::now();
        auto it =
            std::find_if(m_columnsInstances.begin(),
                         m_columnsInstances.end(),
                         [&](const ColumnFamilyQueue& handle) { return handle.postponeTime < currentSystemTime; });

        if (it == m_columnsInstances.end())
        {
            throw std::runtime_error("Probably race condition, no column family available");
        }

        return it->handle()->GetName();
    }

    void postpone(std::string_view columnName, const std::chrono::seconds& time) noexcept
    {
        if (const auto it {std::find_if(m_columnsInstances.begin(),
                                        m_columnsInstances.end(),
                                        [&columnName](const ColumnFamilyQueue& handle)
                                        { return columnName == handle.handle()->GetName(); })};
            it != m_columnsInstances.end())
        {
            it->postponeTime = std::chrono::system_clock::now() + time;
        }
    }

    U front(std::string_view columnFamily) const
    {
        U value;
        if (const auto it {std::find_if(m_columnsInstances.begin(),
                                        m_columnsInstances.end(),
                                        [&columnFamily](const ColumnFamilyQueue& handle)
                                        { return columnFamily == handle.handle()->GetName(); })};
            it != m_columnsInstances.end())
        {
            if (!m_db->Get(rocksdb::ReadOptions(), it->handle(), std::to_string(it->head), &value).ok())
            {
                throw std::runtime_error("Failed to get front element, column family: " + std::string {columnFamily} +
                                         " key: " + std::to_string(it->head));
            }
        }
        else
        {
            throw std::runtime_error("Couldn't find column family: " + std::string {columnFamily});
        }

        return value;
    }

private:
    std::shared_ptr<rocksdb::DB> m_db;
    std::shared_ptr<rocksdb::Cache> m_readCache;
    std::shared_ptr<rocksdb::WriteBufferManager> m_writeManager;
    std::vector<ColumnFamilyQueue> m_columnsInstances; ///< List of column family.
};

#endif // _ROCKSDB_QUEUE_CF_HPP
