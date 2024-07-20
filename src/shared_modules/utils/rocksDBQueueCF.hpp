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

#include "loggerHelper.h"
#include "rocksDBOptions.hpp"
#include "rocksdb/db.h"
#include "rocksdb/filter_policy.h"
#include "rocksdb/table.h"
#include "stringHelper.h"
#include <filesystem>
#include <stdexcept>
#include <string>

// RocksDB integration as queue
template<typename T, typename U = T>
class RocksDBQueueCF final
{
private:
    struct QueueMetadata final
    {
        uint64_t head = 0;
        uint64_t tail = 0;
        uint64_t size = 0;

        // Time from epoch + postpone time.
        std::chrono::time_point<std::chrono::system_clock> postponeTime;
    };

    void initializeQueueData()
    {
        constexpr auto ID_QUEUE = 0;
        constexpr auto QUEUE_NUMBER = 1;

        auto it = std::unique_ptr<rocksdb::Iterator>(m_db->NewIterator(rocksdb::ReadOptions()));
        it->SeekToFirst();
        while (it->Valid())
        {
            // Split key to get the ID and queue number.
            const auto data = Utils::split(it->key().ToString(), '_');
            const auto& id = data.at(ID_QUEUE);
            const auto queueNumber = std::stoull(data.at(QUEUE_NUMBER));

            if (m_queueMetadata.find(id.data()) == m_queueMetadata.end())
            {
                m_queueMetadata.emplace(id,
                                        QueueMetadata {queueNumber, queueNumber, 0, std::chrono::system_clock::now()});
            }

            auto& element = m_queueMetadata[id];

            if (queueNumber > element.tail)
            {
                element.tail = queueNumber;
            }

            if (queueNumber < element.head)
            {
                element.head = queueNumber;
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

        if (auto status = rocksdb::DB::Open(options, path, &dbRawPtr); !status.ok())
        {
            if (status.IsCorruption() || status.IsIOError())
            {
                rocksdb::Options repairOptions;
                if (const auto repairStatus {rocksdb::RepairDB(path, repairOptions)}; !repairStatus.ok())
                {
                    throw std::runtime_error("Failed to repair RocksDB database. Reason: " +
                                             std::string {repairStatus.getState()});
                }
                else
                {
                    status = rocksdb::DB::Open(options, path, &dbRawPtr);
                    if (!status.ok())
                    {
                        throw std::runtime_error("Failed to open RocksDB database after repairing. Reason: " +
                                                 std::string {status.getState()});
                    }
                    logWarn(LOGGER_DEFAULT_TAG, "Database '%s' was repaired because it was corrupt.", path.c_str());
                }
            }
            else
            {
                throw std::runtime_error("Failed to open RocksDB database, not repairable. Reason: " +
                                         std::string {status.getState()});
            }
        }

        // Assigns the raw pointer to the unique_ptr. When db goes out of scope, it will automatically delete the
        // allocated RocksDB instance.
        m_db.reset(dbRawPtr);

        // Initialize queue data.
        initializeQueueData();
    }

    void push(std::string_view id, const T& data)
    {
        if (m_queueMetadata.find(id.data()) == m_queueMetadata.end())
        {
            m_queueMetadata.emplace(id, QueueMetadata {1, 0, 0, std::chrono::system_clock::now()});
        }

        if (const auto it {m_queueMetadata.find(id.data())}; it != m_queueMetadata.end())
        {
            ++it->second.tail;
            if (const auto status =
                    m_db->Put(rocksdb::WriteOptions(), std::string(id) + "_" + std::to_string(it->second.tail), data);
                !status.ok())
            {
                throw std::runtime_error("Failed to enqueue element");
            }
            ++it->second.size;
        }
    }

    void pop(std::string_view id)
    {
        if (const auto it {m_queueMetadata.find(id.data())}; it != m_queueMetadata.end())
        {
            // RocksDB dequeue element.
            if (!m_db->Delete(rocksdb::WriteOptions(), std::string(id) + "_" + std::to_string(it->second.head)).ok())
            {
                throw std::runtime_error("Failed to dequeue element, can't delete it");
            }

            ++it->second.head;
            --it->second.size;

            if (it->second.size == 0)
            {
                m_queueMetadata.erase(it);
            }
        }
        else
        {
            throw std::runtime_error("Couldn't find ID: " + std::string {id});
        }
    }

    uint64_t size(std::string_view id) const
    {
        if (const auto it = m_queueMetadata.find(id.data()); it != m_queueMetadata.end())
        {
            return it->second.size;
        }

        return 0;
    }

    bool empty() const
    {
        // Empty calculation not considering the postponed columns.
        // Count if there is any column with elements.
        const auto currentSystemTime = std::chrono::system_clock::now();
        auto count =
            std::count_if(m_queueMetadata.begin(),
                          m_queueMetadata.end(),
                          [&](const auto& metadata) { return metadata.second.postponeTime < currentSystemTime; });
        return count == 0;
    }

    const std::string& getAvailableColumn()
    {
        if (m_queueMetadata.empty())
        {
            throw std::runtime_error("No queue ids available");
        }

        // Only consider the columns that are not postponed.
        const auto currentSystemTime = std::chrono::system_clock::now();
        auto it = std::find_if(m_queueMetadata.begin(),
                               m_queueMetadata.end(),
                               [&](const auto& metadata) { return metadata.second.postponeTime < currentSystemTime; });

        if (it == m_queueMetadata.end())
        {
            throw std::runtime_error("Probably race condition, no queue id available");
        }

        return it->first;
    }

    void postpone(std::string_view id, const std::chrono::seconds& time) noexcept
    {
        if (const auto it {m_queueMetadata.find(id.data())}; it != m_queueMetadata.end())
        {
            it->second.postponeTime = std::chrono::system_clock::now() + time;
        }
    }

    U front(std::string_view id) const
    {
        U value;
        if (const auto it {m_queueMetadata.find(id.data())}; it != m_queueMetadata.end())
        {
            if (!m_db->Get(rocksdb::ReadOptions(),
                           m_db->DefaultColumnFamily(),
                           std::string(id) + "_" + std::to_string(it->second.head),
                           &value)
                     .ok())
            {
                throw std::runtime_error("Failed to get front element, id: " + std::string {id} +
                                         " key: " + std::to_string(it->second.head));
            }
        }
        else
        {
            throw std::runtime_error("Couldn't find id: " + std::string {id});
        }

        return value;
    }

    void clear(std::string_view id)
    {
        auto deleteElement = [this](const std::string& key)
        {
            if (!m_db->Delete(rocksdb::WriteOptions(), key).ok())
            {
                throw std::runtime_error("Failed to clear element, can't delete it");
            }
        };

        if (id.empty())
        {
            // Clear all elements from the queue.
            for (const auto& metadata : m_queueMetadata)
            {
                for (auto i = metadata.second.head; i <= metadata.second.tail; ++i)
                {
                    deleteElement(std::string(metadata.first) + "_" + std::to_string(i));
                }
            }
            m_queueMetadata.clear();
        }
        else
        {
            if (const auto it {m_queueMetadata.find(id.data())}; it != m_queueMetadata.end())
            {
                // Clear all elements from the queue.
                for (auto i = it->second.head; i <= it->second.tail; ++i)
                {
                    deleteElement(std::string(id) + "_" + std::to_string(i));
                    ++it->second.head;
                    --it->second.size;
                }
                m_queueMetadata.erase(it);
            }
        }
    }

private:
    std::shared_ptr<rocksdb::DB> m_db;
    std::shared_ptr<rocksdb::Cache> m_readCache;
    std::shared_ptr<rocksdb::WriteBufferManager> m_writeManager;
    std::map<std::string, QueueMetadata> m_queueMetadata; ///< Map queue.
};

#endif // _ROCKSDB_QUEUE_CF_HPP
