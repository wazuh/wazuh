/*
 * Wazuh Utils - rocksDB queue.
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 2, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROCKSDB_QUEUE_HPP
#define _ROCKSDB_QUEUE_HPP

#include "loggerHelper.h"
#include "rocksDBSharedBuffers.hpp"
#include "rocksdb/db.h"
#include "rocksdb/filter_policy.h"
#include "rocksdb/table.h"
#include "stringHelper.h"
#include <filesystem>
#include <queue>
#include <stdexcept>
#include <string>

constexpr auto ROCKSDB_QUEUE_PADDING {20};

// RocksDB integration as queue
template<typename T, typename U = T>
class RocksDBQueue final
{
public:
    explicit RocksDBQueue(const std::string& connectorName, bool useSharedBuffers = false)
        : m_legacyKeyMode {false}
    {
        // RocksDB initialization using shared buffers.
        // Get shared buffers to reduce memory usage across multiple instances
        if (useSharedBuffers)
        {
            auto& sharedBuffers = RocksDBSharedBuffers::getInstance();
            m_writeManager = sharedBuffers.getWriteBufferManager();
            m_readCache = sharedBuffers.getReadCache();
        }
        else
        {
            // Write buffer manager is used to manage the memory used for writing data to the disk.
            m_readCache = rocksdb::NewLRUCache(16 * 1024 * 1024);
            m_writeManager = std::make_shared<rocksdb::WriteBufferManager>(128 * 1024 * 1024, m_readCache);
        }

        rocksdb::BlockBasedTableOptions tableOptions;
        tableOptions.block_cache = m_readCache;

        rocksdb::Options options;
        options.table_factory.reset(NewBlockBasedTableFactory(tableOptions));
        options.create_if_missing = true;
        // Setting INFO level for the info log. We'll have up to 10 files of 10MB each.
        options.info_log_level = rocksdb::InfoLogLevel::INFO_LEVEL;
        options.keep_log_file_num = 10;
        options.max_log_file_size = 10 * 1024 * 1024;
        options.recycle_log_file_num = 10;
        options.max_open_files = 64;
        options.write_buffer_manager = m_writeManager;
        options.num_levels = 4;

        options.write_buffer_size = 64 * 1024 * 1024;
        options.max_write_buffer_number = 4;
        options.max_background_jobs = 8;

        rocksdb::DB* db;

        // Create directories recursively if they do not exist
        std::filesystem::create_directories(std::filesystem::path(connectorName));

        if (auto status = rocksdb::DB::Open(options, connectorName, &db); !status.ok())
        {
            if (status.IsCorruption() || status.IsIOError())
            {
                rocksdb::Options repairOptions;
                if (const auto repairStatus {rocksdb::RepairDB(connectorName, repairOptions)}; !repairStatus.ok())
                {
                    throw std::runtime_error("Failed to repair RocksDB database. Reason: " +
                                             std::string {repairStatus.getState()});
                }
                else
                {
                    status = rocksdb::DB::Open(options, connectorName, &db);
                    if (!status.ok())
                    {
                        throw std::runtime_error("Failed to open RocksDB database after repairing. Reason: " +
                                                 std::string {status.getState()});
                    }
                    logWarn(LOGGER_DEFAULT_TAG,
                            "Database '%s' was repaired because it was corrupt.",
                            connectorName.c_str());
                }
            }
            else
            {
                throw std::runtime_error("Failed to open RocksDB database, not repairable. Reason: " +
                                         std::string {status.getState()});
            }
        }

        m_db.reset(db);

        // RocksDB counter initialization.
        m_size = 0;
        auto it = std::unique_ptr<rocksdb::Iterator>(m_db->NewIterator(rocksdb::ReadOptions()));
        it->SeekToFirst();

        if (it->Valid())
        {
            auto key = std::stoull(it->key().ToString());
            m_first = key;
            m_last = key;
        }
        else
        {
            m_first = 1;
            m_last = 0;
        }

        uint64_t paddedKeys = 0;
        uint64_t otherKeys = 0;

        while (it->Valid())
        {
            const auto keyString = it->key().ToString();
            const auto key = std::stoull(keyString);

            if (keyString.size() < ROCKSDB_QUEUE_PADDING)
            {
                m_legacyKeyMode = true;
            }

            // Count the keys that are neither the plain decimal nor the padded form of their index.
            if (keyString != std::to_string(key))
            {
                if (keyString == Utils::padString(std::to_string(key), '0', ROCKSDB_QUEUE_PADDING))
                {
                    ++paddedKeys;
                }
                else
                {
                    ++otherKeys;
                }
            }

            if (key > m_last)
            {
                m_last = key;
            }

            if (key < m_first)
            {
                m_first = key;
            }
            ++m_size;

            it->Next();
        }

        // Valid() is false both at the end of the store and when the iteration fails, so the status tells them apart.
        // Bounds computed from a partial scan would make push() overwrite queued entries, so push() is refused.
        if (const auto status = it->status(); !status.ok())
        {
            m_unreliableBounds =
                "the scan failed after reading " + std::to_string(m_size) + " keys: " + status.ToString();
            logError(LOGGER_DEFAULT_TAG,
                     "Queue '%s': the bounds could not be established (%s). New elements are rejected.",
                     connectorName.c_str(),
                     m_unreliableBounds.c_str());
        }

        // A stored key the queue would never build cannot be read or removed.
        if (const auto unreachableKeys = otherKeys + (m_legacyKeyMode ? paddedKeys : 0); unreachableKeys > 0)
        {
            logWarn(LOGGER_DEFAULT_TAG,
                    "Queue '%s': %llu of %llu stored keys do not match the %s key format the queue reads and will "
                    "not be dequeued.",
                    connectorName.c_str(),
                    static_cast<unsigned long long>(unreachableKeys),
                    static_cast<unsigned long long>(m_size),
                    m_legacyKeyMode ? "unpadded" : "padded");
        }
    }

    void push(const T& data)
    {
        if (!m_unreliableBounds.empty())
        {
            throw std::runtime_error("Failed to enqueue element, the bounds of the queue are unreliable: " +
                                     m_unreliableBounds);
        }

        // RocksDB enqueue element.
        if (const auto status = m_db->Put(rocksdb::WriteOptions(), paddedKey(m_last + 1), data); !status.ok())
        {
            throw std::runtime_error("Failed to enqueue element: " + paddedKey(m_last + 1));
        }
        // If enqueue is successful, increment the last element.
        ++m_last;
        ++m_size;
    }

    void pop()
    {
        // If the queue is empty, nothing to do.
        if (m_size == 0)
        {
            return;
        }

        auto index = m_first;
        std::string value;

        // Find the first element in the queue from m_first (included).
        while (index <= m_last &&
               !m_db->KeyMayExist(rocksdb::ReadOptions(), m_db->DefaultColumnFamily(), paddedKey(index), &value))
        {
            // If the key does not exist, it means that the queue is not continuous.
            // This incremental is only for the head, because this is a part of recovery algorithm when the queue
            // not is continuous.
            ++index;
        }

        // If the index is greater than the last element, the queue status is invalid.
        if (index > m_last)
        {
            throw std::runtime_error("Failed to dequeue element, queue is empty");
        }

        // RocksDB dequeue element.
        if (const auto status = m_db->Delete(rocksdb::WriteOptions(), paddedKey(index)); !status.ok())
        {
            throw std::runtime_error("Failed to dequeue element: " + paddedKey(index));
        }
        else
        {
            ++m_first;
            --m_size;

            // If the queue is empty, reset the first and last elements counters.
            if (m_size == 0)
            {
                m_first = 1;
                m_last = 0;
            }
        }
    }

    uint64_t size() const
    {
        return m_size;
    }

    bool empty() const
    {
        return m_size == 0;
    }

    void frontQueue(std::queue<U>& queue, const uint64_t elementsQuantity)
    {
        if (m_size < elementsQuantity)
        {
            throw std::runtime_error("Failed to get elements, queue have less elements than requested");
        }

        auto counter = 0ULL;
        auto index = m_first;

        // Get the first "elementsQuantity" elements in increasing order.
        while (counter < elementsQuantity && index <= m_last)
        {
            U value;
            if (const auto status =
                    m_db->Get(rocksdb::ReadOptions(), m_db->DefaultColumnFamily(), paddedKey(index), &value);
                status.ok())
            {
                queue.push(std::move(value));
                ++counter;
            }
            else
            {
                if (status != rocksdb::Status::NotFound())
                {
                    throw std::runtime_error("Failed to get elements, error: " + std::to_string(status.code()));
                }
            }
            ++index;
        }

        // The keys the queue accounts for do not match the ones stored: do not wait for elements that do not exist.
        if (counter < elementsQuantity)
        {
            throw std::runtime_error("Failed to get elements, only " + std::to_string(counter) + " of " +
                                     std::to_string(elementsQuantity) + " requested elements were found between " +
                                     std::to_string(m_first) + " and " + std::to_string(m_last));
        }
    }

    U front()
    {
        U value;
        // If the queue is empty, return an empty value.
        if (m_size == 0)
        {
            throw std::runtime_error("Failed to get front element, queue is empty");
        }

        // If the queue have bumps between elements, get the first element in increasing order.
        auto index = m_first;

        while (index <= m_last)
        {
            if (const auto status =
                    m_db->Get(rocksdb::ReadOptions(), m_db->DefaultColumnFamily(), paddedKey(index), &value);
                status.ok())
            {
                break;
            }
            else
            {
                if (status != rocksdb::Status::NotFound())
                {
                    throw std::runtime_error("Failed to get elements, error: " + status.code());
                }
            }
            ++index;
        }

        return value;
    }

    U at(const uint64_t index) const
    {
        U value;

        if (const auto status =
                m_db->Get(rocksdb::ReadOptions(), m_db->DefaultColumnFamily(), paddedKey(m_first + index), &value);
            !status.ok())
        {
            throw std::runtime_error("Failed to get element at index: " + paddedKey(m_first + index));
        }

        return value;
    }

private:
    std::unique_ptr<rocksdb::DB> m_db;
    std::shared_ptr<rocksdb::Cache> m_readCache;
    std::shared_ptr<rocksdb::WriteBufferManager> m_writeManager;
    uint64_t m_size = 0;
    uint64_t m_first = 1;
    uint64_t m_last = 0;
    bool m_legacyKeyMode = false;
    std::string m_unreliableBounds; ///< Why the bounds are not trustworthy; empty when they are.

    std::string paddedKey(const uint64_t key) const
    {
        return m_legacyKeyMode ? std::to_string(key)
                               : Utils::padString(std::to_string(key), '0', ROCKSDB_QUEUE_PADDING);
    }
};

#endif // _ROCKSDB_QUEUE_HPP
