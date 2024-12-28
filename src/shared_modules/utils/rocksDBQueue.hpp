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
private:
    std::string paddedKey(uint64_t key) const
    {
        return Utils::padString(std::to_string(key), '0', ROCKSDB_QUEUE_PADDING);
    }

    void keyNormalization(uint64_t key, std::string_view keyString, std::string_view value)
    {
        if (keyString.size() < ROCKSDB_QUEUE_PADDING)
        {
            auto stringPaddedKey = paddedKey(key);
            if (const auto status = m_db->Put(rocksdb::WriteOptions(), stringPaddedKey, value); !status.ok())
            {
                throw std::runtime_error("Failed to re-insert element during key normalization: " + stringPaddedKey);
            }

            if (const auto status = m_db->Delete(rocksdb::WriteOptions(), keyString); !status.ok())
            {
                throw std::runtime_error("Failed to remove element during key normalization: " + stringPaddedKey);
            }
        }
    }

public:
    explicit RocksDBQueue(const std::string& connectorName)
    {
        // RocksDB initialization.
        // Read cache is used to cache the data read from the disk.
        m_readCache = rocksdb::NewLRUCache(16 * 1024 * 1024);
        rocksdb::BlockBasedTableOptions tableOptions;
        tableOptions.block_cache = m_readCache;

        // Write buffer manager is used to manage the memory used for writing data to the disk.
        m_writeManager = std::make_shared<rocksdb::WriteBufferManager>(128 * 1024 * 1024);

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

        options.write_buffer_size = 32 * 1024 * 1024;
        options.max_write_buffer_number = 4;
        options.max_background_jobs = 4;

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

        while (it->Valid())
        {
            auto stringKey = it->key().ToString();
            auto value = it->value().data();
            auto valueSize = it->value().size();
            auto key = std::stoull(stringKey);
            keyNormalization(key, stringKey, {value, valueSize});

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
    }

    void push(const T& data)
    {
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
        while (counter < elementsQuantity)
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
};

#endif // _ROCKSDB_QUEUE_HPP
