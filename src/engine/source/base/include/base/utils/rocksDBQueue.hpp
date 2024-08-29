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

#include "rocksdb/db.h"
#include "rocksdb/filter_policy.h"
#include "rocksdb/table.h"
#include <filesystem>
#include <stdexcept>
#include <string>

// RocksDB integration as queue
template<typename T, typename U = T>
class RocksDBQueue final
{
public:
    explicit RocksDBQueue(const std::string& connectorName)
    {
        // RocksDB initialization.
        // Read cache is used to cache the data read from the disk.
        m_readCache = rocksdb::NewLRUCache(16 * 1024 * 1024);
        rocksdb::BlockBasedTableOptions tableOptions;
        tableOptions.block_cache = m_readCache;

        // Write buffer manager is used to manage the memory used for writing data to the disk.
        m_writeManager = std::make_shared<rocksdb::WriteBufferManager>(64 * 1024 * 1024);

        rocksdb::Options options;
        options.table_factory.reset(NewBlockBasedTableFactory(tableOptions));
        options.create_if_missing = true;
        options.keep_log_file_num = 1;
        options.info_log_level = rocksdb::InfoLogLevel::FATAL_LEVEL;
        options.max_open_files = 64;
        options.write_buffer_manager = m_writeManager;
        options.num_levels = 4;

        options.write_buffer_size = 32 * 1024 * 1024;
        options.max_write_buffer_number = 2;

        rocksdb::DB* db;

        // Create directories recursively if they do not exist
        std::filesystem::create_directories(std::filesystem::path(connectorName));

        if (const auto status = rocksdb::DB::Open(options, connectorName, &db); !status.ok())
        {
            throw std::runtime_error("Failed to open RocksDB database. Reason: " + std::string {status.getState()});
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
            auto key = std::stoull(it->key().ToString());
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
        ++m_last;
        if (const auto status = m_db->Put(rocksdb::WriteOptions(), std::to_string(m_last), data); !status.ok())
        {
            throw std::runtime_error("Failed to enqueue element");
        }
        ++m_size;
    }

    void pop()
    {
        // RocksDB dequeue element.
        if (!m_db->Delete(rocksdb::WriteOptions(), std::to_string(m_first)).ok())
        {
            throw std::runtime_error("Failed to dequeue element, can't delete it");
        }

        ++m_first;
        --m_size;

        if (m_size == 0)
        {
            m_first = 1;
            m_last = 0;
        }
    }

    uint64_t size() const { return m_size; }

    bool empty() const { return m_size == 0; }

    U front() const
    {
        U value;
        if (!m_db->Get(rocksdb::ReadOptions(), m_db->DefaultColumnFamily(), std::to_string(m_first), &value).ok())
        {
            throw std::runtime_error("Failed to get front element");
        }

        return value;
    }

    U at(const uint64_t index) const
    {
        if (index >= m_size)
        {
            throw std::out_of_range("Index out of range");
        }

        U value;
        if (!m_db->Get(rocksdb::ReadOptions(), m_db->DefaultColumnFamily(), std::to_string(m_first + index), &value)
                 .ok())
        {
            throw std::runtime_error("Failed to get element at index");
        }

        return value;
    }

private:
    std::unique_ptr<rocksdb::DB> m_db;
    std::shared_ptr<rocksdb::Cache> m_readCache;
    std::shared_ptr<rocksdb::WriteBufferManager> m_writeManager;
    uint64_t m_size;
    uint64_t m_first;
    uint64_t m_last;
};

#endif // _ROCKSDB_QUEUE_HPP
