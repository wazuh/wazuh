/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROCKS_DB_SHARED_BUFFERS_HPP
#define _ROCKS_DB_SHARED_BUFFERS_HPP

#include <mutex>
#include <rocksdb/write_buffer_manager.h>

// Shared buffers manager for multiple RocksDBQueue instances
class RocksDBSharedBuffers
{
public:
    static RocksDBSharedBuffers& getInstance()
    {
        static RocksDBSharedBuffers instance;
        return instance;
    }

    static constexpr size_t SHARED_BUFFER_SIZE {128 * 1024 * 1024};    // 128MB
    static constexpr size_t SHARED_READ_CACHE_SIZE {32 * 1024 * 1024}; // 32MB

    std::shared_ptr<rocksdb::Cache> getReadCache()
    {
        std::lock_guard lock(m_mutex);
        if (!m_readCache)
        {
            m_readCache = rocksdb::NewLRUCache(SHARED_READ_CACHE_SIZE);
        }
        return m_readCache;
    }

    std::shared_ptr<rocksdb::WriteBufferManager> getWriteBufferManager()
    {
        std::lock_guard lock(m_mutex);

        if (!m_readCache)
        {
            m_readCache = rocksdb::NewLRUCache(SHARED_READ_CACHE_SIZE);
        }

        if (!m_writeBufferManager)
        {
            // Single shared write buffer manager for all instances with strict limit
            // Enable cost_to_cache to enforce stricter memory limits
            m_writeBufferManager = std::make_shared<rocksdb::WriteBufferManager>(
                SHARED_BUFFER_SIZE, // strict limit
                m_readCache,        // No cache (we have separate read cache)
                true                // allow_stall = true, stalls writes when limit exceeded
            );
        }
        return m_writeBufferManager;
    }

private:
    RocksDBSharedBuffers() = default;
    ~RocksDBSharedBuffers() = default;
    RocksDBSharedBuffers(const RocksDBSharedBuffers&) = delete;
    RocksDBSharedBuffers& operator=(const RocksDBSharedBuffers&) = delete;

    std::mutex m_mutex;
    std::shared_ptr<rocksdb::WriteBufferManager> m_writeBufferManager;
    std::shared_ptr<rocksdb::Cache> m_readCache;
};

#endif // _ROCKS_DB_SHARED_BUFFERS_HPP
