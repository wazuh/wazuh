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

    std::shared_ptr<rocksdb::WriteBufferManager> getWriteBufferManager()
    {
        std::lock_guard lock(m_mutex);
        if (!m_writeBufferManager)
        {
            // Single shared write buffer manager for all instances with strict limit
            // Enable cost_to_cache to enforce stricter memory limits
            m_writeBufferManager = std::make_shared<rocksdb::WriteBufferManager>(
                128 * 1024 * 1024, // 128MB strict limit
                nullptr,           // No cache (we have separate read cache)
                true               // allow_stall = true, stalls writes when limit exceeded
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
};

#endif // _ROCKS_DB_SHARED_BUFFERS_HPP
