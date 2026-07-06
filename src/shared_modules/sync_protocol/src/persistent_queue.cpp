/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "persistent_queue.hpp"
#include "persistent_queue_storage.hpp"

#include <algorithm>

PersistentQueue::PersistentQueue(const std::string& dbPath, LoggerFunc logger, std::shared_ptr<IPersistentQueueStorage> storage)
    : m_storage(storage ? std::move(storage) : std::make_shared<PersistentQueueStorage>(dbPath, logger)),
      m_logger(std::move(logger))
{
    if (!m_logger)
    {
        throw std::invalid_argument("Logger provided to PersistentQueue cannot be null.");
    }

    try
    {
        m_storage->resetAllSyncing();
    }
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, std::string("PersistentQueue: Error on DB: ") + ex.what());
        throw;
    }

    m_buffers[0].reserve(FLUSH_BATCH_SIZE);
    m_buffers[1].reserve(FLUSH_BATCH_SIZE);
    m_flushThread = std::thread(&PersistentQueue::flushLoop, this);
}

PersistentQueue::~PersistentQueue()
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stop = true;
    }
    m_cv.notify_one();

    if (m_flushThread.joinable())
    {
        m_flushThread.join();
    }
}

void PersistentQueue::submit(const std::string& id,
                             const std::string& index,
                             const std::string& data,
                             Operation operation,
                             uint64_t version,
                             bool isDataContext)
{
    bool shouldNotify = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_buffers[m_currentIdx].push_back(PersistedData{0, id, index, data, operation, version, isDataContext});
        shouldNotify = (m_buffers[m_currentIdx].size() >= FLUSH_BATCH_SIZE);
    }

    if (shouldNotify)
    {
        m_cv.notify_one();
    }
}

void PersistentQueue::flushLoop()
{
    while (true)
    {
        std::size_t flushIdx;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait_for(lock, FLUSH_INTERVAL, [this]
            {
                return m_buffers[m_currentIdx].size() >= FLUSH_BATCH_SIZE || m_stop.load();
            });

            flushIdx = m_currentIdx;
            m_currentIdx ^= 1;
        }

        if (!m_buffers[flushIdx].empty())
        {
            flushBuffer(m_buffers[flushIdx]);
            m_buffers[flushIdx].clear();
        }

        if (m_stop.load())
        {
            break;
        }
    }
}

void PersistentQueue::flushBuffer(const std::vector<PersistedData>& batch)
{
    try
    {
        std::lock_guard<std::mutex> storageLock(m_storageMutex);
        m_storage->submitBatch(batch);
    }
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, std::string("PersistentQueue: Error flushing batch to storage: ") + ex.what());
    }
}

void PersistentQueue::flushPendingBuffer()
{
    std::size_t flushIdx;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_buffers[m_currentIdx].empty())
        {
            return;
        }
        flushIdx = m_currentIdx;
        m_currentIdx ^= 1;
    }

    flushBuffer(m_buffers[flushIdx]);
    m_buffers[flushIdx].clear();
}

std::vector<PersistedData> PersistentQueue::fetchAndMarkForSync()
{
    flushPendingBuffer();

    try
    {
        std::lock_guard<std::mutex> storageLock(m_storageMutex);
        return m_storage->fetchAndMarkForSync();
    }
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, std::string("PersistentQueue: Error obtaining items for sync: ") + ex.what());
        throw;
    }
}

std::vector<PersistedData> PersistentQueue::fetchPendingItems(bool onlyDataValues)
{
    flushPendingBuffer();

    try
    {
        std::lock_guard<std::mutex> storageLock(m_storageMutex);
        return m_storage->fetchPending(onlyDataValues);
    }
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, std::string("PersistentQueue: Error fetching pending items: ") + ex.what());
        throw;
    }
}

void PersistentQueue::clearSyncedItems()
{
    try
    {
        std::lock_guard<std::mutex> storageLock(m_storageMutex);
        m_storage->removeAllSynced();
    }
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, std::string("PersistentQueue: Error clearing synchronized items: ") + ex.what());
        throw;
    }
}

void PersistentQueue::resetSyncingItems()
{
    try
    {
        std::lock_guard<std::mutex> storageLock(m_storageMutex);
        m_storage->resetAllSyncing();
    }
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, std::string("PersistentQueue: Error resetting items: ") + ex.what());
        throw;
    }
}

void PersistentQueue::clearItemsByIndex(const std::string& index)
{
    try
    {
        std::lock_guard<std::mutex> storageLock(m_storageMutex);
        m_storage->removeByIndex(index);
    }
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, std::string("PersistentQueue: Error clearing items by index: ") + ex.what());
        throw;
    }
}

void PersistentQueue::clearAllDataContext()
{
    try
    {
        std::lock_guard<std::mutex> storageLock(m_storageMutex);
        m_storage->removeAllDataContext();
    }
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, std::string("PersistentQueue: Error clearing DataContext items: ") + ex.what());
        throw;
    }
}

void PersistentQueue::deleteDatabase()
{
    try
    {
        std::lock_guard<std::mutex> storageLock(m_storageMutex);
        m_storage->deleteDatabase();
    }
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, std::string("PersistentQueue: Error deleting database: ") + ex.what());
        throw;
    }
}
