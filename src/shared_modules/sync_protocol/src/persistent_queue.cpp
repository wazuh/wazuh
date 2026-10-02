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
    m_cv.notifyOne();

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
        m_cv.notifyOne();
    }
}

void PersistentQueue::flushLoop()
{
    while (true)
    {
        bool stopping = false;

        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.waitFor(lock, FLUSH_INTERVAL, [this]
            {
                return m_buffers[m_currentIdx].size() >= FLUSH_BATCH_SIZE || m_stop.load();
            });

            stopping = m_stop.load();
        }

        // Called with m_mutex released: flushActiveBuffer() takes m_storageMutex before m_mutex,
        // so holding m_mutex here would invert that order.
        if (!flushActiveBuffer() && stopping)
        {
            break;
        }
    }
}

bool PersistentQueue::flushActiveBuffer()
{
    // Early exit under m_mutex alone, so an idle background thread (or a shutdown) never waits on
    // the storage lock behind a long storage call only to find nothing to flush. It takes no other
    // lock, so it adds nothing to the lock order. The check under both locks below is the one the
    // swap relies on; this one only skips the common empty case.
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (m_buffers[m_currentIdx].empty())
        {
            return false;
        }
    }

    // Held across the swap, the write and the clear. Only the holder can swap, and it clears the
    // slot it took before releasing it, so no swap can hand producers a slot that another
    // flusher (the background thread or a sync) is still writing and is about to clear.
    std::lock_guard<std::mutex> storageLock(m_storageMutex);

    std::size_t flushIdx;
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (m_buffers[m_currentIdx].empty())
        {
            return false;
        }

        flushIdx = m_currentIdx;
        m_currentIdx ^= 1;
    }

    // Producers now write to the other slot and every other flusher is waiting on the storage
    // lock, so this slot is read and cleared without m_mutex.
    try
    {
        m_storage->submitBatch(m_buffers[flushIdx]);
        m_buffers[flushIdx].clear();
    }
    catch (const std::exception& ex)
    {
        // The items stay in their slot and are retried with whatever producers add to it once
        // it is the active slot again.
        m_logger(LOG_ERROR, std::string("PersistentQueue: Error flushing batch to storage: ") + ex.what());
    }

    return true;
}

std::vector<PersistedData> PersistentQueue::fetchAndMarkForSync(size_t maxBytes)
{
    flushActiveBuffer();

    try
    {
        std::lock_guard<std::mutex> storageLock(m_storageMutex);
        return m_storage->fetchAndMarkForSync(maxBytes);
    }
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, std::string("PersistentQueue: Error obtaining items for sync: ") + ex.what());
        throw;
    }
}

std::vector<PersistedData> PersistentQueue::fetchPendingItems(bool onlyDataValues)
{
    flushActiveBuffer();

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
