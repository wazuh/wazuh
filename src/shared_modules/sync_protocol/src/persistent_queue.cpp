/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "persistent_queue.hpp"
#include "in_memory_queue_storage.hpp"

PersistentQueue::PersistentQueue(const std::string& dbPath, LoggerFunc logger, std::shared_ptr<IPersistentQueueStorage> storage)
    : m_storage(storage ? std::move(storage) : std::make_shared<InMemoryQueueStorage>(dbPath, logger)),
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
}

PersistentQueue::~PersistentQueue() = default;

void PersistentQueue::submit(const std::string& id,
                             const std::string& index,
                             const std::string& data,
                             Operation operation,
                             uint64_t version,
                             bool isDataContext)
{
    std::lock_guard<std::mutex> storageLock(m_storageMutex);

    // Opportunistically retry anything that failed on a previous submit() before handling
    // the new item, so a transient storage failure does not silently and permanently lose
    // an event. This replaces the old buffer/flush-thread-based retry that existed when
    // submitBatch() on a background thread was the only write path -- with submit() now
    // writing synchronously, retrying on the next call is the equivalent, simpler guarantee.
    if (!m_pendingRetry.empty())
    {
        std::vector<PersistedData> stillPending;
        stillPending.reserve(m_pendingRetry.size());

        for (auto& pending : m_pendingRetry)
        {
            try
            {
                m_storage->submitOrCoalesce(pending);
            }
            catch (const std::exception& ex)
            {
                m_logger(LOG_WARNING, std::string("PersistentQueue: Retry of a previously failed item is still failing: ") + ex.what());
                stillPending.push_back(std::move(pending));
            }
        }

        m_pendingRetry = std::move(stillPending);
    }

    PersistedData newItem{0, id, index, data, operation, version, isDataContext};

    try
    {
        m_storage->submitOrCoalesce(newItem);
    }
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, std::string("PersistentQueue: Error submitting item to storage: ") + ex.what() + " (will retry on next submit())");
        m_pendingRetry.push_back(std::move(newItem));
    }
}

std::vector<PersistedData> PersistentQueue::fetchAndMarkForSync(size_t maxBytes)
{
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
