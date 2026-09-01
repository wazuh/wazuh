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

namespace
{
    /// @brief Maximum number of distinct ids this queue will hold in the failed-item retry
    ///        list at once. Bounds memory growth if the storage backend keeps failing (e.g.
    ///        sustained memory pressure) -- once full, a brand-new failing id is dropped
    ///        (logged) rather than retained, since retaining more under exactly the condition
    ///        that is already causing failures would make things worse, not better. An id
    ///        already present is always updated in place regardless of this cap, since that
    ///        never grows the map.
    constexpr size_t MAX_PENDING_RETRY_ITEMS = 1000U;
} // namespace

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

PersistentQueue::~PersistentQueue()
{
    // Best-effort final drain: give anything still stuck in m_pendingRetry one last chance
    // to actually land in m_storage before it's destroyed. Without this, an item that failed
    // and was never retried again by a later submit()/fetchAndMarkForSync()/fetchPendingItems()
    // call would be silently absent from InMemoryQueueStorage's shutdown snapshot -- lost even
    // on a clean, graceful shutdown, not just a crash. Any failure here is logged and swallowed
    // (there is no later point left to retry from), which is an accepted, disclosed loss on top
    // of the already-accepted "ungraceful termination loses unsaved state" trade-off.
    for (auto& [id, pending] : m_pendingRetry)
    {
        try
        {
            m_storage->submitOrCoalesce(pending);
        }
        // LCOV_EXCL_START
        catch (const std::exception& ex)
        {
            m_logger(LOG_ERROR, std::string("PersistentQueue: A previously failed item is still failing on final shutdown drain, it will be lost: ") + ex.what());
        }

        // LCOV_EXCL_STOP
    }
}

void PersistentQueue::drainPendingRetryLocked()
{
    // Caller must already hold m_storageMutex.
    if (m_pendingRetry.empty())
    {
        return;
    }

    for (auto it = m_pendingRetry.begin(); it != m_pendingRetry.end();)
    {
        try
        {
            m_storage->submitOrCoalesce(it->second);
            it = m_pendingRetry.erase(it);
        }
        catch (const std::exception& ex)
        {
            m_logger(LOG_WARNING, std::string("PersistentQueue: Retry of a previously failed item is still failing: ") + ex.what());
            ++it;
        }
    }
}

void PersistentQueue::submit(const std::string& id,
                             const std::string& index,
                             const std::string& data,
                             Operation operation,
                             uint64_t version,
                             bool isDataContext)
{
    std::lock_guard<std::mutex> storageLock(m_storageMutex);

    // Opportunistically retry anything that failed previously before handling the new item,
    // so a transient storage failure does not silently and permanently lose an event. This
    // replaces the old buffer/flush-thread-based retry that existed when submitBatch() on a
    // background thread was the only write path -- with submit() now writing synchronously,
    // retrying on the next call is the equivalent, simpler guarantee.
    drainPendingRetryLocked();

    PersistedData newItem{0, id, index, data, operation, version, isDataContext};

    try
    {
        m_storage->submitOrCoalesce(newItem);
    }
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, std::string("PersistentQueue: Error submitting item to storage: ") + ex.what() + " (will retry on next call)");

        // An id already pending retry is always updated in place (never grows the map);
        // only a brand-new failing id is subject to the capacity check below.
        if (m_pendingRetry.find(id) == m_pendingRetry.end() && m_pendingRetry.size() >= MAX_PENDING_RETRY_ITEMS)
        {
            m_logger(LOG_ERROR,
                     "PersistentQueue: Retry list is at capacity (" + std::to_string(MAX_PENDING_RETRY_ITEMS) +
                     " ids); dropping failed item id=" + id + " instead of retaining it for retry.");
            return;
        }

        m_pendingRetry[id] = std::move(newItem);
    }
}

std::vector<PersistedData> PersistentQueue::fetchAndMarkForSync(size_t maxBytes)
{
    try
    {
        std::lock_guard<std::mutex> storageLock(m_storageMutex);

        // Also drain here: AgentSyncProtocol's periodic sync cycle calls this on its own
        // timer, independently of submit() -- without this, an item that failed and was
        // never followed by another submit() call would sit in m_pendingRetry forever,
        // invisible to every sync cycle even though the queue is otherwise being read
        // regularly.
        drainPendingRetryLocked();
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
        drainPendingRetryLocked();
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
