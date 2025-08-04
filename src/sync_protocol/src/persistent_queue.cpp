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

PersistentQueue::PersistentQueue(std::shared_ptr<IPersistentQueueStorage> storage)
    : m_storage(storage ? std::move(storage) : std::make_shared<PersistentQueueStorage>())
{
    try
    {
        m_storage->resetAllSyncing();
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[PersistentQueue] Error on DB: " << ex.what() << std::endl;
        throw;
    }
}

PersistentQueue::~PersistentQueue() = default;

void PersistentQueue::submit(const std::string& id,
                               const std::string& index,
                               const std::string& data,
                               Operation operation)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    PersistedData msg{0, id, index, data, operation};

    try
    {
        m_storage->submitOrCoalesce(msg);
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[PersistentQueue] Error persisting message: " << ex.what() << std::endl;
        throw;
    }
}

std::vector<PersistedData> PersistentQueue::fetchAndMarkForSync()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_storage->fetchAndMarkForSync();
}

void PersistentQueue::clearSyncedItems()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_storage->removeAllSynced();
}

void PersistentQueue::resetSyncingItems()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_storage->resetAllSyncing();
}
