/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "in_memory_queue_storage.hpp"
#include "persistent_queue_storage.hpp"
#include "filesystem_wrapper.hpp"

InMemoryQueueStorage::InMemoryQueueStorage(const std::string& dbPath, LoggerFunc logger, std::shared_ptr<IFileSystemWrapper> fileSystemWrapper)
    : m_dbPath(dbPath),
      m_logger(std::move(logger)),
      m_fileSystemWrapper(fileSystemWrapper ? std::move(fileSystemWrapper) : std::make_shared<file_system::FileSystemWrapper>())
{
    if (!m_logger)
    {
        throw std::invalid_argument("Logger provided to InMemoryQueueStorage cannot be null.");
    }

    loadFromDisk();
}

InMemoryQueueStorage::~InMemoryQueueStorage()
{
    try
    {
        saveToDisk();
    }
    // LCOV_EXCL_START
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, std::string("InMemoryQueueStorage: Failed to save snapshot to disk: ") + ex.what());
    }

    // LCOV_EXCL_STOP
}

void InMemoryQueueStorage::loadFromDisk()
{
    if (!m_fileSystemWrapper->exists(m_dbPath))
    {
        return;
    }

    try
    {
        PersistentQueueStorage onDiskSnapshot(m_dbPath, m_logger, m_fileSystemWrapper);

        for (auto& row : onDiskSnapshot.fetchAll())
        {
            addRow(std::move(row));
        }

        // The snapshot has been fully loaded into memory; remove it so a crash before the
        // next graceful shutdown correctly yields "no snapshot" rather than a stale one.
        onDiskSnapshot.deleteDatabase();
    }
    // LCOV_EXCL_START
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, std::string("InMemoryQueueStorage: Failed to load snapshot from disk, starting empty: ") + ex.what());
    }

    // LCOV_EXCL_STOP
}

void InMemoryQueueStorage::saveToDisk()
{
    // Nothing pending: skip writing a snapshot altogether (there is also nothing to clean up,
    // since loadFromDisk()/deleteDatabase() already remove any on-disk file as soon as its
    // contents are absorbed into m_rows or discarded).
    if (m_rows.empty())
    {
        return;
    }

    PersistentQueueStorage snapshot(m_dbPath, m_logger, m_fileSystemWrapper);
    snapshot.saveAll(std::vector<QueueRow>(m_rows.begin(), m_rows.end()));
}

void InMemoryQueueStorage::addRow(QueueRow row)
{
    row.rowId = m_nextRowId++;
    m_rows.push_back(std::move(row));
    m_index[m_rows.back().data.id] = std::prev(m_rows.end());
}

void InMemoryQueueStorage::applyCoalesceLogic(const PersistedData& newData)
{
    auto it = m_index.find(newData.id);

    if (it == m_index.end())
    {
        QueueRow row;
        row.data = newData;
        row.syncStatus = SyncStatus::PENDING;
        row.createStatus = (newData.operation == Operation::CREATE) ? CreateStatus::NEW : CreateStatus::EXISTING;
        row.operationSyncing = Operation::NO_OP;
        addRow(std::move(row));
        return;
    }

    QueueRow& oldRow = *it->second;
    const Operation oldOperation = oldRow.data.operation;
    const SyncStatus oldSyncStatus = oldRow.syncStatus;
    const CreateStatus oldCreateStatus = oldRow.createStatus;
    const Operation oldOperationSyncing = oldRow.operationSyncing;

    Operation newOperationSyncing = Operation::NO_OP;

    if (oldSyncStatus != SyncStatus::PENDING)
    {
        newOperationSyncing = (oldOperationSyncing == Operation::NO_OP) ? oldOperation : oldOperationSyncing;
    }

    const SyncStatus newSyncStatus = (oldSyncStatus == SyncStatus::PENDING) ? SyncStatus::PENDING : SyncStatus::SYNCING_UPDATED;

    if (newData.operation == Operation::DELETE_)
    {
        if (oldCreateStatus == CreateStatus::NEW && oldSyncStatus == SyncStatus::PENDING)
        {
            m_rows.erase(it->second);
            m_index.erase(it);
            return;
        }

        const CreateStatus newCreateStatus = (oldCreateStatus == CreateStatus::NEW) ? CreateStatus::NEW_DELETED : oldCreateStatus;

        oldRow.data.index = newData.index;
        oldRow.data.data = newData.data;
        oldRow.data.operation = Operation::DELETE_;
        oldRow.data.version = newData.version;
        oldRow.data.is_data_context = newData.is_data_context;
        oldRow.syncStatus = newSyncStatus;
        oldRow.createStatus = newCreateStatus;
        oldRow.operationSyncing = newOperationSyncing;
    }
    else
    {
        const CreateStatus newCreateStatus = (oldCreateStatus == CreateStatus::NEW_DELETED) ? CreateStatus::NEW : oldCreateStatus;

        oldRow.data.index = newData.index;
        oldRow.data.data = newData.data;
        oldRow.data.operation = newData.operation;
        oldRow.data.version = newData.version;
        oldRow.data.is_data_context = newData.is_data_context;
        oldRow.syncStatus = newSyncStatus;
        oldRow.createStatus = newCreateStatus;
        oldRow.operationSyncing = newOperationSyncing;
    }
}

void InMemoryQueueStorage::submitOrCoalesce(const PersistedData& data)
{
    applyCoalesceLogic(data);
}

void InMemoryQueueStorage::submitBatch(const std::vector<PersistedData>& batch)
{
    for (const auto& item : batch)
    {
        applyCoalesceLogic(item);
    }
}

std::vector<PersistedData> InMemoryQueueStorage::fetchAndMarkForSync()
{
    std::vector<PersistedData> result;

    for (auto& row : m_rows)
    {
        if (row.syncStatus == SyncStatus::PENDING)
        {
            result.push_back(row.data);
            row.syncStatus = SyncStatus::SYNCING;
        }
    }

    return result;
}

std::vector<PersistedData> InMemoryQueueStorage::fetchPending(bool onlyDataValues)
{
    std::vector<PersistedData> result;

    for (const auto& row : m_rows)
    {
        if (row.syncStatus == SyncStatus::PENDING && (!onlyDataValues || !row.data.is_data_context))
        {
            PersistedData data = row.data;
            data.seq = row.rowId;
            result.push_back(std::move(data));
        }
    }

    if (m_logger)
    {
        m_logger(LOG_DEBUG, "InMemoryQueueStorage: Fetcheing " + std::to_string(result.size()) +
                 " pending datavalues items");
    }

    return result;
}

void InMemoryQueueStorage::removeAllSynced()
{
    for (auto it = m_rows.begin(); it != m_rows.end();)
    {
        const bool shouldDelete = (it->syncStatus == SyncStatus::SYNCING) ||
                                  (it->createStatus == CreateStatus::NEW_DELETED &&
                                   (it->operationSyncing == Operation::NO_OP || it->operationSyncing == Operation::DELETE_));

        if (shouldDelete)
        {
            m_index.erase(it->data.id);
            it = m_rows.erase(it);
        }
        else
        {
            ++it;
        }
    }

    for (auto& row : m_rows)
    {
        if (row.syncStatus == SyncStatus::SYNCING || row.syncStatus == SyncStatus::SYNCING_UPDATED)
        {
            row.syncStatus = SyncStatus::PENDING;
            row.createStatus = CreateStatus::EXISTING;
            row.operationSyncing = Operation::NO_OP;
        }
    }
}

void InMemoryQueueStorage::resetAllSyncing()
{
    for (auto& row : m_rows)
    {
        if (row.syncStatus == SyncStatus::SYNCING || row.syncStatus == SyncStatus::SYNCING_UPDATED)
        {
            row.syncStatus = SyncStatus::PENDING;
            row.operationSyncing = Operation::NO_OP;
        }
    }

    for (auto it = m_rows.begin(); it != m_rows.end();)
    {
        if (it->data.operation == Operation::DELETE_ && it->createStatus == CreateStatus::NEW_DELETED)
        {
            m_index.erase(it->data.id);
            it = m_rows.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

void InMemoryQueueStorage::removeByIndex(const std::string& index)
{
    for (auto it = m_rows.begin(); it != m_rows.end();)
    {
        if (it->data.index == index)
        {
            m_index.erase(it->data.id);
            it = m_rows.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

void InMemoryQueueStorage::removeAllDataContext()
{
    for (auto it = m_rows.begin(); it != m_rows.end();)
    {
        if (it->data.is_data_context)
        {
            m_index.erase(it->data.id);
            it = m_rows.erase(it);
        }
        else
        {
            ++it;
        }
    }

    if (m_logger)
    {
        m_logger(LOG_DEBUG, "InMemoryQueueStorage: Removed all DataContext items");
    }
}

void InMemoryQueueStorage::deleteDatabase()
{
    m_rows.clear();
    m_index.clear();

    try
    {
        if (m_fileSystemWrapper->exists(m_dbPath))
        {
            m_fileSystemWrapper->remove(m_dbPath);
            m_logger(LOG_DEBUG, std::string("InMemoryQueueStorage: Database file deleted: ") + m_dbPath);
        }
    }
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, std::string("InMemoryQueueStorage: Error deleting database: ") + ex.what());
        throw;
    }
}

std::vector<QueueRow> InMemoryQueueStorage::fetchAll()
{
    return std::vector<QueueRow>(m_rows.begin(), m_rows.end());
}

void InMemoryQueueStorage::saveAll(const std::vector<QueueRow>& rows)
{
    m_rows.clear();
    m_index.clear();

    for (const auto& row : rows)
    {
        addRow(row);
    }
}
