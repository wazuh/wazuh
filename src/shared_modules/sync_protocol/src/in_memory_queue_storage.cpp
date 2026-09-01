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

#include <chrono>
#include <thread>

namespace
{
    // Mirrors PersistentQueueStorage's own byte-budget constants exactly, so the two
    // backends behave identically from AgentSyncProtocol's point of view.
    constexpr size_t SYNC_BLOCK_ESTIMATED_OVERHEAD_BYTES = 8U * 1024U;
    constexpr size_t SYNC_ITEM_ESTIMATED_OVERHEAD_BYTES = 512U;
    constexpr unsigned int MAX_OVERSIZED_ATTEMPTS = 5U;

    /// @brief Maximum estimated total size (in bytes, using the same per-item estimate as
    ///        the sync byte budget above) of distinct (never-seen-before) ids this queue
    ///        will hold at once. Bounds RSS growth if the sync peer is unreachable for an
    ///        extended period: once full, a brand-new id is rejected (throws -- see the
    ///        throw site in applyCoalesceLogic below for why it must not silently no-op)
    ///        rather than evicting already-queued state. This value is a starting point,
    ///        not an authoritative figure -- there is no official sizing guidance for this
    ///        queue, so it should be revisited against real operational data. Tracking the
    ///        cap in bytes rather than row count avoids the previous mismatch where 10000
    ///        rows of small FIM checksums was negligible RSS but the same row count of
    ///        larger SCA/inventory payloads could be tens of MB.
    constexpr size_t MAX_QUEUE_BYTES = 8U * 1024U * 1024U;

    size_t estimateSerializedItemBytes(const PersistedData& data)
    {
        return data.id.size()
               + data.index.size()
               + data.data.size()
               + SYNC_ITEM_ESTIMATED_OVERHEAD_BYTES;
    }
} // namespace

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

    // A transient failure here is far more dangerous than it looks: giving up immediately
    // leaves the on-disk snapshot file untouched (deleteDatabase() below is only reached on
    // success), but m_rows starts empty regardless -- and the NEXT graceful shutdown's
    // saveToDisk() unconditionally overwrites that same on-disk file with whatever is in
    // m_rows at that point (PersistentQueueStorage::saveAll() deletes the old rows first),
    // permanently destroying the never-loaded backlog. Retrying here, mirroring saveToDisk()'s
    // own bounded retry, closes most of that window; a persistent failure still falls back to
    // "start empty" exactly as before, since there is nothing else this constructor can do.
    constexpr int MAX_LOAD_ATTEMPTS = 3;
    constexpr std::chrono::milliseconds RETRY_DELAY{100};

    for (int attempt = 1; attempt <= MAX_LOAD_ATTEMPTS; ++attempt)
    {
        try
        {
            PersistentQueueStorage onDiskSnapshot(m_dbPath, m_logger, m_fileSystemWrapper);

            for (auto& row : onDiskSnapshot.fetchAll())
            {
                addRow(std::move(row));
            }

            // The snapshot has been fully loaded into memory; remove it so a crash before
            // the next graceful shutdown correctly yields "no snapshot" rather than a stale
            // one.
            onDiskSnapshot.deleteDatabase();
            return;
        }
        // LCOV_EXCL_START
        catch (const std::exception& ex)
        {
            if (attempt == MAX_LOAD_ATTEMPTS)
            {
                m_logger(LOG_ERROR, std::string("InMemoryQueueStorage: Failed to load snapshot from disk after ") +
                         std::to_string(MAX_LOAD_ATTEMPTS) + " attempts, starting empty: " + ex.what());
                return;
            }

            m_logger(LOG_WARNING,
                     "InMemoryQueueStorage: Attempt " + std::to_string(attempt) + "/" +
                     std::to_string(MAX_LOAD_ATTEMPTS) +
                     " to load the on-disk snapshot failed, retrying: " + ex.what());
            std::this_thread::sleep_for(RETRY_DELAY);
        }

        // LCOV_EXCL_STOP
    }
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

    // This is the ONLY point where the entire in-memory backlog gets persisted -- a single
    // failed write here loses everything accumulated since the last graceful shutdown. A
    // short bounded retry covers transient failures (e.g. a momentary I/O hiccup) without
    // reintroducing continuous disk writes; a persistent failure (disk full, read-only
    // mount) still surfaces to the caller after the last attempt, as before.
    constexpr int MAX_SAVE_ATTEMPTS = 3;
    constexpr std::chrono::milliseconds RETRY_DELAY{100};

    for (int attempt = 1; attempt <= MAX_SAVE_ATTEMPTS; ++attempt)
    {
        try
        {
            PersistentQueueStorage snapshot(m_dbPath, m_logger, m_fileSystemWrapper);
            snapshot.saveAll(std::vector<QueueRow>(m_rows.begin(), m_rows.end()));
            return;
        }
        catch (const std::exception& ex)
        {
            if (attempt == MAX_SAVE_ATTEMPTS)
            {
                throw;
            }

            m_logger(LOG_WARNING,
                     "InMemoryQueueStorage: Attempt " + std::to_string(attempt) + "/" +
                     std::to_string(MAX_SAVE_ATTEMPTS) +
                     " to save the shutdown snapshot failed, retrying: " + ex.what());
            std::this_thread::sleep_for(RETRY_DELAY);
        }
    }
}

void InMemoryQueueStorage::addRow(QueueRow row)
{
    row.rowId = m_nextRowId++;

    // Capture the id and estimated size before the move below invalidates row's own copy.
    const std::string id = row.data.id;
    const size_t rowBytes = estimateSerializedItemBytes(row.data);
    m_rows.push_back(std::move(row));

    try
    {
        m_index[id] = std::prev(m_rows.end());
    }
    catch (...)
    {
        // The index insert failed (e.g. bad_alloc growing the hash table) after the row
        // was already appended -- roll back the append so m_rows and m_index cannot
        // desync into a state where the same id could be inserted twice.
        m_rows.pop_back();
        throw;
    }

    m_totalEstimatedBytes += rowBytes;
}

void InMemoryQueueStorage::applyCoalesceLogic(const PersistedData& newData)
{
    auto it = m_index.find(newData.id);

    if (it == m_index.end())
    {
        const size_t incomingBytes = estimateSerializedItemBytes(newData);

        if (m_totalEstimatedBytes + incomingBytes > MAX_QUEUE_BYTES)
        {
            // Throw rather than silently returning: a caller like syscheckd's full-table
            // recovery path (which clears the manager's index first, then re-persists every
            // row in a loop with no capacity check of its own) cannot tell a silent no-op
            // apart from success. Throwing lets PersistentQueue::submit() retain this item in
            // m_pendingRetry and retry it once room frees up, instead of permanently losing it
            // the moment the cap is hit -- turning "silently dropped forever" into "retried
            // until the queue has room," which is not a full fix (the caller still gets no
            // synchronous success/failure signal) but is a materially better failure mode.
            const std::string message = "InMemoryQueueStorage: Queue is at capacity (~" +
                                         std::to_string(m_totalEstimatedBytes) + " of " +
                                         std::to_string(MAX_QUEUE_BYTES) + " B); rejecting new item id=" +
                                         newData.id + ". The sync peer may be unreachable for an extended period.";
            m_logger(LOG_ERROR, message);
            throw std::runtime_error(message);
        }

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

    if (newData.operation == Operation::DELETE_ && oldCreateStatus == CreateStatus::NEW && oldSyncStatus == SyncStatus::PENDING)
    {
        m_totalEstimatedBytes -= estimateSerializedItemBytes(oldRow.data);
        m_rows.erase(it->second);
        m_index.erase(it);
        return;
    }

    CreateStatus newCreateStatus = oldCreateStatus;

    if (newData.operation == Operation::DELETE_)
    {
        newCreateStatus = (oldCreateStatus == CreateStatus::NEW) ? CreateStatus::NEW_DELETED : oldCreateStatus;
    }
    else if (oldCreateStatus == CreateStatus::NEW_DELETED)
    {
        newCreateStatus = CreateStatus::NEW;
    }

    m_totalEstimatedBytes -= estimateSerializedItemBytes(oldRow.data);

    oldRow.data.index = newData.index;
    oldRow.data.data = newData.data;
    oldRow.data.operation = newData.operation;
    oldRow.data.version = newData.version;
    oldRow.data.is_data_context = newData.is_data_context;
    oldRow.syncStatus = newSyncStatus;
    oldRow.createStatus = newCreateStatus;
    oldRow.operationSyncing = newOperationSyncing;

    m_totalEstimatedBytes += estimateSerializedItemBytes(oldRow.data);
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

std::vector<PersistedData> InMemoryQueueStorage::fetchAndMarkForSync(size_t maxBytes)
{
    std::vector<PersistedData> result;
    size_t estimatedBytes = SYNC_BLOCK_ESTIMATED_OVERHEAD_BYTES;

    for (auto it = m_rows.begin(); it != m_rows.end();)
    {
        if (it->syncStatus != SyncStatus::PENDING)
        {
            ++it;
            continue;
        }

        const size_t estimatedItemBytes = estimateSerializedItemBytes(it->data);

        if (maxBytes > 0 && estimatedBytes + estimatedItemBytes > maxBytes)
        {
            if (!result.empty())
            {
                // Normal budget exhaustion: stop before adding this item.
                break;
            }

            if (it->data.id == m_oversizedItemId)
            {
                ++m_oversizedItemAttempts;
            }
            else
            {
                m_oversizedItemId = it->data.id;
                m_oversizedItemAttempts = 1;
            }

            if (m_oversizedItemAttempts > MAX_OVERSIZED_ATTEMPTS)
            {
                // This item alone has exceeded the cap for MAX_OVERSIZED_ATTEMPTS
                // consecutive cycles: drop it instead of resending it forever, so it
                // cannot starve every item behind it.
                m_logger(LOG_ERROR,
                         "InMemoryQueueStorage: Dropping pending item (~" +
                         std::to_string(estimatedItemBytes) +
                         " B) after " + std::to_string(m_oversizedItemAttempts) +
                         " consecutive cycles alone over the byte cap (" +
                         std::to_string(maxBytes) + " B); it was blocking every item behind it.");
                m_totalEstimatedBytes -= estimateSerializedItemBytes(it->data);
                m_index.erase(it->data.id);
                it = m_rows.erase(it);
                m_oversizedItemId.clear();
                m_oversizedItemAttempts = 0;
                continue;
            }

            // First item already exceeds the cap. Enforcing the limit here would leave
            // it stuck in PENDING forever, so accept it once but warn.
            m_logger(LOG_WARNING,
                     "InMemoryQueueStorage: A single pending item (~" +
                     std::to_string(estimatedItemBytes) +
                     " B) exceeds the byte cap (" +
                     std::to_string(maxBytes) +
                     " B); sending it alone (attempt " +
                     std::to_string(m_oversizedItemAttempts) + "/" +
                     std::to_string(MAX_OVERSIZED_ATTEMPTS) +
                     "). Consider reducing individual item size.");
        }
        else if (it->data.id == m_oversizedItemId)
        {
            // No longer alone over the cap (e.g. coalesced smaller): clear its streak.
            m_oversizedItemId.clear();
            m_oversizedItemAttempts = 0;
        }

        estimatedBytes += estimatedItemBytes;
        result.push_back(it->data);
        it->syncStatus = SyncStatus::SYNCING;
        ++it;
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
            // NOTE: unlike PersistentQueueStorage (whose seq is the durable SQLite rowid,
            // stable across restarts), row.rowId here comes from m_nextRowId, which restarts
            // at 1 every process start -- including for rows just reloaded from a prior
            // snapshot in loadFromDisk(). No current caller relies on seq being stable across
            // restarts (fetchAndMarkForSync()'s own callers overwrite it per-batch anyway),
            // but this is a real, disclosed drift from the field's documented semantics that
            // a future or external consumer comparing seq values across restarts would need
            // to be aware of.
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
            m_totalEstimatedBytes -= estimateSerializedItemBytes(it->data);
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
            m_totalEstimatedBytes -= estimateSerializedItemBytes(it->data);
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
            m_totalEstimatedBytes -= estimateSerializedItemBytes(it->data);
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
            m_totalEstimatedBytes -= estimateSerializedItemBytes(it->data);
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
    m_totalEstimatedBytes = 0;

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
    m_totalEstimatedBytes = 0;

    for (const auto& row : rows)
    {
        addRow(row);
    }
}
