/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "persistent_queue_storage.hpp"
#include "mock_filesystem_wrapper.hpp"
#include "sqlite3Wrapper.hpp"
#include <memory>
#include <filesystem>
#include <thread>
#include <chrono>

struct QueueScenario
{
    std::string name;
    std::vector<PersistedData> initial;
    bool doFetchAndSync;
    std::vector<PersistedData> eventsInSync;
    bool removeSynced;
    bool resetSyncing;
    size_t expectedRows;
    Operation expectedOp;
};

inline void PrintTo(const QueueScenario& q, std::ostream* os)
{
    *os << q.name;
}

class PersistentQueueFullParamTest :
    public ::testing::TestWithParam<QueueScenario>
{
    protected:
        std::unique_ptr<PersistentQueueStorage> storage;

        LoggerFunc testLogger;

        void SetUp() override
        {
            testLogger = [](modules_log_level_t /*level*/, const std::string& /*msg*/)
            {
            };

            storage = std::make_unique<PersistentQueueStorage>(":memory:", testLogger);
        }

        void TearDown() override
        {
            storage.reset();
        }
};

TEST_P(PersistentQueueFullParamTest, HandlesSubmitFetchRemoveResetCorrectly)
{
    auto param = GetParam();

    // 1. Init DB
    for (auto& ev : param.initial)
    {
        storage->submitOrCoalesce(ev);
    }

    // 2. Simulate fetchAndMarkForSync
    if (param.doFetchAndSync)
    {
        storage->fetchAndMarkForSync();

        // 3. Events during a sincronization
        for (auto& evs : param.eventsInSync)
        {
            storage->submitOrCoalesce(evs);
        }
    }

    // 4. Simulate removeAllSynced
    if (param.removeSynced)
    {
        storage->removeAllSynced();
    }

    // 5. Simulate resetAllSyncing
    if (param.resetSyncing)
    {
        storage->resetAllSyncing();
    }

    // 6. Verify final status
    auto rows = storage->fetchAndMarkForSync();
    EXPECT_EQ(rows.size(), param.expectedRows);

    if (!rows.empty())
    {
        EXPECT_EQ(rows[0].operation, param.expectedOp);
    }
}

INSTANTIATE_TEST_SUITE_P(
    FullQueueCases,
    PersistentQueueFullParamTest,
    ::testing::Values(
        // 1. CREATE
        QueueScenario
{
    "Case 1",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0} },
    false, {}, false, false,
    1, Operation::CREATE
},
// 2. CREATE + MODIFY no sync -> MODIFY
QueueScenario
{
    "Case 2",
    {
        PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0},
        PersistedData{0, "id1", "idx2", "{}", Operation::MODIFY, 0}
    },
    false, {}, false, false,
    1, Operation::MODIFY
},
// 3. CREATE + DELETE no sync -> row deleted
QueueScenario
{
    "Case 3",
    {
        PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0},
        PersistedData{0, "id1", "idx", "{}", Operation::DELETE_, 0}
    },
    false, {}, false, false,
    0, Operation::CREATE
},
// 4. MODIFY + DELETE no sync -> DELETE
QueueScenario
{
    "Case 4",
    {
        PersistedData{0, "id1", "idx", "{}", Operation::MODIFY, 0},
        PersistedData{0, "id1", "idx", "{}", Operation::DELETE_, 0}
    },
    false, {}, false, false,
    1, Operation::DELETE_
},
// 5. DELETE
QueueScenario
{
    "Case 5",
    { PersistedData{0, "id1", "idx", "{}", Operation::DELETE_, 0} },
    false, {}, false, false,
    1, Operation::DELETE_
},
// 6. CREATE + Sync + MODIFY during  sync + sync success -> MODIFY
QueueScenario
{
    "Case 6",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0} },
    true,
    { PersistedData{0, "id1", "idx2", "{}", Operation::MODIFY, 0} },
    true, false,
    1, Operation::MODIFY
},
// 7. CREATE + Sync + DELETE during  sync + sync success -> DELETE
QueueScenario
{
    "Case 7",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0} },
    true,
    { PersistedData{0, "id1", "idx", "{}", Operation::DELETE_, 0} },
    true, false,
    1, Operation::DELETE_
},
// 8. CREATE + Sync + DELETE during  sync + sync fail -> row deleted
QueueScenario
{
    "Case 8",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0} },
    true,
    { PersistedData{0, "id1", "idx", "{}", Operation::DELETE_, 0} },
    false, true,
    0, Operation::DELETE_
},
// 9. CREATE + Sync + MODIFY during  sync + fail -> MODIFY
QueueScenario
{
    "Case 9",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0} },
    true,
    { PersistedData{0, "id1", "idx2", "{}", Operation::MODIFY, 0} },
    false, true,
    1, Operation::MODIFY
},
// 10. DELETE + MODIFY -> MODIFY
QueueScenario
{
    "Case 10",
    {
        PersistedData{0, "id1", "idx", "{}", Operation::DELETE_, 0},
        PersistedData{0, "id1", "idx2", "{}", Operation::MODIFY, 0}
    },
    false, {}, false, false,
    1, Operation::MODIFY
},
// 11. Sync
QueueScenario
{
    "Case 11",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0} },
    true, {}, true, false,
    0, Operation::CREATE
},
// 12. Two MODIFY -> MODIFY
QueueScenario
{
    "Case 12",
    {
        PersistedData{0, "id1", "idx", "{}", Operation::MODIFY, 0},
        PersistedData{0, "id1", "idx2", "{}", Operation::MODIFY, 0},
    },
    false, {}, false, false,
    1, Operation::MODIFY
},
// 13. Two IDs
QueueScenario
{
    "Case 13",
    {
        PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0},
        PersistedData{0, "id2", "idx", "{}", Operation::MODIFY, 0}
    },
    false, {}, false, false,
    2, Operation::CREATE
},
// 14. MODIFY + Sync + DELETE + CREATE + DELETE during sync + sync fail -> DELETE
QueueScenario
{
    "Case 14",
    { PersistedData{0, "id1", "idx", "{}", Operation::MODIFY, 0} },
    true,
    {
        PersistedData{0, "id1", "idx", "{}", Operation::DELETE_, 0},
        PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0},
        PersistedData{0, "id1", "idx", "{}", Operation::DELETE_, 0}
    },
    false, true,
    1, Operation::DELETE_
},
// 15. CREATE -> DELETE -> CREATE -> CREATE
QueueScenario
{
    "Case 15",
    {
        PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0},
        PersistedData{0, "id1", "idx", "{}", Operation::DELETE_, 0},
        PersistedData{0, "id1", "idx2", "{}", Operation::CREATE, 0}
    },
    false, {}, false, false,
    1, Operation::CREATE
},
// 16. CREATE + Sync + MODIFY + DELETE + MODIFY during sync + sync success -> MODIFY
QueueScenario
{
    "Case 16",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0} },
    true,
    {
        PersistedData{0, "id1", "idx2", "{}", Operation::MODIFY, 0},
        PersistedData{0, "id1", "idx", "{}", Operation::DELETE_, 0},
        PersistedData{0, "id1", "idx3", "{}", Operation::MODIFY, 0}
    },
    true, false,
    1, Operation::MODIFY
},
// 17. CREATE + Sync + DELETE + CREATE during sync + sync fail -> CREATE
QueueScenario
{
    "Case 17",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0} },
    true,
    {
        PersistedData{0, "id1", "idx", "{}", Operation::DELETE_, 0},
        PersistedData{0, "id1", "idx2", "{}", Operation::CREATE, 0}
    },
    false, true,
    1, Operation::CREATE
}
    )
);

class PersistentQueueStorageTest : public ::testing::Test
{
    protected:
        std::unique_ptr<PersistentQueueStorage> storage;
        LoggerFunc testLogger;

        void SetUp() override
        {
            testLogger = [](modules_log_level_t /*level*/, const std::string& /*msg*/)
            {
            };

            storage = std::make_unique<PersistentQueueStorage>(":memory:", testLogger);
        }

        void TearDown() override
        {
            storage.reset();
        }
};

TEST_F(PersistentQueueStorageTest, RemoveByIndexDeletesOnlySpecifiedIndex)
{
    // Insert items with different indices
    storage->submitOrCoalesce(PersistedData{0, "id1", "index1", "{}", Operation::CREATE, 0});
    storage->submitOrCoalesce(PersistedData{0, "id2", "index2", "{}", Operation::CREATE, 0});
    storage->submitOrCoalesce(PersistedData{0, "id3", "index1", "{}", Operation::MODIFY, 0});
    storage->submitOrCoalesce(PersistedData{0, "id4", "index3", "{}", Operation::CREATE, 0});

    // Verify all items are present
    auto allItems = storage->fetchAndMarkForSync();
    EXPECT_EQ(allItems.size(), static_cast<size_t>(4));

    // Reset status to pending for next operations
    storage->resetAllSyncing();

    // Remove all items with "index1"
    storage->removeByIndex("index1");

    // Verify only items with "index1" were removed
    auto remainingItems = storage->fetchAndMarkForSync();
    EXPECT_EQ(remainingItems.size(), static_cast<size_t>(2));

    // Verify the remaining items don't have "index1"
    for (const auto& item : remainingItems)
    {
        EXPECT_NE(item.index, "index1");
    }
}

TEST_F(PersistentQueueStorageTest, RemoveByIndexHandlesNonExistentIndex)
{
    // Insert some items
    storage->submitOrCoalesce(PersistedData{0, "id1", "index1", "{}", Operation::CREATE, 1});
    storage->submitOrCoalesce(PersistedData{0, "id2", "index2", "{}", Operation::CREATE, 1});

    // Try to remove items with non-existent index (should not throw)
    EXPECT_NO_THROW(storage->removeByIndex("non_existent_index"));

    // Verify original items are still present
    auto allItems = storage->fetchAndMarkForSync();
    EXPECT_EQ(allItems.size(), static_cast<size_t>(2));
}

TEST_F(PersistentQueueStorageTest, RemoveByIndexHandlesEmptyDatabase)
{
    // Try to remove from empty database (should not throw)
    EXPECT_NO_THROW(storage->removeByIndex("any_index"));

    // Verify database is still empty
    auto allItems = storage->fetchAndMarkForSync();
    EXPECT_EQ(allItems.size(), static_cast<size_t>(0));
}

TEST_F(PersistentQueueStorageTest, RemoveByIndexDeletesItemsInAnyStatus)
{
    // Insert items and mark some as syncing
    storage->submitOrCoalesce(PersistedData{0, "id1", "index1", "{}", Operation::CREATE, 1});
    storage->submitOrCoalesce(PersistedData{0, "id2", "index1", "{}", Operation::MODIFY, 1});
    storage->submitOrCoalesce(PersistedData{0, "id3", "index2", "{}", Operation::CREATE, 1});

    // Mark items as syncing
    storage->fetchAndMarkForSync();

    // Update an item during sync (will be SYNCING_UPDATED)
    storage->submitOrCoalesce(PersistedData{0, "id1", "index1", "{updated}", Operation::MODIFY, 1});

    // Remove all items with "index1" regardless of status
    storage->removeByIndex("index1");

    // Reset and verify only index2 item remains
    storage->resetAllSyncing();
    auto remainingItems = storage->fetchAndMarkForSync();
    EXPECT_EQ(remainingItems.size(), static_cast<size_t>(1));
    EXPECT_EQ(remainingItems[0].id, "id3");
    EXPECT_EQ(remainingItems[0].index, "index2");
}

TEST_F(PersistentQueueStorageTest, FetchAndMarkForSyncByteBudgetSelectsPrefixOnly)
{
    storage->submitOrCoalesce(PersistedData{0, "id1", "index1", "payload1", Operation::CREATE, 1});
    storage->submitOrCoalesce(PersistedData{0, "id2", "index1", "payload2", Operation::CREATE, 1});
    storage->submitOrCoalesce(PersistedData{0, "id3", "index1", "payload3", Operation::CREATE, 1});

    const auto firstBlock = storage->fetchAndMarkForSync(1);
    ASSERT_EQ(firstBlock.size(), static_cast<size_t>(1));
    EXPECT_EQ(firstBlock[0].id, "id1");

    storage->removeAllSynced();

    const auto secondBlock = storage->fetchAndMarkForSync(1);
    ASSERT_EQ(secondBlock.size(), static_cast<size_t>(1));
    EXPECT_EQ(secondBlock[0].id, "id2");
}

// An oversized single item (bigger than the byte cap) must still be returned so
// the queue does not get stuck, BUT the implementation must emit a LOG_WARNING
// rather than silently swallowing the violation.
TEST_F(PersistentQueueStorageTest, FetchAndMarkForSyncByteBudgetAlwaysReturnsAtLeastOneItem)
{
    // Use a fresh storage instance with a capturing logger.
    bool warnEmitted = false;
    LoggerFunc capturingLogger = [&warnEmitted](modules_log_level_t level, const std::string & msg)
    {
        if (level == LOG_WARNING && msg.find("exceeds") != std::string::npos)
        {
            warnEmitted = true;
        }
    };
    auto capStorage = std::make_unique<PersistentQueueStorage>(":memory:", capturingLogger);

    capStorage->submitOrCoalesce(PersistedData{0, "id1", "index1", "payload1", Operation::CREATE, 1});

    // Budget of 1 byte � the item is far larger than that.
    const auto block = capStorage->fetchAndMarkForSync(1);
    ASSERT_EQ(block.size(), static_cast<size_t>(1));
    EXPECT_EQ(block[0].id, "id1");
    EXPECT_TRUE(warnEmitted) << "Expected LOG_WARNING when a single item exceeds the byte cap";
}

// A single item that keeps exceeding the byte cap across consecutive cycles (e.g.
// the manager keeps rejecting it with a real 413) must not block the queue behind
// it forever: past MAX_OVERSIZED_ATTEMPTS (5) cycles it is dropped instead of
// resent, freeing up whatever was stuck behind it.
TEST_F(PersistentQueueStorageTest, FetchAndMarkForSyncDropsPersistentlyOversizedItemAfterMaxAttempts)
{
    int errorCount = 0;
    LoggerFunc capturingLogger = [&errorCount](modules_log_level_t level, const std::string & msg)
    {
        if (level == LOG_ERROR && msg.find("Dropping") != std::string::npos)
        {
            ++errorCount;
        }
    };
    auto capStorage = std::make_unique<PersistentQueueStorage>(":memory:", capturingLogger);

    capStorage->submitOrCoalesce(PersistedData{0, "stuck_id", "index1", "payload1", Operation::CREATE, 1});
    capStorage->submitOrCoalesce(PersistedData{0, "id2", "index1", "payload2", Operation::CREATE, 1});

    // Simulate consecutive failed sync cycles: each one selects the oversized item
    // alone, then the caller resets it back to PENDING (as agent_sync_protocol does
    // on a rejected/failed session) so it is reselected next cycle.
    for (int cycle = 0; cycle < 5; ++cycle)
    {
        const auto block = capStorage->fetchAndMarkForSync(1);
        ASSERT_EQ(block.size(), static_cast<size_t>(1));
        EXPECT_EQ(block[0].id, "stuck_id");
        capStorage->resetAllSyncing();
    }

    EXPECT_EQ(errorCount, 0) << "Should not drop before exceeding MAX_OVERSIZED_ATTEMPTS";

    // One more cycle crosses the threshold: the item is dropped, and the second
    // item (previously starved behind it) is now free to be selected.
    const auto finalBlock = capStorage->fetchAndMarkForSync(1);
    EXPECT_GE(errorCount, 1) << "Expected LOG_ERROR when the item is finally dropped";
    ASSERT_EQ(finalBlock.size(), static_cast<size_t>(1));
    EXPECT_EQ(finalBlock[0].id, "id2");

    capStorage->resetAllSyncing();

    // stuck_id must be gone for good; only id2 remains pending.
    const auto afterDrop = capStorage->fetchAndMarkForSync(1000);
    ASSERT_EQ(afterDrop.size(), static_cast<size_t>(1));
    EXPECT_EQ(afterDrop[0].id, "id2");
}

TEST_F(PersistentQueueStorageTest, FetchAndMarkForSyncWithoutByteBudgetReturnsAllPendingRows)
{
    storage->submitOrCoalesce(PersistedData{0, "id1", "index1", "payload1", Operation::CREATE, 1});
    storage->submitOrCoalesce(PersistedData{0, "id2", "index1", "payload2", Operation::MODIFY, 1});
    storage->submitOrCoalesce(PersistedData{0, "id3", "index1", "payload3", Operation::DELETE_, 1});

    const auto rows = storage->fetchAndMarkForSync(0);
    ASSERT_EQ(rows.size(), static_cast<size_t>(3));
    EXPECT_EQ(rows[0].id, "id1");
    EXPECT_EQ(rows[1].id, "id2");
    EXPECT_EQ(rows[2].id, "id3");
}

// Test class for testing deleteDatabase method with mock filesystem wrapper
class PersistentQueueStorageDeleteDatabaseTest : public ::testing::Test
{
    protected:
        std::shared_ptr<MockFileSystemWrapper> mockFileSystemWrapper;
        std::unique_ptr<PersistentQueueStorage> storage;
        LoggerFunc testLogger;

        void SetUp() override
        {
            mockFileSystemWrapper = std::make_shared<MockFileSystemWrapper>();

            testLogger = [](modules_log_level_t /*level*/, const std::string& /*msg*/)
            {
                // Capture log messages for testing if needed
            };

            storage = std::make_unique<PersistentQueueStorage>(":memory:", testLogger, mockFileSystemWrapper);
        }

        void TearDown() override
        {
            storage.reset();
            mockFileSystemWrapper.reset();
        }
};

TEST_F(PersistentQueueStorageDeleteDatabaseTest, DeleteDatabaseWhenFileExists)
{
    using ::testing::Return;
    using ::testing::_;

    // Mock that file exists and removal succeeds
    EXPECT_CALL(*mockFileSystemWrapper, exists(_))
    .WillOnce(Return(true));
    EXPECT_CALL(*mockFileSystemWrapper, remove(_))
    .WillOnce(Return(true));

    // Call deleteDatabase - should not throw
    EXPECT_NO_THROW(storage->deleteDatabase());
}

TEST_F(PersistentQueueStorageDeleteDatabaseTest, DeleteDatabaseWhenFileDoesNotExist)
{
    using ::testing::Return;
    using ::testing::_;

    // Mock that file does not exist
    EXPECT_CALL(*mockFileSystemWrapper, exists(_))
    .WillOnce(Return(false));
    // remove should not be called when file doesn't exist
    EXPECT_CALL(*mockFileSystemWrapper, remove(_))
    .Times(0);

    // Call deleteDatabase - should not throw and should log warning
    EXPECT_NO_THROW(storage->deleteDatabase());
}

TEST_F(PersistentQueueStorageDeleteDatabaseTest, DeleteDatabaseWhenRemoveFails)
{
    using ::testing::Return;
    using ::testing::Throw;
    using ::testing::_;

    // Mock that file exists but removal fails
    EXPECT_CALL(*mockFileSystemWrapper, exists(_))
    .WillOnce(Return(true));
    EXPECT_CALL(*mockFileSystemWrapper, remove(_))
    .WillOnce(Throw(std::filesystem::filesystem_error("Remove failed", std::error_code())));

    // Call deleteDatabase - should throw filesystem_error
    EXPECT_THROW(storage->deleteDatabase(), std::filesystem::filesystem_error);
}

TEST_F(PersistentQueueStorageDeleteDatabaseTest, DeleteDatabaseWhenExistsThrows)
{
    using ::testing::Throw;
    using ::testing::_;

    // Mock that exists() throws an exception
    EXPECT_CALL(*mockFileSystemWrapper, exists(_))
    .WillOnce(Throw(std::runtime_error("Filesystem access error")));
    // remove should not be called when exists throws
    EXPECT_CALL(*mockFileSystemWrapper, remove(_))
    .Times(0);

    // Call deleteDatabase - should throw the exception
    EXPECT_THROW(storage->deleteDatabase(), std::runtime_error);
}

TEST_F(PersistentQueueStorageDeleteDatabaseTest, DeleteDatabaseWithMemoryDatabase)
{
    using ::testing::_;

    // Mock that the memory path doesn't exist (which is expected)
    EXPECT_CALL(*mockFileSystemWrapper, exists(_))
    .WillOnce(testing::Return(false));
    // remove should not be called for memory database
    EXPECT_CALL(*mockFileSystemWrapper, remove(_))
    .Times(0);

    // Call deleteDatabase - should handle memory database gracefully
    EXPECT_NO_THROW(storage->deleteDatabase());
}

TEST_F(PersistentQueueStorageDeleteDatabaseTest, DeleteDatabaseVerifyConnectionIsClosed)
{
    using ::testing::Return;
    using ::testing::_;

    // Insert some data to ensure database is active
    storage->submitOrCoalesce(PersistedData{0, "id1", "index1", "{}", Operation::CREATE, 1});
    auto items = storage->fetchAndMarkForSync();
    EXPECT_EQ(items.size(), static_cast<size_t>(1));

    // Mock successful file operations
    EXPECT_CALL(*mockFileSystemWrapper, exists(_))
    .WillOnce(Return(true));
    EXPECT_CALL(*mockFileSystemWrapper, remove(_))
    .WillOnce(Return(true));

    // Call deleteDatabase
    EXPECT_NO_THROW(storage->deleteDatabase());
}

/// @brief A stale writer lock left by another connection must resolve once it clears, not fail immediately.
class PersistentQueueStorageBusyLockTest : public ::testing::Test
{
    protected:
        std::string dbPath;
        LoggerFunc testLogger;

        void SetUp() override
        {
            dbPath = (std::filesystem::temp_directory_path() / "wazuh_persistent_queue_busy_lock_test.db").string();
            std::filesystem::remove(dbPath);
            std::filesystem::remove(dbPath + "-wal");
            std::filesystem::remove(dbPath + "-shm");

            testLogger = [](modules_log_level_t /*level*/, const std::string& /*msg*/)
            {
            };
        }

        void TearDown() override
        {
            std::filesystem::remove(dbPath);
            std::filesystem::remove(dbPath + "-wal");
            std::filesystem::remove(dbPath + "-shm");
        }
};

TEST_F(PersistentQueueStorageBusyLockTest, ResetAllSyncingWaitsOutTransientLockInsteadOfFailingImmediately)
{
    // Create the schema first, then hold a real write lock on it.
    PersistentQueueStorage firstInstanceStorage(dbPath, testLogger);

    SQLite3Wrapper::Connection lockHolderConnection(dbPath);
    lockHolderConnection.execute("BEGIN IMMEDIATE TRANSACTION;");

    // A second instance opening the same db while the lock is held.
    PersistentQueueStorage secondInstanceStorage(dbPath, testLogger);

    // Release the lock from another thread after a short delay.
    std::thread lockReleaser(
        [&lockHolderConnection]()
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        lockHolderConnection.execute("COMMIT;");
    });

    // Without busy_timeout this throws immediately; with it, it waits out the 300ms lock.
    EXPECT_NO_THROW(secondInstanceStorage.resetAllSyncing());

    lockReleaser.join();
}

class PersistentQueueStorageDeferralTest : public ::testing::Test
{
protected:
    std::unique_ptr<PersistentQueueStorage> storage;
    LoggerFunc testLogger;
    std::chrono::steady_clock::time_point currentTime;

    void SetUp() override
    {
        testLogger = [](modules_log_level_t /*level*/, const std::string& /*msg*/) {};
        storage = std::make_unique<PersistentQueueStorage>(":memory:", testLogger);
        currentTime = std::chrono::steady_clock::now();
        storage->setClockForTesting([this]() { return currentTime; });
    }

    void TearDown() override
    {
        storage.reset();
    }
};

// TEST 1 — HEAD-OF-LINE UNBLOCKING
TEST_F(PersistentQueueStorageDeferralTest, HeadOfLineUnblocking)
{
    storage->submitOrCoalesce(PersistedData {0, "A", "packages", "payloadA", Operation::CREATE, 1});
    storage->submitOrCoalesce(PersistedData {0, "B", "packages", "payloadB", Operation::CREATE, 1});
    storage->submitOrCoalesce(PersistedData {0, "C", "packages", "payloadC", Operation::CREATE, 1});

    // Defer A
    storage->deferItems({"A"});

    // Call fetchAndMarkForSync(): B and C can be selected, A is skipped
    auto fetched = storage->fetchAndMarkForSync();
    ASSERT_EQ(fetched.size(), 2U);
    EXPECT_EQ(fetched[0].id, "B");
    EXPECT_EQ(fetched[1].id, "C");

    // A remains safely stored in SQLite as PENDING
    auto pending = storage->fetchPending(true);
    ASSERT_EQ(pending.size(), 1U);
    EXPECT_EQ(pending[0].id, "A");
}

// TEST 2 — DEFERRED ITEM RETRIES
TEST_F(PersistentQueueStorageDeferralTest, DeferredItemRetriesAfterCooldownExpires)
{
    storage->submitOrCoalesce(PersistedData {0, "A", "packages", "payloadA", Operation::CREATE, 1});

    // Defer A with initial cooldown (~30s)
    storage->deferItems({"A"});

    // Verify A is skipped before expiration
    currentTime += std::chrono::seconds(15);
    auto fetchedEarly = storage->fetchAndMarkForSync();
    EXPECT_TRUE(fetchedEarly.empty());

    // Allow cooldown to expire (past 30 seconds)
    currentTime += std::chrono::seconds(20); // total 35s > 30s
    auto fetchedExpired = storage->fetchAndMarkForSync();
    ASSERT_EQ(fetchedExpired.size(), 1U);
    EXPECT_EQ(fetchedExpired[0].id, "A");
}

// TEST 3 — SUCCESS REMOVES DEFERRAL
TEST_F(PersistentQueueStorageDeferralTest, SuccessRemovesDeferral)
{
    storage->submitOrCoalesce(PersistedData {0, "A", "packages", "payloadA", Operation::CREATE, 1});

    // Defer A
    storage->deferItems({"A"});

    // Expire cooldown so it can be fetched
    currentTime += std::chrono::seconds(35);
    auto fetched = storage->fetchAndMarkForSync();
    ASSERT_EQ(fetched.size(), 1U);
    EXPECT_EQ(fetched[0].id, "A");

    // Successful sync removes all synced items
    storage->removeAllSynced();

    // Verify A is removed from queue
    auto pending = storage->fetchPending(true);
    EXPECT_TRUE(pending.empty());

    // Re-insert A: verify no stale deferral suppresses it
    storage->submitOrCoalesce(PersistedData {0, "A", "packages", "payloadA_new", Operation::CREATE, 2});
    auto fetchedNew = storage->fetchAndMarkForSync();
    ASSERT_EQ(fetchedNew.size(), 1U);
    EXPECT_EQ(fetchedNew[0].id, "A");
}

// TEST 4 — COALESCING CLEARS DEFERRAL
TEST_F(PersistentQueueStorageDeferralTest, CoalescingClearsDeferralImmediately)
{
    storage->submitOrCoalesce(PersistedData {0, "A", "packages", "payloadA_v1", Operation::CREATE, 1});

    // Defer A (cooldown is 30s)
    storage->deferItems({"A"});

    // Verify A is skipped right now
    auto fetchedEarly = storage->fetchAndMarkForSync();
    EXPECT_TRUE(fetchedEarly.empty());

    // Submit newer data for A (coalescing occurs)
    storage->submitOrCoalesce(PersistedData {0, "A", "packages", "payloadA_v2", Operation::MODIFY, 2});

    // Coalescing must clear deferral immediately without waiting for old cooldown
    auto fetchedAfterCoalesce = storage->fetchAndMarkForSync();
    ASSERT_EQ(fetchedAfterCoalesce.size(), 1U);
    EXPECT_EQ(fetchedAfterCoalesce[0].id, "A");
    EXPECT_EQ(fetchedAfterCoalesce[0].data, "payloadA_v2");
}

// TEST 5 — ALL ROWS DEFERRED
TEST_F(PersistentQueueStorageDeferralTest, AllRowsDeferredReturnsEmptySafely)
{
    storage->submitOrCoalesce(PersistedData {0, "A", "packages", "payloadA", Operation::CREATE, 1});
    storage->submitOrCoalesce(PersistedData {0, "B", "packages", "payloadB", Operation::CREATE, 1});

    // Defer all pending rows
    storage->deferItems({"A", "B"});

    // Calling fetchAndMarkForSync must return empty, not spin, not error, not corrupt queue
    auto fetched = storage->fetchAndMarkForSync();
    EXPECT_TRUE(fetched.empty());

    // Rows still remain PENDING in queue
    auto pending = storage->fetchPending(true);
    EXPECT_EQ(pending.size(), 2U);
}

// TEST 6 — MULTIPLE INDICES
TEST_F(PersistentQueueStorageDeferralTest, MultipleIndicesHealthyProgress)
{
    storage->submitOrCoalesce(PersistedData {0, "pkg1", "packages", "pkg_data", Operation::CREATE, 1});
    storage->submitOrCoalesce(PersistedData {0, "port1", "ports", "port_data", Operation::CREATE, 1});
    storage->submitOrCoalesce(PersistedData {0, "proc1", "processes", "proc_data", Operation::CREATE, 1});

    // Defer packages item
    storage->deferItems({"pkg1"});

    // Fetch batch: ports and processes must progress
    auto fetched = storage->fetchAndMarkForSync();
    ASSERT_EQ(fetched.size(), 2U);
    EXPECT_EQ(fetched[0].id, "port1");
    EXPECT_EQ(fetched[1].id, "proc1");

    // Clear synced ports and processes
    storage->removeAllSynced();

    // Verify packages remains safely queued
    auto pending = storage->fetchPending(true);
    ASSERT_EQ(pending.size(), 1U);
    EXPECT_EQ(pending[0].id, "pkg1");
}

// TEST 7 — SYNCING_UPDATED
TEST_F(PersistentQueueStorageDeferralTest, SyncingUpdatedSemanticsPreserved)
{
    storage->submitOrCoalesce(PersistedData {0, "A", "packages", "v1", Operation::CREATE, 1});

    // Fetch marks A as SYNCING
    auto fetched = storage->fetchAndMarkForSync();
    ASSERT_EQ(fetched.size(), 1U);
    EXPECT_EQ(fetched[0].id, "A");

    // Newer update arrives while A is SYNCING -> becomes SYNCING_UPDATED
    storage->submitOrCoalesce(PersistedData {0, "A", "packages", "v2", Operation::MODIFY, 2});

    // Transmission fails: resetAllSyncing()
    storage->resetAllSyncing();

    // Verify A returned to PENDING with updated data v2
    auto pending = storage->fetchPending(true);
    ASSERT_EQ(pending.size(), 1U);
    EXPECT_EQ(pending[0].id, "A");
    EXPECT_EQ(pending[0].data, "v2");
}

// TEST 7B — SYNCING_UPDATED ENTITY NOT DEFERRED ON PROTOCOL ERROR
TEST_F(PersistentQueueStorageDeferralTest, SyncingUpdatedEntityNotDeferredOnProtocolError)
{
    storage->submitOrCoalesce(PersistedData {0, "A", "packages", "payloadA_v1", Operation::CREATE, 1});

    // Fetch marks A as SYNCING
    auto fetched = storage->fetchAndMarkForSync();
    ASSERT_EQ(fetched.size(), 1U);
    EXPECT_EQ(fetched[0].id, "A");

    // Producer submits newer A' while transmission is in-flight -> A becomes SYNCING_UPDATED
    storage->submitOrCoalesce(PersistedData {0, "A", "packages", "payloadA_v2", Operation::MODIFY, 2});

    // Transmission fails with PROTOCOL_ERROR: deferItems is called with the in-flight IDs {"A"}
    storage->deferItems({"A"});

    // resetAllSyncing returns the row to PENDING
    storage->resetAllSyncing();

    // Invariant: fresh payload A' must NOT be deferred for the old failure;
    // it must be immediately eligible on the next fetch without advancing clock!
    auto fetchedImmediate = storage->fetchAndMarkForSync();
    ASSERT_EQ(fetchedImmediate.size(), 1U);
    EXPECT_EQ(fetchedImmediate[0].id, "A");
    EXPECT_EQ(fetchedImmediate[0].data, "payloadA_v2");
    EXPECT_EQ(fetchedImmediate[0].version, 2U);
}

// TEST 7C — DETERMINISTIC REGRESSION TEST FOR SYNCING_UPDATED RACE:
// A is SYNCING -> deferral recorded -> A becomes SYNCING_UPDATED in SQLite ->
// resetAllSyncing executes -> verify fresh A' is PENDING and NOT deferred.
TEST_F(PersistentQueueStorageDeferralTest, SyncingUpdatedRecordClearedFromDeferralOnResetSyncing)
{
    const std::string testDb = (std::filesystem::temp_directory_path() / "wazuh_syncing_updated_race_test.db").string();
    std::filesystem::remove(testDb);
    std::filesystem::remove(testDb + "-wal");
    std::filesystem::remove(testDb + "-shm");

    {
        PersistentQueueStorage fileStorage(testDb, testLogger);
        fileStorage.setClockForTesting([this]() { return currentTime; });

        fileStorage.submitOrCoalesce(PersistedData {0, "A", "packages", "payloadA_v1", Operation::CREATE, 1});
        fileStorage.submitOrCoalesce(PersistedData {0, "B", "packages", "payloadB_v1", Operation::CREATE, 1});

        // 1. Fetch marks both A and B as SYNCING in SQLite
        auto fetched = fileStorage.fetchAndMarkForSync();
        ASSERT_EQ(fetched.size(), 2U);
        EXPECT_EQ(fetched[0].id, "A");
        EXPECT_EQ(fetched[1].id, "B");

        // 2. Transmission for old batch fails with PROTOCOL_ERROR: defer both A and B
        fileStorage.deferItems({"A", "B"});

        // Verify both are deferred in memory
        auto checkDeferred = fileStorage.fetchAndMarkForSync();
        EXPECT_TRUE(checkDeferred.empty());

        // 3. Producer submits newer A' which transitions A to SYNCING_UPDATED in SQLite.
        // B receives no update and remains SYNCING.
        {
            SQLite3Wrapper::Connection directConn(testDb);
            directConn.execute("UPDATE persistent_queue SET sync_status = 2, data = 'payloadA_v2', version = 2 WHERE id = 'A';");
        }

        // 4. resetAllSyncing() executes
        fileStorage.resetAllSyncing();

        // 5. Invariant:
        // - A (was SYNCING_UPDATED) must be PENDING and NOT deferred -> immediately eligible
        // - B (was SYNCING) must be PENDING but REMAINS deferred -> suppressed by cooldown
        auto fetchedAfterReset = fileStorage.fetchAndMarkForSync();
        ASSERT_EQ(fetchedAfterReset.size(), 1U);
        EXPECT_EQ(fetchedAfterReset[0].id, "A");
        EXPECT_EQ(fetchedAfterReset[0].data, "payloadA_v2");
        EXPECT_EQ(fetchedAfterReset[0].version, 2U);

        // 6. When cooldown expires, B becomes eligible
        currentTime += std::chrono::seconds(35);
        auto fetchedB = fileStorage.fetchAndMarkForSync();
        ASSERT_EQ(fetchedB.size(), 1U);
        EXPECT_EQ(fetchedB[0].id, "B");
        EXPECT_EQ(fetchedB[0].data, "payloadB_v1");
    }

    std::filesystem::remove(testDb);
    std::filesystem::remove(testDb + "-wal");
    std::filesystem::remove(testDb + "-shm");
}

// TEST 8 — DATA PRESERVATION
TEST_F(PersistentQueueStorageDeferralTest, DataPreservationAfterRepeatedFailures)
{
    const std::string originalData = "{\"key\": \"valuable_inventory_data\"}";
    storage->submitOrCoalesce(PersistedData {0, "A", "packages", originalData, Operation::CREATE, 1});

    // Simulate multiple failed sync cycles with repeated deferrals
    for (int cycle = 1; cycle <= 5; ++cycle)
    {
        storage->deferItems({"A"});
        storage->resetAllSyncing();
    }

    // Direct SQLite verification: row still exists, sync_status is PENDING, data is unchanged
    auto pending = storage->fetchPending(true);
    ASSERT_EQ(pending.size(), 1U);
    EXPECT_EQ(pending[0].id, "A");
    EXPECT_EQ(pending[0].data, originalData);
}

// TEST 9 — RESTART-LIKE STATE RESET
TEST_F(PersistentQueueStorageDeferralTest, RestartLikeStateResetPreservesQueueCorrectness)
{
    std::string dbFile = (std::filesystem::temp_directory_path() / "wazuh_restart_test.db").string();
    std::filesystem::remove(dbFile);
    std::filesystem::remove(dbFile + "-wal");
    std::filesystem::remove(dbFile + "-shm");

    {
        PersistentQueueStorage instance1(dbFile, testLogger);
        instance1.submitOrCoalesce(PersistedData {0, "A", "packages", "payloadA", Operation::CREATE, 1});
        instance1.submitOrCoalesce(PersistedData {0, "B", "packages", "payloadB", Operation::CREATE, 1});

        // Defer A in memory
        instance1.deferItems({"A"});

        // fetch in instance1: only B fetched
        auto fetched = instance1.fetchAndMarkForSync();
        ASSERT_EQ(fetched.size(), 1U);
        EXPECT_EQ(fetched[0].id, "B");
        instance1.resetAllSyncing();
    }

    // Instance 2 simulates process restart (in-memory deferrals cleared, SQLite queue intact)
    {
        PersistentQueueStorage instance2(dbFile, testLogger);

        // Both rows exist in SQLite and are valid
        auto pending = instance2.fetchPending(true);
        ASSERT_EQ(pending.size(), 2U);
        EXPECT_EQ(pending[0].id, "A");
        EXPECT_EQ(pending[1].id, "B");

        // Normal fetch succeeds according to rowid order
        auto fetched = instance2.fetchAndMarkForSync();
        ASSERT_EQ(fetched.size(), 2U);
        EXPECT_EQ(fetched[0].id, "A");
        EXPECT_EQ(fetched[1].id, "B");
    }

    std::filesystem::remove(dbFile);
    std::filesystem::remove(dbFile + "-wal");
    std::filesystem::remove(dbFile + "-shm");
}
