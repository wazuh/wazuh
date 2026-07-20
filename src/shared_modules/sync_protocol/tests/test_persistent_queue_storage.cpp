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
#include <memory>
#include <filesystem>

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
