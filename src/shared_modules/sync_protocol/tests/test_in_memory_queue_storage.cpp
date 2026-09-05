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
#include "in_memory_queue_storage.hpp"
#include "persistent_queue_storage.hpp"
#include "mock_filesystem_wrapper.hpp"
#include <memory>
#include <filesystem>
#include <algorithm>

namespace
{
    LoggerFunc silentLogger()
    {
        return [](modules_log_level_t /*level*/, const std::string& /*msg*/) {};
    }

    // Unique per-test path (keyed by the running test's name) so that InMemoryQueueStorage's
    // save-on-destruct behavior in one test can never leak a snapshot into the next test
    // that happens to reuse the same literal path.
    std::string tempDbPath(const std::string& name)
    {
        const auto* testInfo = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = testInfo ? std::string(testInfo->test_suite_name()) + "_" + testInfo->name() : "";
        return (std::filesystem::temp_directory_path() / (suffix + "_" + name)).string();
    }
}

// ========================================
// Coalescing logic: same scenarios as PersistentQueueStorage, since both backends
// must implement identical semantics.
// ========================================

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

class InMemoryQueueFullParamTest : public ::testing::TestWithParam<QueueScenario>
{
    protected:
        std::string dbPath;
        std::unique_ptr<InMemoryQueueStorage> storage;

        void SetUp() override
        {
            dbPath = tempDbPath("in_memory_queue_param_test.db");
            std::filesystem::remove(dbPath);
            storage = std::make_unique<InMemoryQueueStorage>(dbPath, silentLogger());
        }

        void TearDown() override
        {
            storage.reset();
            std::filesystem::remove(dbPath);
        }
};

TEST_P(InMemoryQueueFullParamTest, HandlesSubmitFetchRemoveResetCorrectly)
{
    auto param = GetParam();

    for (auto& ev : param.initial)
    {
        storage->submitOrCoalesce(ev);
    }

    if (param.doFetchAndSync)
    {
        storage->fetchAndMarkForSync();

        for (auto& evs : param.eventsInSync)
        {
            storage->submitOrCoalesce(evs);
        }
    }

    if (param.removeSynced)
    {
        storage->removeAllSynced();
    }

    if (param.resetSyncing)
    {
        storage->resetAllSyncing();
    }

    auto rows = storage->fetchAndMarkForSync();
    EXPECT_EQ(rows.size(), param.expectedRows);

    if (!rows.empty())
    {
        EXPECT_EQ(rows[0].operation, param.expectedOp);
    }
}

INSTANTIATE_TEST_SUITE_P(
    FullQueueCases,
    InMemoryQueueFullParamTest,
    ::testing::Values(
        QueueScenario
{
    "Case 1", { PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0} },
    false, {}, false, false, 1, Operation::CREATE
},
QueueScenario
{
    "Case 2",
    {
        PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0},
        PersistedData{0, "id1", "idx2", "{}", Operation::MODIFY, 0}
    },
    false, {}, false, false, 1, Operation::MODIFY
},
QueueScenario
{
    "Case 3",
    {
        PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0},
        PersistedData{0, "id1", "idx", "{}", Operation::DELETE_, 0}
    },
    false, {}, false, false, 0, Operation::CREATE
},
QueueScenario
{
    "Case 4",
    {
        PersistedData{0, "id1", "idx", "{}", Operation::MODIFY, 0},
        PersistedData{0, "id1", "idx", "{}", Operation::DELETE_, 0}
    },
    false, {}, false, false, 1, Operation::DELETE_
},
QueueScenario
{
    "Case 5", { PersistedData{0, "id1", "idx", "{}", Operation::DELETE_, 0} },
    false, {}, false, false, 1, Operation::DELETE_
},
QueueScenario
{
    "Case 6",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0} },
    true,
    { PersistedData{0, "id1", "idx2", "{}", Operation::MODIFY, 0} },
    true, false, 1, Operation::MODIFY
},
QueueScenario
{
    "Case 7",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0} },
    true,
    { PersistedData{0, "id1", "idx", "{}", Operation::DELETE_, 0} },
    true, false, 1, Operation::DELETE_
},
QueueScenario
{
    "Case 8",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0} },
    true,
    { PersistedData{0, "id1", "idx", "{}", Operation::DELETE_, 0} },
    false, true, 0, Operation::DELETE_
},
QueueScenario
{
    "Case 9",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0} },
    true,
    { PersistedData{0, "id1", "idx2", "{}", Operation::MODIFY, 0} },
    false, true, 1, Operation::MODIFY
},
QueueScenario
{
    "Case 10",
    {
        PersistedData{0, "id1", "idx", "{}", Operation::DELETE_, 0},
        PersistedData{0, "id1", "idx2", "{}", Operation::MODIFY, 0}
    },
    false, {}, false, false, 1, Operation::MODIFY
},
QueueScenario
{
    "Case 11",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0} },
    true, {}, true, false, 0, Operation::CREATE
},
QueueScenario
{
    "Case 12",
    {
        PersistedData{0, "id1", "idx", "{}", Operation::MODIFY, 0},
        PersistedData{0, "id1", "idx2", "{}", Operation::MODIFY, 0},
    },
    false, {}, false, false, 1, Operation::MODIFY
},
QueueScenario
{
    "Case 13",
    {
        PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0},
        PersistedData{0, "id2", "idx", "{}", Operation::MODIFY, 0}
    },
    false, {}, false, false, 2, Operation::CREATE
},
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
    false, true, 1, Operation::DELETE_
},
QueueScenario
{
    "Case 15",
    {
        PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0},
        PersistedData{0, "id1", "idx", "{}", Operation::DELETE_, 0},
        PersistedData{0, "id1", "idx2", "{}", Operation::CREATE, 0}
    },
    false, {}, false, false, 1, Operation::CREATE
},
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
    true, false, 1, Operation::MODIFY
},
QueueScenario
{
    "Case 17",
    { PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0} },
    true,
    {
        PersistedData{0, "id1", "idx", "{}", Operation::DELETE_, 0},
        PersistedData{0, "id1", "idx2", "{}", Operation::CREATE, 0}
    },
    false, true, 1, Operation::CREATE
}
    )
);

// ========================================
// removeByIndex
// ========================================

class InMemoryQueueStorageTest : public ::testing::Test
{
    protected:
        std::string dbPath;
        std::unique_ptr<InMemoryQueueStorage> storage;

        void SetUp() override
        {
            dbPath = tempDbPath("in_memory_queue_basic_test.db");
            std::filesystem::remove(dbPath);
            storage = std::make_unique<InMemoryQueueStorage>(dbPath, silentLogger());
        }

        void TearDown() override
        {
            storage.reset();
            std::filesystem::remove(dbPath);
        }
};

TEST_F(InMemoryQueueStorageTest, RemoveByIndexDeletesOnlySpecifiedIndex)
{
    storage->submitOrCoalesce(PersistedData{0, "id1", "index1", "{}", Operation::CREATE, 0});
    storage->submitOrCoalesce(PersistedData{0, "id2", "index2", "{}", Operation::CREATE, 0});
    storage->submitOrCoalesce(PersistedData{0, "id3", "index1", "{}", Operation::MODIFY, 0});
    storage->submitOrCoalesce(PersistedData{0, "id4", "index3", "{}", Operation::CREATE, 0});

    auto allItems = storage->fetchAndMarkForSync();
    EXPECT_EQ(allItems.size(), static_cast<size_t>(4));

    storage->resetAllSyncing();
    storage->removeByIndex("index1");

    auto remainingItems = storage->fetchAndMarkForSync();
    EXPECT_EQ(remainingItems.size(), static_cast<size_t>(2));

    for (const auto& item : remainingItems)
    {
        EXPECT_NE(item.index, "index1");
    }
}

TEST_F(InMemoryQueueStorageTest, RemoveByIndexHandlesNonExistentIndex)
{
    storage->submitOrCoalesce(PersistedData{0, "id1", "index1", "{}", Operation::CREATE, 1});
    storage->submitOrCoalesce(PersistedData{0, "id2", "index2", "{}", Operation::CREATE, 1});

    EXPECT_NO_THROW(storage->removeByIndex("non_existent_index"));

    auto allItems = storage->fetchAndMarkForSync();
    EXPECT_EQ(allItems.size(), static_cast<size_t>(2));
}

TEST_F(InMemoryQueueStorageTest, RemoveByIndexHandlesEmptyStorage)
{
    EXPECT_NO_THROW(storage->removeByIndex("any_index"));

    auto allItems = storage->fetchAndMarkForSync();
    EXPECT_EQ(allItems.size(), static_cast<size_t>(0));
}

TEST_F(InMemoryQueueStorageTest, RemoveAllDataContextRemovesOnlyDataContextItems)
{
    storage->submitOrCoalesce(PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0, false});
    storage->submitOrCoalesce(PersistedData{0, "id2", "idx", "{}", Operation::CREATE, 0, true});

    storage->removeAllDataContext();

    auto remaining = storage->fetchPending(false);
    ASSERT_EQ(remaining.size(), static_cast<size_t>(1));
    EXPECT_EQ(remaining[0].id, "id1");
}

TEST_F(InMemoryQueueStorageTest, FetchPendingOnlyDataValuesFiltersDataContext)
{
    storage->submitOrCoalesce(PersistedData{0, "value1", "idx", "{}", Operation::CREATE, 0, false});
    storage->submitOrCoalesce(PersistedData{0, "context1", "idx", "{}", Operation::CREATE, 0, true});

    auto onlyValues = storage->fetchPending(true);
    ASSERT_EQ(onlyValues.size(), static_cast<size_t>(1));
    EXPECT_EQ(onlyValues[0].id, "value1");

    auto everything = storage->fetchPending(false);
    EXPECT_EQ(everything.size(), static_cast<size_t>(2));
}

TEST_F(InMemoryQueueStorageTest, FetchAndMarkForSyncMarksRowsSyncing)
{
    storage->submitOrCoalesce(PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0});

    auto firstFetch = storage->fetchAndMarkForSync();
    ASSERT_EQ(firstFetch.size(), static_cast<size_t>(1));

    // Rows already marked SYNCING must not appear again until reset/cleared.
    auto secondFetch = storage->fetchAndMarkForSync();
    EXPECT_TRUE(secondFetch.empty());
}

TEST_F(InMemoryQueueStorageTest, SubmitBatchAppliesCoalesceLogicForEachItem)
{
    std::vector<PersistedData> batch =
    {
        PersistedData{0, "id1", "idx1", "{}", Operation::CREATE, 1},
        PersistedData{0, "id2", "idx2", "{}", Operation::CREATE, 1},
        PersistedData{0, "id1", "idx1", "{updated}", Operation::MODIFY, 2}
    };

    storage->submitBatch(batch);

    auto rows = storage->fetchAndMarkForSync();
    ASSERT_EQ(rows.size(), static_cast<size_t>(2));

    const auto id1 = std::find_if(rows.begin(), rows.end(), [](const PersistedData& d) { return d.id == "id1"; });
    ASSERT_NE(id1, rows.end());
    EXPECT_EQ(id1->operation, Operation::MODIFY);
}

TEST_F(InMemoryQueueStorageTest, SubmitBatchWithEmptyBatchIsANoOp)
{
    EXPECT_NO_THROW(storage->submitBatch({}));

    auto rows = storage->fetchAndMarkForSync();
    EXPECT_TRUE(rows.empty());
}

TEST_F(InMemoryQueueStorageTest, FetchAllReturnsEveryRowRegardlessOfStatus)
{
    storage->submitOrCoalesce(PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 1});
    storage->submitOrCoalesce(PersistedData{0, "id2", "idx", "{}", Operation::CREATE, 1});
    storage->fetchAndMarkForSync(); // marks both SYNCING

    auto rows = storage->fetchAll();
    ASSERT_EQ(rows.size(), static_cast<size_t>(2));

    for (const auto& row : rows)
    {
        EXPECT_EQ(row.syncStatus, SyncStatus::SYNCING);
    }
}

TEST_F(InMemoryQueueStorageTest, SaveAllReplacesExistingRowsWithGivenSet)
{
    storage->submitOrCoalesce(PersistedData{0, "old", "idx", "{}", Operation::CREATE, 1});

    QueueRow replacement;
    replacement.data = PersistedData{0, "new", "idx", "{}", Operation::CREATE, 1};
    replacement.syncStatus = SyncStatus::PENDING;
    storage->saveAll({replacement});

    auto rows = storage->fetchPending(false);
    ASSERT_EQ(rows.size(), static_cast<size_t>(1));
    EXPECT_EQ(rows[0].id, "new");
}

TEST(InMemoryQueueStorageConstructorTest, ThrowsWhenLoggerIsNull)
{
    LoggerFunc nullLogger = nullptr;
    EXPECT_THROW(InMemoryQueueStorage("fake_path_for_null_logger_test.db", nullLogger), std::invalid_argument);
}

// ========================================
// deleteDatabase
// ========================================

class InMemoryQueueStorageDeleteDatabaseTest : public ::testing::Test
{
    protected:
        std::shared_ptr<MockFileSystemWrapper> mockFileSystemWrapper;
        std::unique_ptr<InMemoryQueueStorage> storage;

        void SetUp() override
        {
            mockFileSystemWrapper = std::make_shared<MockFileSystemWrapper>();
            // Constructor-time loadFromDisk() checks existence once; default to "no snapshot"
            // for tests that don't care about the load path, then set explicit expectations
            // for deleteDatabase() itself below.
            EXPECT_CALL(*mockFileSystemWrapper, exists(::testing::_)).WillOnce(::testing::Return(false));
            storage = std::make_unique<InMemoryQueueStorage>("fake_path.db", silentLogger(), mockFileSystemWrapper);
        }

        void TearDown() override
        {
            storage.reset();
            mockFileSystemWrapper.reset();
        }
};

TEST_F(InMemoryQueueStorageDeleteDatabaseTest, DeleteDatabaseWhenFileExists)
{
    using ::testing::Return;
    using ::testing::_;

    EXPECT_CALL(*mockFileSystemWrapper, exists(_)).WillOnce(Return(true));
    EXPECT_CALL(*mockFileSystemWrapper, remove(_)).WillOnce(Return(true));

    EXPECT_NO_THROW(storage->deleteDatabase());
}

TEST_F(InMemoryQueueStorageDeleteDatabaseTest, DeleteDatabaseWhenFileDoesNotExist)
{
    using ::testing::Return;
    using ::testing::_;

    EXPECT_CALL(*mockFileSystemWrapper, exists(_)).WillOnce(Return(false));
    EXPECT_CALL(*mockFileSystemWrapper, remove(_)).Times(0);

    EXPECT_NO_THROW(storage->deleteDatabase());
}

TEST_F(InMemoryQueueStorageDeleteDatabaseTest, DeleteDatabaseClearsInMemoryRows)
{
    using ::testing::Return;
    using ::testing::_;

    storage->submitOrCoalesce(PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 0});

    EXPECT_CALL(*mockFileSystemWrapper, exists(_)).WillOnce(Return(false));
    EXPECT_CALL(*mockFileSystemWrapper, remove(_)).Times(0);

    storage->deleteDatabase();

    auto remaining = storage->fetchPending(false);
    EXPECT_TRUE(remaining.empty());
}

TEST_F(InMemoryQueueStorageDeleteDatabaseTest, DeleteDatabaseWhenRemoveFails)
{
    using ::testing::Return;
    using ::testing::Throw;
    using ::testing::_;

    EXPECT_CALL(*mockFileSystemWrapper, exists(_)).WillOnce(Return(true));
    EXPECT_CALL(*mockFileSystemWrapper, remove(_))
    .WillOnce(Throw(std::filesystem::filesystem_error("Remove failed", std::error_code())));

    EXPECT_THROW(storage->deleteDatabase(), std::filesystem::filesystem_error);
}

TEST_F(InMemoryQueueStorageDeleteDatabaseTest, DeleteDatabaseWhenExistsThrows)
{
    using ::testing::Throw;
    using ::testing::_;

    EXPECT_CALL(*mockFileSystemWrapper, exists(_)).WillOnce(Throw(std::runtime_error("Filesystem access error")));
    EXPECT_CALL(*mockFileSystemWrapper, remove(_)).Times(0);

    EXPECT_THROW(storage->deleteDatabase(), std::runtime_error);
}

// ========================================
// Disk round trip: this is the behavior this class exists for — no disk I/O during
// normal operation, snapshot only at construction (load) and destruction (save).
// ========================================

class InMemoryQueueStorageRoundTripTest : public ::testing::Test
{
    protected:
        std::string dbPath;

        void SetUp() override
        {
            dbPath = tempDbPath("in_memory_queue_roundtrip_test.db");
            std::filesystem::remove(dbPath);
        }

        void TearDown() override
        {
            std::filesystem::remove(dbPath);
        }
};

TEST_F(InMemoryQueueStorageRoundTripTest, SavesSnapshotOnDestructionAndLoadsItOnNextConstruction)
{
    {
        InMemoryQueueStorage storage(dbPath, silentLogger());
        storage.submitOrCoalesce(PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 1});
        storage.submitOrCoalesce(PersistedData{0, "id2", "idx2", "{}", Operation::MODIFY, 2});
    } // destructor saves both rows to dbPath

    ASSERT_TRUE(std::filesystem::exists(dbPath));

    {
        InMemoryQueueStorage storage(dbPath, silentLogger());
        // Loading absorbs the on-disk file into memory and removes it.
        EXPECT_FALSE(std::filesystem::exists(dbPath));

        auto pending = storage.fetchPending(false);
        ASSERT_EQ(pending.size(), static_cast<size_t>(2));
        EXPECT_EQ(pending[0].id, "id1");
        EXPECT_EQ(pending[1].id, "id2");
    }
}

TEST_F(InMemoryQueueStorageRoundTripTest, DoesNotWriteASnapshotWhenQueueIsEmpty)
{
    {
        InMemoryQueueStorage storage(dbPath, silentLogger());
        // Nothing submitted.
    }

    EXPECT_FALSE(std::filesystem::exists(dbPath));
}

TEST_F(InMemoryQueueStorageRoundTripTest, PreservesSyncStatusAcrossRestartAfterResetAllSyncing)
{
    {
        InMemoryQueueStorage storage(dbPath, silentLogger());
        storage.submitOrCoalesce(PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 1});
        // Mark it SYNCING (as if a sync round were in flight) without an ack.
        storage.fetchAndMarkForSync();
    } // destructor saves the row while it is still SYNCING

    {
        InMemoryQueueStorage storage(dbPath, silentLogger());
        // PersistentQueue::resetAllSyncing() is normally called right after construction;
        // this class doesn't call it itself, so the row loads back as SYNCING...
        auto beforeReset = storage.fetchPending(false);
        EXPECT_TRUE(beforeReset.empty());

        // ...and becomes visible again once the caller normalizes leftover sync state,
        // exactly as PersistentQueue's constructor does today.
        storage.resetAllSyncing();
        auto afterReset = storage.fetchPending(false);
        ASSERT_EQ(afterReset.size(), static_cast<size_t>(1));
        EXPECT_EQ(afterReset[0].id, "id1");
    }
}

TEST_F(InMemoryQueueStorageRoundTripTest, LoadsASnapshotWrittenDirectlyByPersistentQueueStorage)
{
    // Simulate a snapshot left behind before this feature existed (or written by another
    // process using the SQLite format directly) to confirm the two backends' on-disk
    // format is compatible.
    {
        PersistentQueueStorage onDiskStorage(dbPath, silentLogger());
        onDiskStorage.submitOrCoalesce(PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 1});
    }

    ASSERT_TRUE(std::filesystem::exists(dbPath));

    InMemoryQueueStorage storage(dbPath, silentLogger());
    EXPECT_FALSE(std::filesystem::exists(dbPath));

    auto pending = storage.fetchPending(false);
    ASSERT_EQ(pending.size(), static_cast<size_t>(1));
    EXPECT_EQ(pending[0].id, "id1");
}

TEST(InMemoryQueueStorageCapacityTest, RejectsNewItemsPastQueueByteCapacityWithoutEvictingExisting)
{
    // Bounds RSS growth when the sync peer is unreachable for an extended period: once the
    // estimated total size of the queue is at capacity, a brand-new (never-seen) id is
    // rejected -- by throwing, not silently returning, so a caller (e.g.
    // PersistentQueue::submit()) can tell the difference from success and retain the item
    // for retry -- rather than evicting already-queued state. The exact byte cap is an
    // internal implementation detail (not exposed via the header), so this only checks the
    // boundary behavior, not the specific limit value -- each item carries a large enough
    // payload, and enough of them are submitted, to comfortably exceed any plausible cap.
    InMemoryQueueStorage storage(":memory:", silentLogger());

    const std::string largePayload(4096, 'x');

    // Fill up to well past any plausible cap, expecting the first throw to mark where the
    // real limit was hit. 3000 items * (~4096 payload + ~512 overhead) bytes is well past
    // any plausible byte cap.
    size_t acceptedCount = 0;
    bool threwOnce = false;

    for (int i = 0; i < 3000; ++i)
    {
        try
        {
            storage.submitOrCoalesce(PersistedData{0, "id" + std::to_string(i), "idx", largePayload, Operation::CREATE, 1});
            ++acceptedCount;
        }
        catch (const std::exception&)
        {
            threwOnce = true;
        }
    }

    EXPECT_TRUE(threwOnce) << "Expected at least one rejection once the cap was reached";

    const auto rows = storage.fetchAll();

    // The row count must match exactly how many submissions were actually accepted -- not
    // every one of the 3000 attempted submissions made it in.
    EXPECT_LT(rows.size(), static_cast<size_t>(3000));
    EXPECT_EQ(rows.size(), acceptedCount);

    // The very first item submitted must still be present: capacity enforcement rejects
    // new arrivals once full, it does not evict already-queued state to make room.
    const bool firstItemStillPresent = std::any_of(rows.begin(), rows.end(),
                                                    [](const QueueRow & row) { return row.data.id == "id0"; });
    EXPECT_TRUE(firstItemStillPresent);
}

TEST(InMemoryQueueStorageCapacityTest, CoalescedUpdatesDoNotLeakIntoTheByteBudget)
{
    // Repeated updates to the SAME id must not each add to the running byte total -- only
    // net queue content should count against the cap, otherwise a single hot id could
    // eventually exhaust the whole budget on its own via in-place updates.
    InMemoryQueueStorage storage(":memory:", silentLogger());

    const std::string largePayload(4096, 'x');

    for (int i = 0; i < 5000; ++i)
    {
        storage.submitOrCoalesce(PersistedData{0, "same-id", "idx", largePayload, Operation::MODIFY, static_cast<uint64_t>(i)});
    }

    // A single coalesced id, however many times it was updated, must never itself be
    // rejected by the capacity check, and a fresh, distinct id must still fit right after.
    storage.submitOrCoalesce(PersistedData{0, "brand-new-id", "idx", "{}", Operation::CREATE, 1});

    const auto rows = storage.fetchAll();
    const bool sameIdPresent = std::any_of(rows.begin(), rows.end(),
                                            [](const QueueRow & row) { return row.data.id == "same-id"; });
    const bool newIdPresent = std::any_of(rows.begin(), rows.end(),
                                           [](const QueueRow & row) { return row.data.id == "brand-new-id"; });
    EXPECT_TRUE(sameIdPresent);
    EXPECT_TRUE(newIdPresent);
}

TEST(InMemoryQueueStorageCapacityTest, RejectsCoalescedUpdateThatWouldGrowTrackedItemPastCapacity)
{
    // The cap must also apply when an already-tracked id grows, not just to brand-new ids.
    InMemoryQueueStorage storage(":memory:", silentLogger());

    const std::string largePayload(4096, 'x');

    // Fill the queue with distinct ids up to just under the cap.
    int lastAcceptedIndex = -1;

    for (int i = 0; i < 3000; ++i)
    {
        try
        {
            storage.submitOrCoalesce(PersistedData{0, "id" + std::to_string(i), "idx", largePayload, Operation::CREATE, 1});
            lastAcceptedIndex = i;
        }
        catch (const std::exception&)
        {
            break;
        }
    }

    ASSERT_GE(lastAcceptedIndex, 0) << "Test setup expected at least one item to fit before the cap";

    const std::string trackedId = "id" + std::to_string(lastAcceptedIndex);
    const auto rowsBeforeGrowth = storage.fetchAll();
    const auto originalRow = std::find_if(rowsBeforeGrowth.begin(), rowsBeforeGrowth.end(),
                                          [&](const QueueRow & row)
    {
        return row.data.id == trackedId;
    });
    ASSERT_NE(originalRow, rowsBeforeGrowth.end());

    // Re-submit that same, already-tracked id with a much bigger payload: this must be
    // rejected exactly like a brand-new id would be once the cap is reached.
    const std::string oversizedPayload(2 * 1024 * 1024, 'y');
    EXPECT_THROW(
        storage.submitOrCoalesce(PersistedData{0, trackedId, "idx", oversizedPayload, Operation::MODIFY, 2}),
        std::runtime_error);

    // The rejected update must leave the tracked item exactly as it was, not partially applied.
    const auto rowsAfterRejection = storage.fetchAll();
    const auto rowAfterRejection = std::find_if(rowsAfterRejection.begin(), rowsAfterRejection.end(),
                                                [&](const QueueRow & row)
    {
        return row.data.id == trackedId;
    });
    ASSERT_NE(rowAfterRejection, rowsAfterRejection.end());
    EXPECT_EQ(rowAfterRejection->data.data, originalRow->data.data);
    EXPECT_EQ(rowAfterRejection->data.version, originalRow->data.version);
}

TEST(InMemoryQueueStorageCapacityTest, SubmitBatchRollsBackFullyOnMidBatchFailure)
{
    // submitBatch() must persist atomically: a mid-batch failure must not leave earlier
    // items in the batch applied.
    InMemoryQueueStorage storage(":memory:", silentLogger());

    // Bigger than the whole queue byte cap alone, so it's rejected no matter how much room
    // the first two items left.
    const std::string oversizedPayload(9 * 1024 * 1024, 'x');

    const std::vector<PersistedData> batch =
    {
        PersistedData{0, "id1", "idx", "{}", Operation::CREATE, 1},
        PersistedData{0, "id2", "idx", "{}", Operation::CREATE, 1},
        PersistedData{0, "id3", "idx", oversizedPayload, Operation::CREATE, 1},
    };

    EXPECT_THROW(storage.submitBatch(batch), std::runtime_error);

    // Nothing remains -- not even "id1"/"id2", applied before "id3" triggered the rejection.
    EXPECT_TRUE(storage.fetchAll().empty());
}
