/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "ipersistent_queue_storage.hpp"
#include "persistent_queue.hpp"

using ::testing::_;
using ::testing::Return;
using ::testing::SaveArg;

class MockPersistentQueueStorage : public IPersistentQueueStorage
{
    public:
        MOCK_METHOD(void, submitOrCoalesce, (const PersistedData& data), (override));
        MOCK_METHOD(void, submitBatch, (const std::vector<PersistedData>& batch), (override));
        MOCK_METHOD(std::vector<PersistedData>, fetchAndMarkForSync, (size_t maxItems), (override));
        MOCK_METHOD(std::vector<PersistedData>, fetchPending, (bool onlyDataValues), (override));
        MOCK_METHOD(void, removeAllSynced, (), (override));
        MOCK_METHOD(void, resetAllSyncing, (), (override));
        MOCK_METHOD(void, removeByIndex, (const std::string& index), (override));
        MOCK_METHOD(void, removeAllDataContext, (), (override));
        MOCK_METHOD(void, deleteDatabase, (), (override));
};

TEST(PersistentQueueTest, ConstructorCallsLoadAllForEachModule)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);
}

TEST(PersistentQueueTest, ConstructorThrowsWhenLoggerIsNull)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    // Pass null logger function
    LoggerFunc nullLogger = nullptr;

    EXPECT_THROW(
    {
        PersistentQueue queue(":memory:", nullLogger, mockStorage);
    }, std::invalid_argument);
}

TEST(PersistentQueueTest, ConstructorThrowsWhenResetAllSyncingFails)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    // Make resetAllSyncing throw an exception
    EXPECT_CALL(*mockStorage, resetAllSyncing())
    .WillOnce(testing::Throw(std::runtime_error("Simulated DB error")));

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    EXPECT_THROW(
    {
        PersistentQueue queue(":memory:", testLogger, mockStorage);
    }, std::runtime_error);
}

TEST(PersistentQueueTest, SubmitStoresInMemoryAndStorage)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    std::vector<PersistedData> flushedBatch;
    EXPECT_CALL(*mockStorage, submitBatch(_))
    .Times(1)
    .WillOnce(SaveArg<0>(&flushedBatch));

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    {
        PersistentQueue queue(":memory:", testLogger, mockStorage);
        queue.submit("id1", "index1", "{}", Operation::CREATE, 1);
    } // destructor joins flush thread, ensuring submitBatch has been called

    ASSERT_EQ(flushedBatch.size(), 1u);
    EXPECT_EQ(flushedBatch[0].id, "id1");
}

TEST(PersistentQueueTest, SubmitRollbackSequenceOnPersistError)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    // With double-buffer design, submitBatch errors are caught in flushBuffer().
    // submit() itself never throws — events are buffered and flushed asynchronously.
    EXPECT_CALL(*mockStorage, submitBatch(_))
    .WillOnce(testing::Throw(std::runtime_error("Simulated DB error")))
    .WillRepeatedly(testing::Return());

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);

    EXPECT_NO_THROW(queue.submit("id1", "idx1", "{}", Operation::CREATE, 1));
    EXPECT_NO_THROW(queue.submit("id2", "idx2", "{}", Operation::CREATE, 2));
}

TEST(PersistentQueueTest, SubmitLogsErrorWhenPersistingFails)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    EXPECT_CALL(*mockStorage, submitBatch(_))
    .WillOnce(testing::Throw(std::runtime_error("Simulated persistence error")));

    // Capture the log message
    std::string capturedLogMessage;
    modules_log_level_t capturedLogLevel;
    LoggerFunc testLogger = [&capturedLogMessage, &capturedLogLevel](modules_log_level_t level, const std::string & message)
    {
        capturedLogLevel = level;
        capturedLogMessage = message;
    };

    {
        PersistentQueue queue(":memory:", testLogger, mockStorage);
        queue.submit("id1", "idx1", "{}", Operation::CREATE, 0);
    } // destructor joins flush thread — guarantees log was written before assertions

    // Verify that the specific error message was logged
    EXPECT_EQ(capturedLogLevel, LOG_ERROR);
    EXPECT_TRUE(capturedLogMessage.find("PersistentQueue: Error flushing batch to storage:") != std::string::npos);
    EXPECT_TRUE(capturedLogMessage.find("Simulated persistence error") != std::string::npos);
}

TEST(PersistentQueueTest, FailedBatchIsRetainedAndRetriedOnNextFlushCycle)
{
    // Verifies the fix: a transient submitBatch() failure must not drop the batch.
    // The failed events stay in their buffer slot and are merged with newly
    // submitted events on the next flush of that slot.
    //
    // Drives every flush explicitly via fetchAndMarkForSync() (which calls the
    // synchronous flushPendingBuffer()) so the sequence is deterministic and
    // never depends on the background flush thread's timing.
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();
    LoggerFunc logger = [](modules_log_level_t, const std::string&) {};

    std::vector<PersistedData> retryBatch;

    EXPECT_CALL(*mockStorage, submitBatch(_))
    .WillOnce(::testing::Throw(std::runtime_error("Simulated transient storage error")))
    .WillOnce(Return())
    .WillOnce(SaveArg<0>(&retryBatch));

    EXPECT_CALL(*mockStorage, fetchAndMarkForSync(_) )
    .WillRepeatedly(Return(std::vector<PersistedData> {}));

    {
        PersistentQueue queue(":memory:", logger, mockStorage);

        // Buffer A gets "id1" and its flush fails -- the event must stay buffered.
        queue.submit("id1", "idx", "{}", Operation::CREATE, 1);
        queue.fetchAndMarkForSync();

        // Buffer B gets "id2" and its flush succeeds, flipping back to buffer A.
        queue.submit("id2", "idx", "{}", Operation::CREATE, 2);
        queue.fetchAndMarkForSync();

        // Buffer A now holds the still-unflushed "id1" plus this new "id3".
        queue.submit("id3", "idx", "{}", Operation::CREATE, 3);
        queue.fetchAndMarkForSync();
    }

    ASSERT_EQ(retryBatch.size(), 2u);
    EXPECT_EQ(retryBatch[0].id, "id1");
    EXPECT_EQ(retryBatch[1].id, "id3");
}

TEST(PersistentQueueTest, FetchAllReturnsAllMessages)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    std::vector<PersistedData> fakeData =
    {
        {0, "id1", "idx", "{}", Operation::CREATE, 0},
        {0, "id2", "idx", "{}", Operation::MODIFY, 0}
    };

    EXPECT_CALL(*mockStorage, fetchAndMarkForSync(_) )
    .WillOnce(testing::Return(fakeData));

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);

    auto all = queue.fetchAndMarkForSync();
    EXPECT_EQ(all.size(), static_cast<size_t>(2));
}

TEST(PersistentQueueTest, FetchAndMarkForSyncThrowsOnStorageError)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    EXPECT_CALL(*mockStorage, fetchAndMarkForSync(_) )
    .WillOnce(testing::Throw(std::runtime_error("Simulated error obtaining items for sync")));

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);

    EXPECT_THROW(queue.fetchAndMarkForSync(), std::exception);
}

TEST(PersistentQueueTest, ClearItemsByIndexCallsStorageRemoveByIndex)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    std::string capturedIndex;
    EXPECT_CALL(*mockStorage, removeByIndex(_))
    .Times(1)
    .WillOnce(SaveArg<0>(&capturedIndex));

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);

    queue.clearItemsByIndex("test_index");
    EXPECT_EQ(capturedIndex, "test_index");
}

TEST(PersistentQueueTest, ClearItemsByIndexThrowsOnStorageError)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    EXPECT_CALL(*mockStorage, removeByIndex(_))
    .WillOnce(testing::Throw(std::runtime_error("Simulated DB error")));

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);

    EXPECT_THROW(queue.clearItemsByIndex("test_index"), std::exception);
}

TEST(PersistentQueueTest, DeleteDatabaseCallsStorageDeleteDatabase)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    EXPECT_CALL(*mockStorage, deleteDatabase())
    .Times(1);

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);

    EXPECT_NO_THROW(queue.deleteDatabase());
}

TEST(PersistentQueueTest, DeleteDatabaseThrowsOnStorageError)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    EXPECT_CALL(*mockStorage, deleteDatabase())
    .WillOnce(testing::Throw(std::runtime_error("Simulated DB deletion error")));

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);

    EXPECT_THROW(queue.deleteDatabase(), std::exception);
}

TEST(PersistentQueueTest, ClearSyncedItemsCallsStorageRemoveAllSynced)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    EXPECT_CALL(*mockStorage, removeAllSynced())
    .Times(1);

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);

    EXPECT_NO_THROW(queue.clearSyncedItems());
}

TEST(PersistentQueueTest, ClearSyncedItemsThrowsOnStorageError)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    EXPECT_CALL(*mockStorage, removeAllSynced())
    .WillOnce(testing::Throw(std::runtime_error("Simulated error clearing synchronized items")));

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);

    EXPECT_THROW(queue.clearSyncedItems(), std::exception);
}

TEST(PersistentQueueTest, ResetSyncingItemsCallsStorageResetAllSyncing)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    // resetAllSyncing() is called twice: once during construction and once during the method call
    EXPECT_CALL(*mockStorage, resetAllSyncing())
    .Times(2);

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);

    EXPECT_NO_THROW(queue.resetSyncingItems());
}

TEST(PersistentQueueTest, ResetSyncingItemsThrowsOnStorageError)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    // Make the first call (constructor) succeed, but the second call (method) fail
    EXPECT_CALL(*mockStorage, resetAllSyncing())
    .WillOnce(testing::Return()) // Constructor call succeeds
    .WillOnce(testing::Throw(std::runtime_error("Simulated error resetting items"))); // Method call fails

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);

    EXPECT_THROW(queue.resetSyncingItems(), std::exception);
}

// Test to cover IPersistentQueue D0 destructor (delete through base pointer)
TEST(InterfaceDestructorTest, IPersistentQueueDeletingDestructor)
{
    // Create concrete implementation through base interface pointer
    IPersistentQueue* queue = nullptr;

    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};

    // Create PersistentQueue through base interface pointer
    queue = new PersistentQueue(":memory:", testLogger, mockStorage);

    // Delete through base pointer - this calls D0 destructor
    delete queue;
}

// ========================================
// Tests for fetchPendingItems()
// ========================================

TEST(PersistentQueueTest, fetchPendingItems_OnlyDataValues_True)
{
    /**
     * Test: fetchPendingItems with onlyDataValues=true should call storage's fetchPending(true)
     */

    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);

    // Create test data
    std::vector<PersistedData> expectedData;
    PersistedData item1;
    item1.seq = 0;
    item1.id = "test1";
    item1.index = "test-index";
    item1.data = R"({"test":"data"})";
    item1.operation = Operation::CREATE;
    item1.is_data_context = false;
    expectedData.push_back(item1);

    // Expect fetchPending to be called with onlyDataValues=true
    EXPECT_CALL(*mockStorage, fetchPending(true))
    .Times(1)
    .WillOnce(Return(expectedData));

    auto result = queue.fetchPendingItems(true);

    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0].id, "test1");
    EXPECT_FALSE(result[0].is_data_context);
}

TEST(PersistentQueueTest, fetchPendingItems_OnlyDataValues_False)
{
    /**
     * Test: fetchPendingItems with onlyDataValues=false should call storage's fetchPending(false)
     */

    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);

    // Create test data with both DataValue and DataContext
    std::vector<PersistedData> expectedData;

    PersistedData dataValue;
    dataValue.seq = 0;
    dataValue.id = "value1";
    dataValue.index = "test-index";
    dataValue.data = R"({"value":"data"})";
    dataValue.operation = Operation::CREATE;
    dataValue.is_data_context = false;
    expectedData.push_back(dataValue);

    PersistedData dataContext;
    dataContext.seq = 1;
    dataContext.id = "context1";
    dataContext.index = "test-index";
    dataContext.data = R"({"context":"data"})";
    dataContext.operation = Operation::MODIFY;
    dataContext.is_data_context = true;
    expectedData.push_back(dataContext);

    // Expect fetchPending to be called with onlyDataValues=false
    EXPECT_CALL(*mockStorage, fetchPending(false))
    .Times(1)
    .WillOnce(Return(expectedData));

    auto result = queue.fetchPendingItems(false);

    ASSERT_EQ(result.size(), 2);
    EXPECT_FALSE(result[0].is_data_context);
    EXPECT_TRUE(result[1].is_data_context);
}

TEST(PersistentQueueTest, fetchPendingItems_EmptyResult)
{
    /**
     * Test: fetchPendingItems should handle empty result from storage
     */

    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);

    std::vector<PersistedData> emptyData;

    EXPECT_CALL(*mockStorage, fetchPending(true))
    .Times(1)
    .WillOnce(Return(emptyData));

    auto result = queue.fetchPendingItems(true);

    EXPECT_TRUE(result.empty());
}

TEST(PersistentQueueTest, fetchPendingItems_ExceptionHandling)
{
    /**
     * Test: fetchPendingItems should handle exceptions from storage
     */

    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);

    // Make storage throw an exception
    EXPECT_CALL(*mockStorage, fetchPending(true))
    .Times(1)
    .WillOnce(::testing::Throw(std::runtime_error("Database error")));

    // Should throw the exception
    EXPECT_THROW(queue.fetchPendingItems(true), std::runtime_error);
}

// ========================================
// Tests for clearAllDataContext()
// ========================================

TEST(PersistentQueueTest, clearAllDataContext_Success)
{
    /**
     * Test: clearAllDataContext should call storage's removeAllDataContext
     */

    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);

    // Expect removeAllDataContext to be called once
    EXPECT_CALL(*mockStorage, removeAllDataContext())
    .Times(1);

    EXPECT_NO_THROW(queue.clearAllDataContext());
}

TEST(PersistentQueueTest, clearAllDataContext_ExceptionHandling)
{
    /**
     * Test: clearAllDataContext should handle exceptions from storage
     */

    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();
    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);

    // Make storage throw an exception
    EXPECT_CALL(*mockStorage, removeAllDataContext())
    .Times(1)
    .WillOnce(::testing::Throw(std::runtime_error("Database error")));

    // Should throw the exception
    EXPECT_THROW(queue.clearAllDataContext(), std::runtime_error);
}

// ========================================
// Tests for graceful shutdown / destructor
// ========================================

TEST(PersistentQueueTest, DestructorFlushesBufferedEventsOnGracefulShutdown)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();
    LoggerFunc logger = [](modules_log_level_t, const std::string&) {};

    std::vector<PersistedData> flushedBatch;
    EXPECT_CALL(*mockStorage, submitBatch(_))
    .Times(1)
    .WillOnce(SaveArg<0>(&flushedBatch));

    {
        PersistentQueue queue(":memory:", logger, mockStorage);
        queue.submit("id1", "idx", R"({"k":1})", Operation::CREATE, 1);
        queue.submit("id2", "idx", R"({"k":2})", Operation::MODIFY, 2);
        queue.submit("id3", "idx", R"({"k":3})", Operation::DELETE_, 3);
        // Destructor: sets m_stop=true, notifies flush thread, joins.
        // Flush thread wakes up, sees m_stop, swaps buffer, calls submitBatch.
    }

    // join() in destructor guarantees submitBatch has returned before we assert.
    ASSERT_EQ(flushedBatch.size(), 3u);
    EXPECT_EQ(flushedBatch[0].id, "id1");
    EXPECT_EQ(flushedBatch[1].id, "id2");
    EXPECT_EQ(flushedBatch[2].id, "id3");
}

TEST(PersistentQueueTest, DestructorWithEmptyBufferDoesNotCallSubmitBatch)
{
    // Verify that no spurious write happens when the buffer is empty at shutdown.
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();
    LoggerFunc logger = [](modules_log_level_t, const std::string&) {};

    EXPECT_CALL(*mockStorage, submitBatch(_)).Times(0);

    {
        PersistentQueue queue(":memory:", logger, mockStorage);
        // No events submitted — destructor must not call submitBatch.
    }
}
