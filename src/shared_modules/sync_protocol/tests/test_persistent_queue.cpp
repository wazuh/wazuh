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
        MOCK_METHOD(std::vector<PersistedData>, fetchAndMarkForSync, (), (override));
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
    EXPECT_CALL(*mockStorage, submitOrCoalesce(_)).Times(1);

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);

    queue.submit("id1", "index1", "{}", Operation::CREATE, 1);
}

TEST(PersistentQueueTest, SubmitRollbackSequenceOnPersistError)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    EXPECT_CALL(*mockStorage, submitOrCoalesce(_))
    .WillOnce(testing::Throw(std::runtime_error("Simulated DB error")))
    .WillOnce(testing::Return());

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);

    EXPECT_THROW(queue.submit("id1", "idx1", "{}", Operation::CREATE, 1), std::exception);

    EXPECT_NO_THROW(queue.submit("id2", "idx2", "{}", Operation::CREATE, 2));
}

TEST(PersistentQueueTest, SubmitLogsErrorWhenPersistingFails)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    EXPECT_CALL(*mockStorage, submitOrCoalesce(_))
    .WillOnce(testing::Throw(std::runtime_error("Simulated persistence error")));

    // Capture the log message
    std::string capturedLogMessage;
    modules_log_level_t capturedLogLevel;
    LoggerFunc testLogger = [&capturedLogMessage, &capturedLogLevel](modules_log_level_t level, const std::string & message)
    {
        capturedLogLevel = level;
        capturedLogMessage = message;
    };

    PersistentQueue queue(":memory:", testLogger, mockStorage);

    EXPECT_THROW(queue.submit("id1", "idx1", "{}", Operation::CREATE, 0), std::runtime_error);

    // Verify that the specific error message was logged
    EXPECT_EQ(capturedLogLevel, LOG_ERROR);
    EXPECT_TRUE(capturedLogMessage.find("PersistentQueue: Error persisting message:") != std::string::npos);
    EXPECT_TRUE(capturedLogMessage.find("Simulated persistence error") != std::string::npos);
}

TEST(PersistentQueueTest, FetchAllReturnsAllMessages)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    std::vector<PersistedData> fakeData =
    {
        {0, "id1", "idx", "{}", Operation::CREATE, 0},
        {0, "id2", "idx", "{}", Operation::MODIFY, 0}
    };

    EXPECT_CALL(*mockStorage, fetchAndMarkForSync())
    .WillOnce(testing::Return(fakeData));

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);

    auto all = queue.fetchAndMarkForSync();
    EXPECT_EQ(all.size(), static_cast<size_t>(2));
}

TEST(PersistentQueueTest, FetchAndMarkForSyncThrowsOnStorageError)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    EXPECT_CALL(*mockStorage, fetchAndMarkForSync())
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
