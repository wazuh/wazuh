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
        MOCK_METHOD(void, removeAllSynced, (), (override));
        MOCK_METHOD(void, resetAllSyncing, (), (override));
        MOCK_METHOD(void, removeByIndex, (const std::string& index), (override));
};

TEST(PersistentQueueTest, ConstructorCallsLoadAllForEachModule)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    LoggerFunc testLogger = [](modules_log_level_t, const std::string&) {};
    PersistentQueue queue(":memory:", testLogger, mockStorage);
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
