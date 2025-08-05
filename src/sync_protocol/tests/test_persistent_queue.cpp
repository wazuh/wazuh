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
};

TEST(PersistentQueueTest, ConstructorCallsLoadAllForEachModule)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    PersistentQueue queue(mockStorage);
}

TEST(PersistentQueueTest, SubmitStoresInMemoryAndStorage)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();
    EXPECT_CALL(*mockStorage, submitOrCoalesce(_)).Times(1);

    PersistentQueue queue(mockStorage);

    queue.submit("id1", "index1", "{}", Operation::CREATE);
}

TEST(PersistentQueueTest, SubmitRollbackSequenceOnPersistError)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    EXPECT_CALL(*mockStorage, submitOrCoalesce(_))
    .WillOnce(testing::Throw(std::runtime_error("Simulated DB error")))
    .WillOnce(testing::Return());

    PersistentQueue queue(mockStorage);

    EXPECT_THROW(queue.submit("id1", "idx1", "{}", Operation::CREATE), std::exception);

    EXPECT_NO_THROW(queue.submit("id2", "idx2", "{}", Operation::CREATE));
}

TEST(PersistentQueueTest, FetchAllReturnsAllMessages)
{
    auto mockStorage = std::make_shared<MockPersistentQueueStorage>();

    std::vector<PersistedData> fakeData =
    {
        {0, "id1", "idx", "{}", Operation::CREATE},
        {0, "id2", "idx", "{}", Operation::MODIFY}
    };

    EXPECT_CALL(*mockStorage, fetchAndMarkForSync())
    .WillOnce(testing::Return(fakeData));

    PersistentQueue queue(mockStorage);

    auto all = queue.fetchAndMarkForSync();
    EXPECT_EQ(all.size(), static_cast<size_t>(2));
}
