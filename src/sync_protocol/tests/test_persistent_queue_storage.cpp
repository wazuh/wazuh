/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include "persistent_queue_storage.hpp"

TEST(PersistentQueueStorageTest, SaveAndLoad)
{
    PersistentQueueStorage storage(":memory:");

    PersistedData data
    {
        .seq = 1,
        .id = "test_id",
        .index = "test_index",
        .data = "{\"value\":42}",
        .operation = Wazuh::SyncSchema::Operation::Upsert
    };

    storage.save("FIM", data);
    auto results = storage.loadAll("FIM");

    ASSERT_EQ(results.size(), static_cast<size_t>(1));
    EXPECT_EQ(results[0].seq, data.seq);
    EXPECT_EQ(results[0].id, data.id);
    EXPECT_EQ(results[0].index, data.index);
    EXPECT_EQ(results[0].data, data.data);
    EXPECT_EQ(results[0].operation, data.operation);
}

TEST(PersistentQueueStorageTest, SaveException)
{
    PersistentQueueStorage storage(":memory:");

    PersistedData data
    {
        .seq = 1,
        .id = "test_id",
        .index = "test_index",
        .data = "{\"value\":42}",
        .operation = Wazuh::SyncSchema::Operation::Upsert
    };

    storage.save("FIM", data);
    // An exception is expected because an attempt is made to insert a row with the same primary key twice.
    EXPECT_ANY_THROW(storage.save("FIM", data));
}

TEST(PersistentQueueStorageTest, Save2AndRemoveAll)
{
    PersistentQueueStorage storage(":memory:");

    PersistedData data
    {
        .seq = 1,
        .id = "test_id",
        .index = "test_index",
        .data = "{\"value\":42}",
        .operation = Wazuh::SyncSchema::Operation::Upsert
    };

    PersistedData data2
    {
        .seq = 2,
        .id = "test_id_2",
        .index = "test_index",
        .data = "{\"value\":142}",
        .operation = Wazuh::SyncSchema::Operation::Upsert
    };

    storage.save("FIM", data);
    storage.save("FIM", data2);
    storage.removeAll("FIM");
    auto results = storage.loadAll("FIM");

    ASSERT_EQ(results.size(), static_cast<size_t>(0));
}
