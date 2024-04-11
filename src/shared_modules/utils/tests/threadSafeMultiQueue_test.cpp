/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * April 11, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "threadSafeMultiQueue_test.hpp"
#include <thread>

void ThreadSafeMultiQueueTest::SetUp()
{
    std::filesystem::remove_all("test");
    // Not apply
};

void ThreadSafeMultiQueueTest::TearDown() {
    // Not apply
};

TEST_F(ThreadSafeMultiQueueTest, Ctor)
{
    Utils::
        TSafeMultiQueue<rocksdb::Slice, rocksdb::PinnableSlice, RocksDBQueueCF<rocksdb::Slice, rocksdb::PinnableSlice>>
            queue(RocksDBQueueCF<rocksdb::Slice, rocksdb::PinnableSlice>("test"));
    EXPECT_TRUE(queue.empty());
    EXPECT_FALSE(queue.cancelled());
}

TEST_F(ThreadSafeMultiQueueTest, FrontAndPop)
{
    Utils::
        TSafeMultiQueue<rocksdb::Slice, rocksdb::PinnableSlice, RocksDBQueueCF<rocksdb::Slice, rocksdb::PinnableSlice>>
            queue(RocksDBQueueCF<rocksdb::Slice, rocksdb::PinnableSlice>("test"));

    constexpr auto EXPECTED_COUNT_MSGS = 1;
    auto count = 0;

    std::thread t1 {[&]()
                    {
                        auto retVal = queue.front();
                        EXPECT_STREQ("DATA", retVal.first.data());
                        ++count;
                    }};
    rocksdb::Slice slice("DATA");
    queue.push("000", slice);
    t1.join();
    EXPECT_FALSE(queue.empty());
    queue.pop("000");
    EXPECT_TRUE(queue.empty());
    EXPECT_EQ(EXPECTED_COUNT_MSGS, count);
}

TEST_F(ThreadSafeMultiQueueTest, MultiDataFrontAndPop)
{
    Utils::
        TSafeMultiQueue<rocksdb::Slice, rocksdb::PinnableSlice, RocksDBQueueCF<rocksdb::Slice, rocksdb::PinnableSlice>>
            queue(RocksDBQueueCF<rocksdb::Slice, rocksdb::PinnableSlice>("test"));

    constexpr auto EXPECTED_COUNT_MSGS = 1;
    auto count = 0;

    std::thread t1 {[&]()
                    {
                        auto retVal = queue.front();
                        EXPECT_STREQ("DATA", retVal.first.data());
                        ++count;
                    }};
    rocksdb::Slice slice("DATA");
    queue.push("000", slice);
    queue.push("001", slice);
    t1.join();
    EXPECT_FALSE(queue.empty());
    queue.pop("000");
    EXPECT_FALSE(queue.empty());
    queue.pop("001");
    EXPECT_TRUE(queue.empty());
    EXPECT_EQ(EXPECTED_COUNT_MSGS, count);
}

TEST_F(ThreadSafeMultiQueueTest, Cancel)
{
    Utils::
        TSafeMultiQueue<rocksdb::Slice, rocksdb::PinnableSlice, RocksDBQueueCF<rocksdb::Slice, rocksdb::PinnableSlice>>
            queue(RocksDBQueueCF<rocksdb::Slice, rocksdb::PinnableSlice>("test"));
    std::thread t1 {[&]()
                    {
                        queue.front();
                    }};

    queue.cancel();
    t1.join();
    EXPECT_TRUE(queue.cancelled());
}

