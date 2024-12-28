/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 4, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "rocksDBQueue_test.hpp"
#include "rocksDBWrapper.hpp"
#include <filesystem>

void RocksDBQueueTest::SetUp()
{
    std::error_code ec;
    std::filesystem::remove_all(TEST_DB, ec);
    queue = std::make_unique<RocksDBQueue<std::string>>(TEST_DB);
};

void RocksDBQueueTest::TearDown() {};

// Test pushing elements and validating size and non-emptiness of the queue
TEST_F(RocksDBQueueTest, PushIncreasesSizeAndNonEmptyState)
{
    // Push elements into the queue
    queue->push("first");
    queue->push("second");
    queue->push("third");

    // Verify the size of the queue
    EXPECT_EQ(queue->size(), 3);

    // Verify the queue is not empty
    EXPECT_FALSE(queue->empty());
}

// Test accessing elements at specific indices
TEST_F(RocksDBQueueTest, AtMethodReturnsCorrectElement)
{
    // Push elements into the queue
    queue->push("first");
    queue->push("second");
    queue->push("third");

    // Retrieve the second element (index 1, assuming 0-based indexing)
    auto value = queue->at(1);

    // Verify the value of the second element
    EXPECT_EQ(value, "second");
}

// Test correct key padding for RocksDB
TEST_F(RocksDBQueueTest, KeyPaddingIsCorrect)
{
    // Push elements into the queue
    queue->push("value1");
    queue->push("value2");

    // Open RocksDB in read-only mode to verify keys
    rocksdb::DB* db;
    rocksdb::Options options;
    options.create_if_missing = true;
    rocksdb::Status status = rocksdb::DB::OpenForReadOnly(options, TEST_DB, &db);

    ASSERT_TRUE(status.ok()) << "Failed to open database in read-only mode: " << status.ToString();

    {
        // Use iterator to verify keys
        auto it = std::unique_ptr<rocksdb::Iterator>(db->NewIterator(rocksdb::ReadOptions()));

        // Validate the first key and its value
        it->SeekToFirst();
        ASSERT_TRUE(it->Valid());
        EXPECT_EQ(it->key().ToString(), "00000000000000000001");
        EXPECT_EQ(it->value().ToString(), "value1");

        // Validate the second key and its value
        it->Next();
        ASSERT_TRUE(it->Valid());
        EXPECT_EQ(it->key().ToString(), "00000000000000000002");
        EXPECT_EQ(it->value().ToString(), "value2");

        // Ensure no more keys exist
        it->Next();
        EXPECT_FALSE(it->Valid());
    }

    // Clean up RocksDB instance
    delete db;
}

// Test correct key padding for RocksDB with pre-existent keys not padded
TEST_F(RocksDBQueueTest, KeyPaddingIsCorrectPreExistentKeysNotPadded)
{
    // Load pre-existent keys into the database
    queue.reset();
    rocksdb::DB* db;
    rocksdb::Options options;
    options.create_if_missing = true;
    rocksdb::Status status = rocksdb::DB::Open(options, TEST_DB, &db);
    ASSERT_TRUE(status.ok()) << "Failed to open database: " << status.ToString();

    std::string binaryValue = {'\xA1', '\x3A', '\x5F', '\x00', '\x10', '\xDA', '\x0F', '\x1A'};

    db->Put(rocksdb::WriteOptions(), "1", "value1");
    db->Put(rocksdb::WriteOptions(), "2", "value2");
    db->Put(rocksdb::WriteOptions(), "3", binaryValue);
    delete db;

    // Retrieve the values
    queue = std::make_unique<RocksDBQueue<std::string>>(TEST_DB);

    EXPECT_EQ(queue->size(), 3);

    auto value = queue->front();
    EXPECT_EQ(value, "value1");
    queue->pop();

    value = queue->front();
    EXPECT_EQ(value, "value2");
    queue->pop();

    value = queue->front();
    EXPECT_EQ(value, binaryValue);
    queue->pop();
}

// Test popping an element updates the queue correctly
TEST_F(RocksDBQueueTest, PopMethodRemovesFirstElement)
{
    // Push elements into the queue
    queue->push("value1");
    queue->push("value2");

    // Pop the first element
    queue->pop();

    // Open RocksDB in read-only mode to verify keys
    rocksdb::DB* db;
    rocksdb::Options options;
    options.create_if_missing = true;
    rocksdb::Status status = rocksdb::DB::OpenForReadOnly(options, TEST_DB, &db);

    ASSERT_TRUE(status.ok()) << "Failed to open database in read-only mode: " << status.ToString();

    {
        // Use iterator to verify keys
        auto it = std::unique_ptr<rocksdb::Iterator>(db->NewIterator(rocksdb::ReadOptions()));

        // Validate the first remaining key and its value
        it->SeekToFirst();
        ASSERT_TRUE(it->Valid());
        EXPECT_EQ(it->key().ToString(), "00000000000000000002");
        EXPECT_EQ(it->value().ToString(), "value2");

        // Ensure no more keys exist
        it->Next();
        EXPECT_FALSE(it->Valid());
    }

    // Clean up RocksDB instance
    delete db;
}

// Test retrieving the front element of the queue
TEST_F(RocksDBQueueTest, FrontMethodReturnsFirstElement)
{
    // Push elements into the queue
    queue->push("value1");
    queue->push("value2");

    // Retrieve the front element
    auto value = queue->front();

    // Verify the value of the front element
    EXPECT_EQ(value, "value1");
}
