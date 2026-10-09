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
#include <cstdarg>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <string>
#include <utility>
#include <vector>

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

// Test that asking for elements the store cannot provide fails instead of waiting for keys that do not exist
TEST_F(RocksDBQueueTest, FrontQueueFailsWhenTheKeysAreUnreachable)
{
    queue.reset();
    rocksdb::DB* db;
    rocksdb::Options options;
    options.create_if_missing = true;
    rocksdb::Status status = rocksdb::DB::Open(options, TEST_DB, &db);
    ASSERT_TRUE(status.ok()) << "Failed to open database: " << status.ToString();

    // The queue counts this key as element 5 but neither the padded nor the plain key it builds for it exists.
    db->Put(rocksdb::WriteOptions(), "5a", "value");
    delete db;

    queue = std::make_unique<RocksDBQueue<std::string>>(TEST_DB);
    ASSERT_EQ(queue->size(), 1);

    std::queue<std::string> elements;
    EXPECT_THROW(queue->frontQueue(elements, 1), std::runtime_error);
    EXPECT_TRUE(elements.empty());
}

namespace
{
    // Runs `action` with a log function that collects the messages logged meanwhile.
    template<typename Action>
    std::string captureLogs(Action&& action)
    {
        std::string captured;
        Log::deassignLogFunction();
        Log::assignLogFunction(
            [&captured](const int, const char*, const char*, const int, const char*, const char* message, va_list args)
            {
                char buffer[1024] {};
                vsnprintf(buffer, sizeof(buffer), message, args);
                captured.append(buffer).append("\n");
            });
        action();
        Log::deassignLogFunction();
        return captured;
    }

    void writeRawKeys(const std::vector<std::pair<std::string, std::string>>& keys)
    {
        rocksdb::DB* db;
        rocksdb::Options options;
        options.create_if_missing = true;
        ASSERT_TRUE(rocksdb::DB::Open(options, TEST_DB, &db).ok());
        for (const auto& [key, value] : keys)
        {
            db->Put(rocksdb::WriteOptions(), key, value);
        }
        delete db;
    }
} // namespace

// Test that the startup reports stored keys the queue would never read
TEST_F(RocksDBQueueTest, StartupWarnsAboutKeysTheQueueCannotReach)
{
    queue.reset();
    writeRawKeys({{"5a", "value"}});

    const auto logs = captureLogs([this]() { queue = std::make_unique<RocksDBQueue<std::string>>(TEST_DB); });

    EXPECT_NE(logs.find("1 of 1 stored keys are neither the plain nor the padded"), std::string::npos) << logs;
}

// Test that a store mixing unpadded and padded keys starts without warnings, since both formats can be read
TEST_F(RocksDBQueueTest, StartupIsSilentOnAMixedStore)
{
    queue.reset();
    writeRawKeys({{"1", "value1"}, {"00000000000000000002", "value2"}, {"00000000000000000003", "value3"}});

    const auto logs = captureLogs([this]() { queue = std::make_unique<RocksDBQueue<std::string>>(TEST_DB); });

    EXPECT_TRUE(logs.empty()) << logs;
}

// Test that a store mixing both formats is read and drained in order, whichever the format of each key
TEST_F(RocksDBQueueTest, MixedStoreIsReadAndDrainedInOrder)
{
    queue.reset();
    writeRawKeys(
        {{"1", "value1"}, {"00000000000000000002", "value2"}, {"3", "value3"}, {"00000000000000000004", "value4"}});
    queue = std::make_unique<RocksDBQueue<std::string>>(TEST_DB);
    ASSERT_EQ(queue->size(), 4);

    std::queue<std::string> elements;
    ASSERT_NO_THROW(queue->frontQueue(elements, 4));
    for (const auto* expected : {"value1", "value2", "value3", "value4"})
    {
        ASSERT_FALSE(elements.empty());
        EXPECT_EQ(elements.front(), expected);
        elements.pop();
    }

    for (const auto* expected : {"value1", "value2", "value3", "value4"})
    {
        EXPECT_EQ(queue->front(), expected);
        queue->pop();
    }
    EXPECT_TRUE(queue->empty());
    queue.reset();

    // Each pop removed the key that was stored.
    rocksdb::DB* db;
    rocksdb::Options options;
    ASSERT_TRUE(rocksdb::DB::OpenForReadOnly(options, TEST_DB, &db).ok());
    auto it = std::unique_ptr<rocksdb::Iterator>(db->NewIterator(rocksdb::ReadOptions()));
    it->SeekToFirst();
    EXPECT_FALSE(it->Valid());
    it.reset();
    delete db;
}

// Test that a store that already has unpadded keys keeps writing unpadded keys
TEST_F(RocksDBQueueTest, PushOnUnpaddedKeysKeepsTheUnpaddedFormat)
{
    queue.reset();
    writeRawKeys({{"1", "value1"}, {"2", "value2"}});

    queue = std::make_unique<RocksDBQueue<std::string>>(TEST_DB);
    queue->push("value3");
    queue.reset();

    rocksdb::DB* db;
    rocksdb::Options options;
    ASSERT_TRUE(rocksdb::DB::OpenForReadOnly(options, TEST_DB, &db).ok());
    std::string value;
    EXPECT_TRUE(db->Get(rocksdb::ReadOptions(), "3", &value).ok());
    EXPECT_EQ(value, "value3");
    EXPECT_FALSE(db->Get(rocksdb::ReadOptions(), "00000000000000000003", &value).ok());
    delete db;

    queue = std::make_unique<RocksDBQueue<std::string>>(TEST_DB);
    for (const auto* expected : {"value1", "value2", "value3"})
    {
        EXPECT_EQ(queue->front(), expected);
        queue->pop();
    }
    EXPECT_TRUE(queue->empty());
}

// Test that a well formed store starts without warnings
TEST_F(RocksDBQueueTest, StartupIsSilentWithWellFormedKeys)
{
    queue->push("value1");
    queue->push("value2");
    queue.reset();

    const auto logs = captureLogs([this]() { queue = std::make_unique<RocksDBQueue<std::string>>(TEST_DB); });

    EXPECT_TRUE(logs.empty()) << logs;
    EXPECT_EQ(queue->size(), 2);
}

// Test that a corrupted block found at startup is repaired, and that the queue then either accepts elements or rejects
// them because its bounds are unreliable
TEST_F(RocksDBQueueTest, StartupRepairsACorruptedBlockOfAnSstFile)
{
    // Values that do not compress, so that the file has several data blocks.
    std::mt19937 generator {42};
    std::uniform_int_distribution<int> letters {'a', 'z'};
    for (auto i = 0; i < 100; ++i)
    {
        std::string value(200, ' ');
        for (auto& character : value)
        {
            character = static_cast<char>(letters(generator));
        }
        queue->push(value);
    }
    queue.reset();

    // Moves the keys from the log to an .sst file.
    {
        rocksdb::DB* db;
        rocksdb::Options options;
        ASSERT_TRUE(rocksdb::DB::Open(options, TEST_DB, &db).ok());
        ASSERT_TRUE(db->Flush(rocksdb::FlushOptions()).ok());
        delete db;
    }

    std::filesystem::path sst;
    for (const auto& entry : std::filesystem::directory_iterator(TEST_DB))
    {
        if (entry.path().extension() == ".sst" && (sst.empty() || entry.file_size() > std::filesystem::file_size(sst)))
        {
            sst = entry.path();
        }
    }
    ASSERT_FALSE(sst.empty());

    // Overwrites 64 bytes in the middle of the file, inside its data blocks.
    {
        std::fstream file {sst, std::ios::in | std::ios::out | std::ios::binary};
        ASSERT_TRUE(file.is_open());
        file.seekp(static_cast<std::streamoff>(std::filesystem::file_size(sst) / 2));
        const std::string garbage(64, '\xff');
        file.write(garbage.data(), static_cast<std::streamsize>(garbage.size()));
    }

    std::unique_ptr<RocksDBQueue<std::string>> repaired;
    const auto logs = captureLogs(
        [&repaired]() { EXPECT_NO_THROW(repaired = std::make_unique<RocksDBQueue<std::string>>(TEST_DB)); });
    ASSERT_NE(repaired, nullptr);

    // The corruption is found and the database repaired, either when opening it or when scanning its keys.
    EXPECT_TRUE(logs.find("Repairing the database") != std::string::npos ||
                logs.find("was repaired") != std::string::npos)
        << logs;

    try
    {
        repaired->push("after the repair");
        EXPECT_GE(repaired->size(), 1);
        EXPECT_NO_THROW(repaired->front());
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_NE(std::string {e.what()}.find("bounds"), std::string::npos) << e.what();
    }
}
