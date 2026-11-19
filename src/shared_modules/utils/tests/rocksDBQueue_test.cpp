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
#include "rocksDBQueueTestHelpers.hpp"
#include "rocksDBWrapper.hpp"
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <filesystem>
#include <future>
#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <thread>
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

namespace
{
    using namespace RocksDBQueueTestHelpers;

    constexpr auto RECLAIM_LOG {"is empty, compacting"};

    // Runs the action and returns the lines it logged.
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

    std::unique_ptr<RocksDBQueue<std::string>> openQueue(const Utils::RocksDBCompression compression,
                                                         const bool reclaimWhenEmpty)
    {
        return std::make_unique<RocksDBQueue<std::string>>(TEST_DB, false, compression, reclaimWhenEmpty);
    }

    // Pushes RECLAIM_ELEMENTS random values (twice the reclaim threshold) and pops them all, leaving deleted elements
    // in the files and memtables.
    void fillAndDrain(RocksDBQueue<std::string>& queue)
    {
        std::mt19937_64 generator {42};
        for (size_t i = 0; i < RECLAIM_ELEMENTS; ++i)
        {
            queue.push(randomValue(generator));
        }
        while (!queue.empty())
        {
            queue.pop();
        }
    }
} // namespace

// Test that a queue opened with the default arguments writes no compression, as before
TEST_F(RocksDBQueueTest, QueueDefaultHasNoCompression)
{
    queue->push("value");
    queue.reset();

    const auto options {latestDefaultColumnOptions(TEST_DB)};
    EXPECT_EQ(options.compression, rocksdb::kNoCompression);
    EXPECT_NE(options.bottommost_compression, rocksdb::kZSTD);
}

// Test that a queue opened with LZ4_ZSTD writes compressed files only
TEST_F(RocksDBQueueTest, QueueLz4ZstdCompresses)
{
    queue.reset();
    queue = openQueue(Utils::RocksDBCompression::LZ4_ZSTD, false);
    std::mt19937_64 generator {42};
    for (size_t i = 0; i < RECLAIM_ELEMENTS / 2; ++i)
    {
        queue->push(randomValue(generator));
    }
    // A flush still running at close is dropped. Once it ends, its WAL file is deleted and only the current one is
    // left.
    const auto flushed = []()
    {
        auto logs {0};
        for (const auto& entry : std::filesystem::directory_iterator(TEST_DB))
        {
            logs += entry.path().extension() == ".log" ? 1 : 0;
        }
        return logs == 1 && sstBytes(TEST_DB) > 0;
    };
    const auto deadline {std::chrono::steady_clock::now() + std::chrono::seconds(30)};
    while (!flushed() && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    queue.reset();

    const auto options {latestDefaultColumnOptions(TEST_DB)};
    EXPECT_EQ(options.compression, rocksdb::kLZ4Compression);
    EXPECT_EQ(options.bottommost_compression, rocksdb::kZSTD);

    const auto compressions {tableCompressions(TEST_DB)};
    ASSERT_FALSE(compressions.empty());
    EXPECT_EQ(compressions.count("NoCompression"), 0);
    for (const auto& name : compressions)
    {
        EXPECT_TRUE(name == "LZ4" || name == "ZSTD") << name;
    }
}

// Test that an emptied queue gives back the space of its deleted elements and keeps working
TEST_F(RocksDBQueueTest, ReclaimGivesBackSpaceWhenEmpty)
{
    queue.reset();
    queue = openQueue(Utils::RocksDBCompression::LZ4_ZSTD, true);
    fillAndDrain(*queue);

    const auto logs = captureLogs([this]() { queue->reclaimSpace(); });
    EXPECT_NE(logs.find(RECLAIM_LOG), std::string::npos) << logs;
    queue.reset();
    EXPECT_LT(sstBytes(TEST_DB), RECLAIMED_MAX_BYTES);

    queue = openQueue(Utils::RocksDBCompression::LZ4_ZSTD, true);
    EXPECT_TRUE(queue->empty());
    queue->push("value");
    EXPECT_EQ(queue->front(), "value");
}

// Test that a queue whose files and memtables are under the threshold is not compacted
TEST_F(RocksDBQueueTest, ReclaimSkipsSmallQueues)
{
    queue.reset();
    queue = openQueue(Utils::RocksDBCompression::LZ4_ZSTD, true);
    for (auto i = 0; i < 10; ++i)
    {
        queue->push(std::string(1024, 'x'));
    }
    while (!queue->empty())
    {
        queue->pop();
    }

    const auto logs = captureLogs([this]() { queue->reclaimSpace(); });
    EXPECT_EQ(logs.find(RECLAIM_LOG), std::string::npos) << logs;
}

// Test that a queue opened without reclaim keeps its files
TEST_F(RocksDBQueueTest, ReclaimOffByDefault)
{
    queue.reset();
    queue = openQueue(Utils::RocksDBCompression::LZ4_ZSTD, false);
    fillAndDrain(*queue);
    const auto before {sstBytes(TEST_DB)};

    const auto logs = captureLogs([this]() { queue->reclaimSpace(); });
    EXPECT_EQ(logs.find(RECLAIM_LOG), std::string::npos) << logs;
    // A flush still running can only add to the files; a skipped reclaim never removes any.
    EXPECT_GE(sstBytes(TEST_DB), before);
}

// Test that an element pushed between the emptiness check and the reclaim is kept
TEST_F(RocksDBQueueTest, ReclaimKeepsElementsPushedMeanwhile)
{
    queue.reset();
    queue = openQueue(Utils::RocksDBCompression::LZ4_ZSTD, true);
    fillAndDrain(*queue);
    queue->push("kept");

    const auto logs = captureLogs([this]() { queue->reclaimSpace(); });
    EXPECT_NE(logs.find(RECLAIM_LOG), std::string::npos) << logs;
    EXPECT_EQ(queue->size(), 1);
    EXPECT_EQ(queue->front(), "kept");

    queue.reset();
    queue = openQueue(Utils::RocksDBCompression::LZ4_ZSTD, true);
    ASSERT_EQ(queue->size(), 1);
    EXPECT_EQ(queue->front(), "kept");
}

// Test that a canceled reclaim returns at once and leaves the files as they are
TEST_F(RocksDBQueueTest, ReclaimCanceled)
{
    queue.reset();
    queue = openQueue(Utils::RocksDBCompression::LZ4_ZSTD, true);
    queue->cancelReclaim();
    fillAndDrain(*queue);
    const auto before {sstBytes(TEST_DB)};

    const auto logs = captureLogs([this]() { queue->reclaimSpace(); });
    EXPECT_EQ(logs.find(RECLAIM_LOG), std::string::npos) << logs;
    // A flush still running can only add to the files; a skipped reclaim never removes any.
    EXPECT_GE(sstBytes(TEST_DB), before);
}

// Test that canceling a reclaim that is running stops it and leaves the queue usable
TEST_F(RocksDBQueueTest, ReclaimCanceledWhileRunning)
{
    queue.reset();
    queue = openQueue(Utils::RocksDBCompression::LZ4_ZSTD, true);
    fillAndDrain(*queue);

    std::promise<void> started;
    Log::deassignLogFunction();
    Log::assignLogFunction(
        [&started](const int, const char*, const char*, const int, const char*, const char* message, va_list)
        {
            if (std::string_view {message}.find(RECLAIM_LOG) != std::string_view::npos)
            {
                started.set_value();
            }
        });
    std::thread reclaim {[this]() { queue->reclaimSpace(); }};
    started.get_future().wait();
    queue->cancelReclaim();
    reclaim.join();
    Log::deassignLogFunction();

    queue->push("value");
    EXPECT_EQ(queue->front(), "value");
}
