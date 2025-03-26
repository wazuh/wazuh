/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <future>
#include <memory>
#include <thread>

#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <base/utils/rocksDBQueue.hpp>
#include <base/utils/threadEventDispatcher.hpp>
#include <base/utils/threadSafeMultiQueue.hpp>

class ThreadEventDispatcherTest : public ::testing::Test
{
protected:
    ThreadEventDispatcherTest() = default;
    ~ThreadEventDispatcherTest() override = default;
    void SetUp() override;
    void TearDown() override;
};

auto constexpr TEST_DB = "test.db";

void ThreadEventDispatcherTest::SetUp()
{
    logging::testInit();
    std::filesystem::remove_all(TEST_DB);
};

void ThreadEventDispatcherTest::TearDown()
{
    std::filesystem::remove_all(TEST_DB);
};

constexpr auto BULK_SIZE {50};
TEST_F(ThreadEventDispatcherTest, ConstructorTestSingleThread)
{
    static const std::vector<int> MESSAGES_TO_SEND_LIST {120, 100};

    for (auto MESSAGES_TO_SEND : MESSAGES_TO_SEND_LIST)
    {
        std::atomic<size_t> counter {0};
        std::promise<void> promise;
        auto index {0};

        ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>> dispatcher(
            [&counter, &index, &MESSAGES_TO_SEND, &promise](std::queue<std::string>& data)
            {
                counter += data.size();
                while (!data.empty())
                {
                    auto value = data.front();
                    data.pop();
                    EXPECT_EQ(std::to_string(index), value);
                    ++index;
                }

                if (counter == MESSAGES_TO_SEND)
                {
                    promise.set_value();
                }
            },
            {.dbPath = TEST_DB, .bulkSize = BULK_SIZE});

        for (int i = 0; i < MESSAGES_TO_SEND; ++i)
        {
            dispatcher.push(std::to_string(i));
        }
        promise.get_future().wait_for(std::chrono::seconds(10));
        EXPECT_EQ(MESSAGES_TO_SEND, counter);
    }
}

TEST_F(ThreadEventDispatcherTest, ConstructorTestMultiThread)
{
    static const std::vector<int> MESSAGES_TO_SEND_LIST {120, 100};

    for (auto MESSAGES_TO_SEND : MESSAGES_TO_SEND_LIST)
    {
        std::atomic<size_t> counter {0};
        std::promise<void> promise;
        std::atomic<size_t> index {0};

        ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>> dispatcher(
            [&counter, &index, &MESSAGES_TO_SEND, &promise](std::queue<std::string>& data)
            {
                counter += data.size();
                while (!data.empty())
                {
                    auto value = data.front();
                    data.pop();
                    EXPECT_EQ(std::to_string(index), value);
                    ++index;
                }

                if (counter == MESSAGES_TO_SEND)
                {
                    promise.set_value();
                }
            },
            {.dbPath = TEST_DB,
             .bulkSize = BULK_SIZE,
             .maxQueueSize = UNLIMITED_QUEUE_SIZE,
             .dispatcherType = ThreadEventDispatcherType::MULTI_THREADED_UNORDERED});

        for (int i = 0; i < MESSAGES_TO_SEND; ++i)
        {
            dispatcher.push(std::to_string(i));
        }
        promise.get_future().wait_for(std::chrono::seconds(10));
        EXPECT_EQ(MESSAGES_TO_SEND, counter);
    }
}

TEST_F(ThreadEventDispatcherTest, ConstructorTestMultiThreadStartWorker)
{
    static const std::vector<int> MESSAGES_TO_SEND_LIST {120, 100};

    for (auto MESSAGES_TO_SEND : MESSAGES_TO_SEND_LIST)
    {
        std::atomic<size_t> counter {0};
        std::promise<void> promise;
        std::atomic<size_t> index {0};

        ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>> dispatcher(
            {.dbPath = TEST_DB,
             .bulkSize = BULK_SIZE,
             .maxQueueSize = UNLIMITED_QUEUE_SIZE,
             .dispatcherType = ThreadEventDispatcherType::MULTI_THREADED_UNORDERED});

        for (int i = 0; i < MESSAGES_TO_SEND; ++i)
        {
            dispatcher.push(std::to_string(i));
        }

        dispatcher.startWorker(
            [&counter, &index, &MESSAGES_TO_SEND, &promise](std::queue<std::string>& data)
            {
                counter += data.size();
                while (!data.empty())
                {
                    auto value = data.front();
                    data.pop();
                    EXPECT_EQ(std::to_string(index), value);
                    ++index;
                }

                if (counter == MESSAGES_TO_SEND)
                {
                    promise.set_value();
                }
            });

        promise.get_future().wait_for(std::chrono::seconds(10));
        EXPECT_EQ(MESSAGES_TO_SEND, counter);
    }
}

TEST_F(ThreadEventDispatcherTest, ConstructorTestMultiThreadDifferentTypeExceptions)
{
    const auto MESSAGES_TO_SEND {100};
    const auto CONDITION {20};
    const auto BULK_SIZE {10};
    std::vector<int> messagesProcessed;
    std::mutex mutex;
    std::atomic<size_t> counter {0};
    std::promise<void> promise;
    std::atomic<bool> fail {true};

    TThreadEventDispatcher<rocksdb::Slice,
                           rocksdb::PinnableSlice,
                           std::function<void(std::queue<rocksdb::PinnableSlice>&)>>
        dispatcher(
            [&](std::queue<rocksdb::PinnableSlice>& data)
            {
                // We throw some exceptions to force the reinsertion
                if (counter % CONDITION == 0 && fail)
                {
                    fail = false;
                    throw std::runtime_error("Test exception: " + std::to_string(counter));
                }
                else
                {
                    fail = true;
                }

                counter += data.size();
                while (!data.empty())
                {
                    auto& value = data.front();
                    {
                        std::lock_guard<std::mutex> lock(mutex);
                        messagesProcessed.push_back(std::stoi(value.ToString()));
                    }
                    data.pop();
                }

                if (counter == MESSAGES_TO_SEND)
                {
                    promise.set_value();
                }
            },
            {.dbPath = TEST_DB,
             .bulkSize = BULK_SIZE,
             .maxQueueSize = UNLIMITED_QUEUE_SIZE,
             .dispatcherType = ThreadEventDispatcherType::MULTI_THREADED_UNORDERED});

    for (int i = 0; i < MESSAGES_TO_SEND; ++i)
    {
        dispatcher.push(std::to_string(i));
    }
    promise.get_future().wait_for(std::chrono::seconds(10));
    EXPECT_EQ(MESSAGES_TO_SEND, counter);

    // Check that all messages were processed. The failing event was reinserted.
    std::sort(messagesProcessed.begin(), messagesProcessed.end());
    for (int i = 0; i < MESSAGES_TO_SEND; ++i)
    {
        EXPECT_EQ(i, messagesProcessed[i]);
    }
}

TEST_F(ThreadEventDispatcherTest, ConstructorTestMultiThreadDifferentTypeExceptionsDropElement)
{
    const auto MESSAGES_TO_SEND {100};
    const auto CONDITION {20};
    const auto BULK_SIZE {10};
    std::vector<int> messagesProcessed;
    std::vector<int> messagesDiscarded;
    std::mutex mutex;
    std::atomic<size_t> counter {0};
    std::atomic<size_t> dropped {0};
    std::promise<void> promise;
    std::atomic<bool> fail {true};
    std::atomic<int> loops {0};

    TThreadEventDispatcher<rocksdb::Slice,
                           rocksdb::PinnableSlice,
                           std::function<void(std::queue<rocksdb::PinnableSlice>&)>>
        dispatcher(
            [&](std::queue<rocksdb::PinnableSlice>& data)
            {
                ++loops;
                counter += data.size();
                std::lock_guard<std::mutex> lock(mutex);
                while (!data.empty())
                {
                    auto& value = data.front();
                    {
                        if (std::stoi(value.ToString()) % CONDITION == 0)
                        {
                            try
                            {
                                throw std::runtime_error("Unexpected error during event processing");
                            }
                            catch (const std::exception& e)
                            {
                                // The log message is resposibility of the lambda function.
                                ++dropped;
                                messagesDiscarded.push_back(std::stoi(value.ToString()));
                                data.pop();
                                throw std::runtime_error(e.what());
                            }
                        }
                        messagesProcessed.push_back(std::stoi(value.ToString()));
                    }
                    data.pop();
                }

                // We need to wait until the reinserted events are processed.
                if (messagesProcessed.size() == MESSAGES_TO_SEND - dropped)
                {
                    promise.set_value();
                }
            },
            {.dbPath = TEST_DB,
             .bulkSize = BULK_SIZE,
             .maxQueueSize = UNLIMITED_QUEUE_SIZE,
             .dispatcherType = ThreadEventDispatcherType::MULTI_THREADED_UNORDERED});

    for (int i = 0; i < MESSAGES_TO_SEND; ++i)
    {
        dispatcher.push(std::to_string(i));
    }

    promise.get_future().wait_for(std::chrono::seconds(10));

    EXPECT_EQ(messagesProcessed.size(), MESSAGES_TO_SEND - dropped);

    // Check that all messages were processed. The failing event was dropped.
    std::sort(messagesProcessed.begin(), messagesProcessed.end());
    std::sort(messagesDiscarded.begin(), messagesDiscarded.end());

    auto indexProcessed {0};
    auto indexDiscarded {0};
    for (int i = 0; i < MESSAGES_TO_SEND; ++i)
    {
        if (i % CONDITION != 0)
        {
            EXPECT_EQ(i, messagesProcessed[indexProcessed++]);
        }
        else
        {
            EXPECT_EQ(i, messagesDiscarded[indexDiscarded++]);
        }
    }
}

TEST_F(ThreadEventDispatcherTest, CtorNoWorkerSingleThread)
{
    static const std::vector<int> MESSAGES_TO_SEND_LIST {120, 100};

    for (auto MESSAGES_TO_SEND : MESSAGES_TO_SEND_LIST)
    {
        std::atomic<size_t> counter {0};
        std::promise<void> promise;
        auto index {0};

        ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>> dispatcher(
            {.dbPath = TEST_DB, .bulkSize = BULK_SIZE});

        for (int i = 0; i < MESSAGES_TO_SEND; ++i)
        {
            dispatcher.push(std::to_string(i));
        }

        dispatcher.startWorker(
            [&counter, &index, &MESSAGES_TO_SEND, &promise](std::queue<std::string>& data)
            {
                counter += data.size();
                while (!data.empty())
                {
                    auto value = data.front();
                    data.pop();
                    EXPECT_EQ(std::to_string(index), value);
                    ++index;
                }

                if (counter == MESSAGES_TO_SEND)
                {
                    promise.set_value();
                }
            });

        promise.get_future().wait_for(std::chrono::seconds(10));
        EXPECT_EQ(MESSAGES_TO_SEND, counter);
    }
}

TEST_F(ThreadEventDispatcherTest, CtorPopFeatureSingleThread)
{
    constexpr auto MESSAGES_TO_SEND {1000};

    std::atomic<size_t> counter {0};
    std::promise<void> promise;
    std::promise<void> pushPromise;
    bool firstIteration {true};
    auto index {0};

    ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>> dispatcher(
        [&firstIteration, &pushPromise, &counter, &index, &promise](std::queue<std::string>& data)
        {
            if (firstIteration)
            {
                pushPromise.get_future().wait_for(std::chrono::seconds(10));
                firstIteration = false;
                throw std::runtime_error("Test exception");
            }
            counter += data.size();
            while (!data.empty())
            {
                auto value = data.front();
                data.pop();
                EXPECT_EQ(std::to_string(index), value);
                ++index;
            }
            if (counter == MESSAGES_TO_SEND)
            {
                promise.set_value();
            }
        },
        {.dbPath = TEST_DB, .bulkSize = BULK_SIZE});

    for (int i = 0; i < MESSAGES_TO_SEND; ++i)
    {
        dispatcher.push(std::to_string(i));
    }
    pushPromise.set_value();
    promise.get_future().wait_for(std::chrono::seconds(10));
    EXPECT_EQ(MESSAGES_TO_SEND, counter);
}
