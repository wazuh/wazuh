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

#include "asyncValueDispatcher.hpp"
#include <future>
#include <gtest/gtest.h>

class AsyncValueDispatcherTest : public ::testing::Test
{
protected:
    AsyncValueDispatcherTest() = default;
    ~AsyncValueDispatcherTest() override = default;
    void SetUp() override;
    void TearDown() override;
};

void AsyncValueDispatcherTest::SetUp() {
    // Not implemented
};

void AsyncValueDispatcherTest::TearDown() {
    // Not implemented
};

extern int ALLOCATION_COUNTER;
extern bool ENABLE_ALLOCATION_COUNTER;

constexpr auto BULK_SIZE {50};
TEST_F(AsyncValueDispatcherTest, Ctor)
{
    static std::queue<std::string> MESSAGES_TO_SEND_LIST;
    MESSAGES_TO_SEND_LIST.emplace("09876543210987654321");
    MESSAGES_TO_SEND_LIST.emplace("12345678901234567890");
    std::atomic<size_t> counter {0};
    std::promise<void> promise;

    Utils::AsyncValueDispatcher<std::string, std::function<void(std::string&&)>> dispatcher(
        [&counter, &promise](std::string&&)
        {
            counter++;

            if (counter == 2)
            {
                promise.set_value();
            }
        },
        "test-dispatcher",
        1,
        BULK_SIZE);
    ENABLE_ALLOCATION_COUNTER = true;
    while (!MESSAGES_TO_SEND_LIST.empty())
    {
        dispatcher.push(std::move(MESSAGES_TO_SEND_LIST.front()));
        MESSAGES_TO_SEND_LIST.pop();
    }
    promise.get_future().wait();
    EXPECT_EQ(2, counter);
    EXPECT_EQ(0, ALLOCATION_COUNTER);
    ENABLE_ALLOCATION_COUNTER = false;
    ALLOCATION_COUNTER = 0;
}

TEST_F(AsyncValueDispatcherTest, MultiThreadedProcessing)
{
    constexpr auto THREAD_COUNT = 2;
    constexpr auto MESSAGE_COUNT = 10;
    std::atomic<size_t> counter {0};
    std::promise<void> promise;

    Utils::AsyncValueDispatcher<int, std::function<void(int)>> dispatcher(
        [&counter, &promise](int)
        {
            counter++;
            if (counter == MESSAGE_COUNT)
            {
                promise.set_value();
            }
        },
        "test-dispatcher",
        THREAD_COUNT,
        BULK_SIZE);

    for (int i = 0; i < MESSAGE_COUNT; ++i)
    {
        dispatcher.push(i);
    }

    promise.get_future().wait();
    EXPECT_EQ(MESSAGE_COUNT, counter);
    EXPECT_EQ(THREAD_COUNT, dispatcher.numberOfThreads());
}

TEST_F(AsyncValueDispatcherTest, QueueSizeLimits)
{
    constexpr auto QUEUE_SIZE = 10;
    std::atomic<size_t> counter {0};
    std::promise<void> promise;

    std::promise<void> pushPromise;

    Utils::AsyncValueDispatcher<int, std::function<void(int)>> dispatcher(
        [&counter, &promise, &pushPromise](int)
        {
            if (static bool first = true; first)
            {
                first = false;
                pushPromise.get_future().wait();
            }
            counter++;
            if (counter == QUEUE_SIZE)
            {
                promise.set_value();
            }
        },
        "test-dispatcher",
        1,
        QUEUE_SIZE);

    for (int i = 0; i < QUEUE_SIZE + 5; ++i)
    {
        dispatcher.push(i);
    }

    pushPromise.set_value();

    promise.get_future().wait();
    // we might process slightly more than QUEUE_SIZE (typically +1)
    // The important thing is that we don't process all QUEUE_SIZE + 5
    EXPECT_GE(counter, QUEUE_SIZE) << "Should process at least QUEUE_SIZE elements";
    EXPECT_LE(counter, QUEUE_SIZE + 2) << "Should not process significantly more than QUEUE_SIZE";
    EXPECT_LT(counter, QUEUE_SIZE + 5) << "Should discard some events due to queue limit";
}

TEST_F(AsyncValueDispatcherTest, ExceptionHandling)
{
    std::atomic<size_t> counter {0};
    std::atomic<size_t> processedCount {0};
    std::promise<void> promise;

    Utils::AsyncValueDispatcher<int, std::function<void(int)>> dispatcher(
        [&counter, &processedCount, &promise](int value)
        {
            processedCount++;
            if (value == 5)
            {
                throw std::runtime_error("Test exception");
            }
            counter++;
            if (processedCount == 10)
            {
                promise.set_value();
            }
        },
        "test-dispatcher",
        1,
        BULK_SIZE);

    for (int i = 0; i < 10; ++i)
    {
        dispatcher.push(i);
    }

    promise.get_future().wait();
    EXPECT_EQ(9, counter);
    EXPECT_EQ(10, processedCount);
}

TEST_F(AsyncValueDispatcherTest, CancelFunctionality)
{
    std::atomic<size_t> counter {0};
    std::promise<void> promise;

    Utils::AsyncValueDispatcher<int, std::function<void(int)>> dispatcher(
        [&counter, &promise](int)
        {
            counter++;
            if (counter == 5)
            {
                promise.set_value();
            }
        },
        "test-dispatcher",
        1,
        BULK_SIZE);

    for (int i = 0; i < 10; ++i)
    {
        dispatcher.push(i);
    }

    promise.get_future().wait();
    EXPECT_FALSE(dispatcher.cancelled());

    dispatcher.cancel();
    EXPECT_TRUE(dispatcher.cancelled());

    for (int i = 10; i < 20; ++i)
    {
        dispatcher.push(i);
    }

    EXPECT_EQ(10, counter);
}

TEST_F(AsyncValueDispatcherTest, DifferentDataTypes)
{
    std::atomic<size_t> counter {0};
    std::promise<void> promise;

    Utils::AsyncValueDispatcher<std::string, std::function<void(std::string&&)>> dispatcher(
        [&counter, &promise](std::string&&)
        {
            counter++;
            if (counter == 3)
            {
                promise.set_value();
            }
        },
        "test-dispatcher",
        1,
        BULK_SIZE);

    dispatcher.push("Hello");
    dispatcher.push("World");
    dispatcher.push("Test");

    promise.get_future().wait();
    EXPECT_EQ(3, counter);
}

TEST_F(AsyncValueDispatcherTest, LargeBulkProcessing)
{
    constexpr auto LARGE_COUNT = 100;
    std::atomic<size_t> counter {0};
    std::promise<void> promise;

    Utils::AsyncValueDispatcher<int, std::function<void(int)>> dispatcher(
        [&counter, &promise](int)
        {
            counter++;
            if (counter == LARGE_COUNT)
            {
                promise.set_value();
            }
        },
        "test-dispatcher",
        2,
        LARGE_COUNT);

    for (int i = 0; i < LARGE_COUNT; ++i)
    {
        dispatcher.push(i);
    }

    promise.get_future().wait();
    EXPECT_EQ(LARGE_COUNT, counter);
}

TEST_F(AsyncValueDispatcherTest, CaptureWarningMsg)
{
    std::promise<void> promise;
    std::atomic<bool> warningCaptured {false};
    // Custom function that will capture and compare the warning log message.
    Log::assignLogFunction(
        [&promise, &warningCaptured](const int logLevel,
                                     const char* tag,
                                     const char* file,
                                     const int line,
                                     const char* func,
                                     const char* message,
                                     va_list args)
        {
            // Receives the exception message from the dispatch method.
            if (logLevel == Log::LOGLEVEL_DEBUG)
            {
                // Format the message.
                char buffer[4096];
                vsnprintf(buffer, sizeof(buffer), message, args);
                std::string formattedMsg(buffer);
                // Compare expected message.
                EXPECT_EQ("Dispatch handler error, Test exception", formattedMsg);
                warningCaptured = true;
                // Avoid multiple captures.
                try
                {
                    promise.set_value();
                }
                catch (...)
                {
                }
            }
        });

    std::string testMsg {"Test message"};
    Utils::AsyncValueDispatcher<std::string, std::function<void(std::string)>> dispatcher(
        [testMsg](const std::string& data)
        {
            EXPECT_EQ(testMsg, data);
            throw std::runtime_error("Test exception");
        },
        "test-dispatcher");

    dispatcher.push(testMsg);
    // Wait for the warning log to be captured.
    auto status = promise.get_future().wait_for(std::chrono::seconds(5));
    EXPECT_EQ(status, std::future_status::ready);

    EXPECT_EQ(warningCaptured.load(), true);

    // Teardown
    dispatcher.cancel();
    Log::deassignLogFunction();
}

TEST_F(AsyncValueDispatcherTest, Push_ReturnsTrueWhenAccepted)
{
    Utils::AsyncValueDispatcher<int, std::function<void(int)>> dispatcher([](int) {}, "test-dispatcher", 1, /*maxQueueSize*/ 10);
    EXPECT_TRUE(dispatcher.push(42));
}

TEST_F(AsyncValueDispatcherTest, Push_ReturnsFalseWhenQueueFull)
{
    constexpr auto QUEUE_SIZE = 2;
    std::promise<void> blockWorker;
    std::shared_future<void> blockFuture = blockWorker.get_future().share();

    // Single worker blocks on the first message so subsequent pushes pile up on
    // the queue until it hits maxQueueSize. Any push beyond that must return
    // false, signalling the drop to the caller.
    Utils::AsyncValueDispatcher<int, std::function<void(int)>> dispatcher([blockFuture](int) { blockFuture.wait(); },
                                                                          "test-dispatcher",
                                                                          /*numberOfThreads*/ 1,
                                                                          QUEUE_SIZE);

    // First push is consumed by the worker (which then blocks).
    EXPECT_TRUE(dispatcher.push(1));
    // Give the worker a moment to pick up the first message.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // The next QUEUE_SIZE pushes fill the bounded queue.
    EXPECT_TRUE(dispatcher.push(2));
    EXPECT_TRUE(dispatcher.push(3));

    // Anything past QUEUE_SIZE is dropped.
    EXPECT_FALSE(dispatcher.push(4));
    EXPECT_FALSE(dispatcher.push(5));

    // Release the worker so the dispatcher can shut down cleanly.
    blockWorker.set_value();
}

TEST_F(AsyncValueDispatcherTest, Push_ReturnsFalseAfterCancel)
{
    Utils::AsyncValueDispatcher<int, std::function<void(int)>> dispatcher([](int) {}, "test-dispatcher", 1, /*maxQueueSize*/ 10);
    dispatcher.cancel();
    EXPECT_FALSE(dispatcher.push(7));
}

TEST_F(AsyncValueDispatcherTest, Push_ReturnsTrueOnUnlimitedQueue)
{
    // Default constructor uses UNLIMITED_QUEUE_SIZE.
    std::promise<void> blockWorker;
    std::shared_future<void> blockFuture = blockWorker.get_future().share();
    Utils::AsyncValueDispatcher<int, std::function<void(int)>> dispatcher([blockFuture](int) { blockFuture.wait(); },
                                                                          "test-dispatcher",
                                                                          1);

    // Push more items than any reasonable bounded queue would accept; with the
    // unlimited size, every push must succeed.
    for (int i = 0; i < 1000; ++i)
    {
        EXPECT_TRUE(dispatcher.push(i));
    }

    blockWorker.set_value();
}
