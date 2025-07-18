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

static int allocationCounter = 0;
static bool enableAllocationCounter = false;

void* operator new(size_t size)
{
    if (enableAllocationCounter)

        allocationCounter++;
    return malloc(size);
}

constexpr auto BULK_SIZE {50};
TEST_F(AsyncValueDispatcherTest, Ctor)
{
    static std::queue<std::string> MESSAGES_TO_SEND_LIST;
    MESSAGES_TO_SEND_LIST.emplace("09876543210987654321");
    MESSAGES_TO_SEND_LIST.emplace("12345678901234567890");
    std::atomic<size_t> counter {0};
    std::promise<void> promise;

    Utils::AsyncValueDispatcher<std::string, std::function<void(std::string &&)>> dispatcher(
        [&counter, &promise](std::string&&)
        {
            counter++;

            if (counter == 2)
            {
                promise.set_value();
            }
        },
        1,
        BULK_SIZE);
    enableAllocationCounter = true;
    while (!MESSAGES_TO_SEND_LIST.empty())
    {
        dispatcher.push(std::move(MESSAGES_TO_SEND_LIST.front()));
        MESSAGES_TO_SEND_LIST.pop();
    }
    promise.get_future().wait();
    EXPECT_EQ(2, counter);
    EXPECT_EQ(0, allocationCounter);
    enableAllocationCounter = false;
    allocationCounter = 0;
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
        1,
        QUEUE_SIZE);

    for (int i = 0; i < QUEUE_SIZE + 5; ++i)
    {
        dispatcher.push(i);
    }

    pushPromise.set_value();

    promise.get_future().wait();
    EXPECT_EQ(QUEUE_SIZE, counter);
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

    Utils::AsyncValueDispatcher<std::string, std::function<void(std::string &&)>> dispatcher(
        [&counter, &promise](std::string&&)
        {
            counter++;
            if (counter == 3)
            {
                promise.set_value();
            }
        },
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
        2,
        LARGE_COUNT);

    for (int i = 0; i < LARGE_COUNT; ++i)
    {
        dispatcher.push(i);
    }

    promise.get_future().wait();
    EXPECT_EQ(LARGE_COUNT, counter);
}
