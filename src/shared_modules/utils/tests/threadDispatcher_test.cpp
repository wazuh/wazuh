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

#include "threadDispatcher_test.h"
#include "threadDispatcher.h"
#include <chrono>
#include <thread>

void ThreadDispatcherTest::SetUp() {};

void ThreadDispatcherTest::TearDown() {};

using ::testing::_;
using namespace Utils;

// LCOV_EXCL_START
class FunctorWrapper
{
public:
    FunctorWrapper() {}
    ~FunctorWrapper() {}
    MOCK_METHOD(void, Operator, (const int), ());
    void operator()(const int value)
    {
        Operator(value);
    }
};
// LCOV_EXCL_STOP

TEST_F(ThreadDispatcherTest, AsyncDispatcherPushAndRundown)
{
    FunctorWrapper functor;
    AsyncDispatcher<int, std::reference_wrapper<FunctorWrapper>> dispatcher {std::ref(functor)};
    EXPECT_EQ(std::thread::hardware_concurrency(), dispatcher.numberOfThreads());

    for (int i = 0; i < 10; ++i)
    {
        EXPECT_CALL(functor, Operator(i));
    }

    for (int i = 0; i < 10; ++i)
    {
        dispatcher.push(i);
    }

    dispatcher.rundown();
    EXPECT_TRUE(dispatcher.cancelled());
    EXPECT_EQ(0ul, dispatcher.size());
}

TEST_F(ThreadDispatcherTest, AsyncDispatcherCancel)
{
    FunctorWrapper functor;
    AsyncDispatcher<int, std::reference_wrapper<FunctorWrapper>> dispatcher {std::ref(functor)};
    EXPECT_EQ(std::thread::hardware_concurrency(), dispatcher.numberOfThreads());
    dispatcher.cancel();

    for (int i = 0; i < 10; ++i)
    {
        EXPECT_CALL(functor, Operator(i)).Times(0);
        dispatcher.push(i);
    }

    EXPECT_TRUE(dispatcher.cancelled());
    dispatcher.rundown();
    EXPECT_EQ(0ul, dispatcher.size());
}

TEST_F(ThreadDispatcherTest, AsyncDispatcherQueue)
{
    constexpr auto NUMBER_OF_THREADS {1ul};
    constexpr auto MAX_QUEUE_SIZE {5ull};
    constexpr auto NUMBER_OF_ITEMS {1000};
    std::mutex mutex;
    std::unique_lock<std::mutex> lock(mutex);
    std::condition_variable condition;
    std::atomic<bool> firstCall {true};

    AsyncDispatcher<int, std::function<void(int)>> dispatcher {[&mutex, &condition, &firstCall](int)
                                                               {
                                                                   std::unique_lock<std::mutex> lock(mutex);
                                                                   condition.notify_one();

                                                                   if (firstCall)
                                                                   {
                                                                       firstCall = false;
                                                                       condition.wait(lock);
                                                                   }
                                                               },
                                                               NUMBER_OF_THREADS,
                                                               MAX_QUEUE_SIZE};

    dispatcher.push(0);
    condition.wait(lock);

    for (int i = 0; i < NUMBER_OF_ITEMS - 1; ++i)
    {
        dispatcher.push(0);
    }

    EXPECT_EQ(MAX_QUEUE_SIZE, dispatcher.size());
    condition.notify_one();
    lock.unlock();
    dispatcher.rundown();
}
