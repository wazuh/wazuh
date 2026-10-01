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

#include "threadEventDispatcher_test.hpp"
#include "threadEventDispatcher.hpp"
#include <algorithm>
#include <filesystem>
#include <mutex>
#include <vector>

void ThreadEventDispatcherTest::SetUp() {
    // Not implemented
};

void ThreadEventDispatcherTest::TearDown() {
    // Not implemented
};

constexpr auto BULK_SIZE {50};
TEST_F(ThreadEventDispatcherTest, Ctor)
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
            "test.db",
            BULK_SIZE);

        for (int i = 0; i < MESSAGES_TO_SEND; ++i)
        {
            dispatcher.push(std::to_string(i));
        }
        promise.get_future().wait_for(std::chrono::seconds(10));
        EXPECT_EQ(MESSAGES_TO_SEND, counter);
    }
}

TEST_F(ThreadEventDispatcherTest, CtorNoWorker)
{
    static const std::vector<int> MESSAGES_TO_SEND_LIST {120, 100};

    for (auto MESSAGES_TO_SEND : MESSAGES_TO_SEND_LIST)
    {
        std::atomic<size_t> counter {0};
        std::promise<void> promise;
        auto index {0};

        ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>> dispatcher("test.db",
                                                                                                     BULK_SIZE);

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

TEST_F(ThreadEventDispatcherTest, CtorPopFeature)
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
        "test.db",
        BULK_SIZE);

    for (int i = 0; i < MESSAGES_TO_SEND; ++i)
    {
        dispatcher.push(std::to_string(i));
    }
    pushPromise.set_value();
    promise.get_future().wait_for(std::chrono::seconds(10));
    EXPECT_EQ(MESSAGES_TO_SEND, counter);
}

TEST_F(ThreadEventDispatcherTest, DiscardIsReportedOncePerOverflow)
{
    constexpr auto MAX_QUEUE_SIZE {3};
    std::filesystem::remove_all("test_discard.db");

    std::mutex logMutex;
    std::vector<std::string> logs;
    auto count = [&](const std::string& text)
    {
        std::lock_guard<std::mutex> lock(logMutex);
        return std::count_if(
            logs.begin(), logs.end(), [&](const std::string& line) { return line.find(text) != std::string::npos; });
    };
    auto waitForSize = [](auto& dispatcher, const size_t size)
    {
        for (int i = 0; i < 300 && dispatcher.size() != size; ++i)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    };

    // The worker handles one event per permit, so the queue can be filled and drained in controlled steps.
    std::atomic<int> permits {0};
    ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>> dispatcher(
        [&](std::queue<std::string>& data)
        {
            while (permits <= 0)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            --permits;
            while (!data.empty())
            {
                data.pop();
            }
        },
        "test_discard.db",
        1,
        MAX_QUEUE_SIZE,
        false,
        [&](const std::string& message)
        {
            std::lock_guard<std::mutex> lock(logMutex);
            logs.push_back(message);
        });

    // Overflow: one report for the whole burst, not one per discarded event.
    for (int i = 0; i < 20; ++i)
    {
        dispatcher.push(std::to_string(i));
    }
    EXPECT_EQ(count("Starting to discard events"), 1);

    // Room for one event, but the queue is not empty: the report is not re-armed, so no new line.
    permits = 1;
    waitForSize(dispatcher, MAX_QUEUE_SIZE - 1);
    ASSERT_EQ(dispatcher.size(), MAX_QUEUE_SIZE - 1);
    for (int i = 0; i < 20; ++i)
    {
        dispatcher.push(std::to_string(i));
    }
    EXPECT_EQ(count("Starting to discard events"), 1);

    // Once the queue is fully drained, the next overflow is reported again.
    permits = 1000;
    waitForSize(dispatcher, 0);
    ASSERT_EQ(dispatcher.size(), 0);
    permits = 0;
    for (int i = 0; i < 20; ++i)
    {
        dispatcher.push(std::to_string(i));
    }
    EXPECT_EQ(count("Starting to discard events"), 2);
    permits = 1000;
}

TEST_F(ThreadEventDispatcherTest, NoDiscardReportWhenQueueNeverOverflows)
{
    std::filesystem::remove_all("test_no_discard.db");
    std::atomic<size_t> calls {0};
    std::atomic<size_t> consumed {0};
    ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>> dispatcher(
        [&](std::queue<std::string>& data)
        {
            consumed += data.size();
            while (!data.empty())
            {
                data.pop();
            }
        },
        "test_no_discard.db",
        1,
        100,
        false,
        [&](const std::string&) { ++calls; });

    for (int i = 0; i < 50; ++i)
    {
        dispatcher.push(std::to_string(i));
    }
    for (int i = 0; i < 200 && consumed < 50; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    EXPECT_EQ(consumed, 50);
    EXPECT_EQ(calls, 0);
}
