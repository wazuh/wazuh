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

