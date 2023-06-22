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

void ThreadEventDispatcherTest::SetUp() {};

void ThreadEventDispatcherTest::TearDown() {};

constexpr auto BULK_SIZE {50};
TEST_F(ThreadEventDispatcherTest, Ctor)
{
    constexpr auto MESSAGES_TO_SEND {100000};

    std::atomic<uint32_t> counter {0};
    std::promise<void> promise;
    ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>> dispatcher(
        [&counter, &promise](std::queue<std::string>& data)
        {
            counter += data.size();
            if (counter == MESSAGES_TO_SEND)
            {
                promise.set_value();
            }
        },
        "test.db",
        BULK_SIZE);

    for (int i = 0; i < MESSAGES_TO_SEND; ++i)
    {
        dispatcher.push("test");
    }
    promise.get_future().wait_for(std::chrono::seconds(10));
    EXPECT_EQ(MESSAGES_TO_SEND, counter);
}

