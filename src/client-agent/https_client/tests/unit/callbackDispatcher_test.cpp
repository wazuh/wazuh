/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "callbackDispatcher.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <mutex>
#include <thread>
#include <vector>

namespace
{
    // Shared recording state reached through the C callbacks' user_data.
    struct Record
    {
        std::mutex mutex;
        std::vector<std::string> order;
        std::vector<std::thread::id> threads;
        std::atomic<int> count {0};
    };

    void recordTask(const char* taskId, const char*, const char*, void* userData)
    {
        auto* record = static_cast<Record*>(userData);
        std::lock_guard<std::mutex> lock(record->mutex);
        record->order.emplace_back(taskId);
        record->threads.push_back(std::this_thread::get_id());
        record->count++;
    }

    void recordState(int state, void* userData)
    {
        auto* record = static_cast<Record*>(userData);
        std::lock_guard<std::mutex> lock(record->mutex);
        record->order.push_back("state:" + std::to_string(state));
        record->threads.push_back(std::this_thread::get_id());
        record->count++;
    }

    hc_callbacks_t makeCallbacks(Record* record)
    {
        hc_callbacks_t callbacks {};
        callbacks.on_task = recordTask;
        callbacks.on_state_change = recordState;
        callbacks.user_data = record;
        return callbacks;
    }

    void waitForCount(const Record& record, int expected)
    {
        while (record.count.load() < expected)
        {
            std::this_thread::yield();
        }
    }
} // namespace

TEST(CallbackDispatcherTest, DeliversInSubmissionOrderOnOneThread)
{
    Record record;
    CallbackDispatcher dispatcher {makeCallbacks(&record)};
    dispatcher.start();

    for (int index = 0; index < 20; index++)
    {
        dispatcher.onTask("task-" + std::to_string(index), "ar", "{}");
    }
    waitForCount(record, 20);
    dispatcher.stop();

    ASSERT_EQ(20u, record.order.size());
    for (int index = 0; index < 20; index++)
    {
        EXPECT_EQ("task-" + std::to_string(index), record.order[index]); // FIFO.
    }
    // Every callback ran on the same (single) dispatcher thread.
    for (const auto& id : record.threads)
    {
        EXPECT_EQ(record.threads.front(), id);
    }
    EXPECT_NE(std::this_thread::get_id(), record.threads.front());
}

TEST(CallbackDispatcherTest, StopDrainsQueuedCallbacks)
{
    Record record;
    CallbackDispatcher dispatcher {makeCallbacks(&record)};
    dispatcher.start();
    for (int index = 0; index < 50; index++)
    {
        dispatcher.onStateChange(HC_STATE_REGISTERED);
        dispatcher.onTask("t" + std::to_string(index), "ar", "{}");
    }
    dispatcher.stop(); // Must run everything already queued before joining.
    EXPECT_EQ(100, record.count.load());
}

TEST(CallbackDispatcherTest, PostAfterStopIsRejected)
{
    Record record;
    CallbackDispatcher dispatcher {makeCallbacks(&record)};
    dispatcher.start();
    dispatcher.stop();
    dispatcher.onTask("late", "ar", "{}");
    EXPECT_EQ(0, record.count.load());
}

TEST(CallbackDispatcherTest, NullCallbacksAreSafe)
{
    hc_callbacks_t callbacks {}; // All function pointers null.
    CallbackDispatcher dispatcher {callbacks};
    dispatcher.start();
    dispatcher.onTask("x", "ar", "{}");
    dispatcher.onStateChange(HC_STATE_STARTING);
    dispatcher.onSyncResponse("s", 0, "{}");
    dispatcher.onStartupResult(true, "{}");
    dispatcher.onBufferLevel(HC_BUFFER_NORMAL);
    dispatcher.stop(); // No crash despite null handlers.
}

TEST(CallbackDispatcherTest, DoubleStartAndDoubleStopAreSafe)
{
    Record record;
    CallbackDispatcher dispatcher {makeCallbacks(&record)};
    dispatcher.start();
    dispatcher.start(); // Ignored.
    dispatcher.onTask("one", "ar", "{}");
    waitForCount(record, 1);
    dispatcher.stop();
    dispatcher.stop(); // Ignored.
    EXPECT_EQ(1, record.count.load());
}
