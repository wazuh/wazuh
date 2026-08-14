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

#include <algorithm>
#include <atomic>
#include <fstream>
#include <memory>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>

#include <unistd.h>

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

    void recordTag(const std::string& tag, Record* record)
    {
        std::lock_guard<std::mutex> lock(record->mutex);
        record->order.push_back(tag);
        record->count++;
    }

    void recordStartup(bool accepted, const char*, void* userData)
    {
        recordTag(accepted ? "startup:ok" : "startup:no", static_cast<Record*>(userData));
    }

    void recordTaskFailed(const char* taskId, const char*, const char*, void* userData)
    {
        recordTag(std::string {"failed:"} + taskId, static_cast<Record*>(userData));
    }

    void recordReenroll(void* userData)
    {
        recordTag("reenroll", static_cast<Record*>(userData));
    }

    void recordSync(const char* sessionId, int, const char*, size_t, void* userData)
    {
        recordTag(std::string {"sync:"} + sessionId, static_cast<Record*>(userData));
    }

    void recordBuffer(int level, void* userData)
    {
        recordTag("buffer:" + std::to_string(level), static_cast<Record*>(userData));
    }

    hc_callbacks_t makeCallbacks(Record* record)
    {
        hc_callbacks_t callbacks {};
        callbacks.on_startup_result = recordStartup;
        callbacks.on_task = recordTask;
        callbacks.on_task_failed = recordTaskFailed;
        callbacks.on_reenroll_required = recordReenroll;
        callbacks.on_sync_response = recordSync;
        callbacks.on_state_change = recordState;
        callbacks.on_buffer_level = recordBuffer;
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
    dispatcher.onTaskFailed("x", "remote_upgrade", "reason");
    dispatcher.onStateChange(HC_STATE_STARTING);
    dispatcher.onSyncResponse("s", 0, "{}");
    dispatcher.onStartupResult(true, "{}");
    dispatcher.onBufferLevel(HC_BUFFER_NORMAL);
    dispatcher.stop(); // No crash despite null handlers.
}

TEST(CallbackDispatcherTest, EveryCallbackKindIsForwarded)
{
    Record record;
    CallbackDispatcher dispatcher {makeCallbacks(&record)};
    dispatcher.start();
    dispatcher.onStartupResult(true, R"({"limits":{}})");
    dispatcher.onTask("t1", "active_response", "{}");
    dispatcher.onTaskFailed("t2", "remote_upgrade", "wpk sha1 mismatch");
    dispatcher.onReenrollRequired();
    dispatcher.onSyncResponse("sess-1", 0, R"({"ok":true})");
    dispatcher.onStateChange(HC_STATE_REGISTERED);
    dispatcher.onBufferLevel(HC_BUFFER_WARNING);
    waitForCount(record, 7);
    dispatcher.stop();

    EXPECT_NE(record.order.end(),
              std::find(record.order.begin(), record.order.end(), "startup:ok"));
    EXPECT_NE(record.order.end(), std::find(record.order.begin(), record.order.end(), "t1"));
    EXPECT_NE(record.order.end(),
              std::find(record.order.begin(), record.order.end(), "failed:t2"));
    EXPECT_NE(record.order.end(),
              std::find(record.order.begin(), record.order.end(), "reenroll"));
    EXPECT_NE(record.order.end(),
              std::find(record.order.begin(), record.order.end(), "sync:sess-1"));
    EXPECT_NE(record.order.end(),
              std::find(record.order.begin(), record.order.end(),
                        "state:" + std::to_string(HC_STATE_REGISTERED)));
    EXPECT_NE(record.order.end(),
              std::find(record.order.begin(), record.order.end(),
                        "buffer:" + std::to_string(HC_BUFFER_WARNING)));
}

namespace
{
    struct ConfigRecord
    {
        std::atomic<int> count {0};
        std::string hash;
        std::string path;
        bool existedDuringCallback {false};
    };

    void recordConfigDownload(const char* configHash, const char* filePath, void* userData)
    {
        auto* record = static_cast<ConfigRecord*>(userData);
        record->hash = configHash;
        record->path = filePath;
        std::ifstream probe {filePath};
        record->existedDuringCallback = probe.good();
        record->count++;
    }

    std::string makeTempConfigFile(const std::string& content)
    {
        const std::string path =
            ::testing::TempDir() + "hc_dispatcher_config_" + std::to_string(::getpid()) + ".tmp";
        std::ofstream file {path, std::ios::binary};
        file << content;
        return path;
    }
} // namespace

TEST(CallbackDispatcherTest, ConfigFileLivesForTheCallbackAndDiesAfterStop)
{
    ConfigRecord record;
    hc_callbacks_t callbacks {};
    callbacks.on_config_downloaded = recordConfigDownload;
    callbacks.user_data = &record;

    const std::string path = makeTempConfigFile("merged-bytes");
    CallbackDispatcher dispatcher {callbacks};
    dispatcher.start();
    dispatcher.onConfigDownloaded("hash-1", std::make_shared<SpoolFile>(path));

    while (record.count.load() < 1)
    {
        std::this_thread::yield();
    }

    dispatcher.stop(); // Drains: the task (and its file reference) is gone.

    EXPECT_EQ("hash-1", record.hash);
    EXPECT_EQ(path, record.path);
    EXPECT_TRUE(record.existedDuringCallback);
    std::ifstream after {path};
    EXPECT_FALSE(after.good()); // Deleted right after the callback returned.
}

TEST(CallbackDispatcherTest, NullConfigCallbackDeletesTheFileImmediately)
{
    hc_callbacks_t callbacks {}; // No on_config_downloaded.
    const std::string path = makeTempConfigFile("merged-bytes");
    CallbackDispatcher dispatcher {callbacks};
    dispatcher.start();
    dispatcher.onConfigDownloaded("hash-1", std::make_shared<SpoolFile>(path));

    // The early return dropped the last reference synchronously.
    std::ifstream probe {path};
    EXPECT_FALSE(probe.good());
    dispatcher.stop();
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

TEST(CallbackDispatcherBinaryTest, ASyncResponseBodyKeepsItsNulBytes)
{
    // A session is answered with an EndAck FlatBuffer, which is binary. The
    // callback used to hand the body over as a bare const char*, so anything
    // past the first NUL was lost - which for a FlatBuffer is most of it.
    struct Captured
    {
        std::mutex mutex;
        std::condition_variable cv;
        std::string body;
        bool got {false};
    } captured;

    hc_callbacks_t callbacks {};
    callbacks.on_sync_response = [](const char*, int, const char* body, size_t bodyLen,
                                    void* userData)
    {
        auto* sink = static_cast<Captured*>(userData);
        std::lock_guard<std::mutex> lock(sink->mutex);
        sink->body.assign(body, bodyLen);
        sink->got = true;
        sink->cv.notify_all();
    };
    callbacks.user_data = &captured;

    // A body with an embedded NUL partway through, to prove c_str()-style truncation
    // never happens on the way through.
    const std::string binaryBody {"\x0c\x00\x00\x00WZ\x00\x01\x00\x00\x00\x00", 12};

    CallbackDispatcher dispatcher {callbacks};
    dispatcher.start();
    dispatcher.onSyncResponse("fim-42", 200, binaryBody);

    {
        std::unique_lock<std::mutex> lock(captured.mutex);
        ASSERT_TRUE(captured.cv.wait_for(lock, std::chrono::seconds {5}, [&] { return captured.got; }));
    }

    dispatcher.stop();
    EXPECT_EQ(binaryBody, captured.body);
    EXPECT_EQ(12u, captured.body.size()); // Not 4, which is where the first NUL sits.
}
