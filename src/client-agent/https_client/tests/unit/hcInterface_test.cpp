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

/*
 * Black-box tests over the C ABI (include/https_client.h), the
 * remoted_module_test style: only the public header is included. The client
 * points at a closed local port with tiny timeouts, so Startup never
 * succeeds and every test stops quickly. State-change callbacks are
 * asynchronous (serialized on the dispatcher and fully drained by hc_stop),
 * so the lifecycle is asserted on the drained record after destroy.
 */

#include "https_client.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

namespace
{
    std::atomic<int> g_logCalls {0};

    void testLogCallback(const int, const char*, const char*, const int, const char*, const char*,
                         va_list)
    {
        g_logCalls++;
    }

    struct Recorder
    {
        std::mutex mutex;
        std::vector<int> states;
    };

    void onStateChange(int state, void* userData)
    {
        auto* recorder = static_cast<Recorder*>(userData);
        std::lock_guard<std::mutex> lock(recorder->mutex);
        recorder->states.push_back(state);
    }

    // Points at a closed localhost port with tiny timeouts and backoff so the
    // control loop churns quickly and stop is near-instant.
    hc_config_t makeConfig()
    {
        hc_config_t config {};
        std::strncpy(config.server_host, "127.0.0.1", sizeof(config.server_host) - 1);
        config.server_port = 9; // discard; nothing listens for HTTPS.
        std::strncpy(config.agent_id, "001", sizeof(config.agent_id) - 1);
        std::strncpy(config.agent_key, "000102030405060708090a0b0c0d0e0f", sizeof(config.agent_key) - 1);
        config.verify_mode = HC_VERIFY_NONE;
        config.request_timeout_ms = 200;
        config.backoff_base_ms = 1;
        config.backoff_cap_ms = 5;
        config.notify_interval_s = 1;
        config.rejected_retry_interval_s = 1;
        config.drain_timeout_ms = 100;
        std::strncpy(config.version, "5.1.0", sizeof(config.version) - 1);
        return config;
    }

    hc_callbacks_t makeCallbacks(Recorder* recorder)
    {
        hc_callbacks_t callbacks {};
        callbacks.log = testLogCallback;
        callbacks.on_state_change = onStateChange;
        callbacks.user_data = recorder;
        return callbacks;
    }

    bool contains(const std::vector<int>& values, int value)
    {
        return std::find(values.begin(), values.end(), value) != values.end();
    }
} // namespace

class HcInterfaceTest : public ::testing::Test
{
    protected:
        Recorder m_recorder;
        hc_config_t m_config {makeConfig()};
        hc_callbacks_t m_callbacks {makeCallbacks(&m_recorder)};
};

TEST_F(HcInterfaceTest, CreateWithNullArgsReturnsNull)
{
    EXPECT_EQ(nullptr, hc_create(nullptr, &m_callbacks));
    EXPECT_EQ(nullptr, hc_create(&m_config, nullptr));
    EXPECT_EQ(nullptr, hc_create(nullptr, nullptr));
}

TEST_F(HcInterfaceTest, StartAndStopRecordsStartingThenStopped)
{
    hc_handle* handle = hc_create(&m_config, &m_callbacks);
    ASSERT_NE(nullptr, handle);
    EXPECT_EQ(HC_STATE_STOPPED, hc_get_state(handle));

    EXPECT_TRUE(hc_start(handle));
    hc_stop(handle);
    EXPECT_EQ(HC_STATE_STOPPED, hc_get_state(handle));
    hc_destroy(handle); // Drains the dispatcher.

    ASSERT_FALSE(m_recorder.states.empty());
    EXPECT_EQ(HC_STATE_STARTING, m_recorder.states.front());
    EXPECT_EQ(HC_STATE_STOPPED, m_recorder.states.back());
    EXPECT_GT(g_logCalls.load(), 0);
}

TEST_F(HcInterfaceTest, StopWithoutStartIsSafe)
{
    hc_handle* handle = hc_create(&m_config, &m_callbacks);
    ASSERT_NE(nullptr, handle);
    hc_stop(handle);
    EXPECT_EQ(HC_STATE_STOPPED, hc_get_state(handle));
    EXPECT_TRUE(m_recorder.states.empty());
    hc_destroy(handle);
}

TEST_F(HcInterfaceTest, DoubleStartIsIgnored)
{
    hc_handle* handle = hc_create(&m_config, &m_callbacks);
    ASSERT_NE(nullptr, handle);
    EXPECT_TRUE(hc_start(handle));
    EXPECT_TRUE(hc_start(handle)); // Ignored.
    hc_destroy(handle);
    // STARTING recorded exactly once despite two start calls.
    EXPECT_EQ(1, std::count(m_recorder.states.begin(), m_recorder.states.end(), HC_STATE_STARTING));
}

TEST_F(HcInterfaceTest, DestroyImpliesStop)
{
    hc_handle* handle = hc_create(&m_config, &m_callbacks);
    ASSERT_NE(nullptr, handle);
    EXPECT_TRUE(hc_start(handle));
    hc_destroy(handle); // No explicit stop; destroy must stop and drain.
    EXPECT_TRUE(contains(m_recorder.states, HC_STATE_STARTING));
    EXPECT_EQ(HC_STATE_STOPPED, m_recorder.states.back());
}

TEST_F(HcInterfaceTest, DrainReturnsWithinDeadlineAgainstADeadServer)
{
    hc_handle* handle = hc_create(&m_config, &m_callbacks);
    ASSERT_NE(nullptr, handle);
    ASSERT_TRUE(hc_start(handle));

    const auto begin = std::chrono::steady_clock::now();
    hc_stop(handle); // Must not hang despite the unreachable server.
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::steady_clock::now() - begin)
                         .count();
    EXPECT_LT(elapsed, 5);
    hc_destroy(handle);
}

TEST_F(HcInterfaceTest, SubmitBeforeStartIsRejected)
{
    hc_handle* handle = hc_create(&m_config, &m_callbacks);
    ASSERT_NE(nullptr, handle);
    const uint8_t frame[] = "1:/var/log/syslog:hello";
    EXPECT_FALSE(hc_submit_event(handle, frame, sizeof(frame) - 1));
    EXPECT_FALSE(hc_submit_sync_session(handle, "sess-0001", frame, sizeof(frame) - 1));
    hc_notify_now(handle);
    EXPECT_EQ(HC_STATE_STOPPED, hc_get_state(handle));
    hc_destroy(handle);
}

TEST_F(HcInterfaceTest, SubmitAfterStartAcceptsIntoQueues)
{
    hc_handle* handle = hc_create(&m_config, &m_callbacks);
    ASSERT_NE(nullptr, handle);
    ASSERT_TRUE(hc_start(handle));
    const uint8_t frame[] = "1:/var/log/syslog:hello";
    EXPECT_TRUE(hc_submit_event(handle, frame, sizeof(frame) - 1));
    EXPECT_TRUE(hc_submit_sync_session(handle, "sess-0001", frame, sizeof(frame) - 1));
    hc_notify_now(handle);
    hc_destroy(handle);
}

TEST_F(HcInterfaceTest, SyncSubmitAfterStopIsRejected)
{
    // Both sync entry points read the lifecycle flag under the same lock stop()
    // writes it with, so a session can never be queued behind the sender's exit.
    hc_handle* handle = hc_create(&m_config, &m_callbacks);
    ASSERT_NE(nullptr, handle);
    ASSERT_TRUE(hc_start(handle));
    hc_stop(handle);

    const uint8_t frame[] = "1:/var/log/syslog:hello";
    EXPECT_FALSE(hc_submit_sync_session(handle, "sess-0001", frame, sizeof(frame) - 1));
    EXPECT_FALSE(hc_submit_sync_session_file(handle, "sess-0002", "/tmp/hc_never_read", 1));
    EXPECT_FALSE(hc_submit_event(handle, frame, sizeof(frame) - 1));
    hc_destroy(handle);
}

TEST_F(HcInterfaceTest, SubmitNullArgumentsAreRejected)
{
    hc_handle* handle = hc_create(&m_config, &m_callbacks);
    ASSERT_NE(nullptr, handle);
    ASSERT_TRUE(hc_start(handle));
    const uint8_t frame[] = "x";
    EXPECT_FALSE(hc_submit_event(handle, nullptr, 1));
    EXPECT_FALSE(hc_submit_event(handle, frame, 0));
    EXPECT_FALSE(hc_submit_sync_session(handle, nullptr, frame, 1));
    EXPECT_FALSE(hc_submit_sync_session(handle, "sess", nullptr, 1));
    hc_destroy(handle);
}

TEST_F(HcInterfaceTest, StartRejectsMissingMandatoryFields)
{
    hc_config_t badConfig = m_config;
    badConfig.server_host[0] = '\0';
    hc_handle* handle = hc_create(&badConfig, &m_callbacks);
    ASSERT_NE(nullptr, handle);
    EXPECT_FALSE(hc_start(handle));
    EXPECT_EQ(HC_STATE_STOPPED, hc_get_state(handle));
    EXPECT_TRUE(m_recorder.states.empty());
    hc_destroy(handle);
}

TEST_F(HcInterfaceTest, StartFailsClosedWithoutCaInFullMode)
{
    hc_config_t failClosed = m_config;
    failClosed.verify_mode = HC_VERIFY_FULL; // No CA -> must refuse to start.
    hc_handle* handle = hc_create(&failClosed, &m_callbacks);
    ASSERT_NE(nullptr, handle);
    EXPECT_FALSE(hc_start(handle));
    EXPECT_EQ(HC_STATE_STOPPED, hc_get_state(handle));
    EXPECT_TRUE(m_recorder.states.empty());
    hc_destroy(handle);
}

TEST_F(HcInterfaceTest, SyncIntakeBindFailureIsNonFatal)
{
    // A sync socket in a nonexistent directory cannot bind; the client must
    // still start (the intake is best-effort) and stop cleanly.
    hc_config_t config = m_config;
    std::strncpy(config.sync_socket_path, "/nonexistent_dir_xyz/hc_sync.sock",
                 sizeof(config.sync_socket_path) - 1);
    hc_handle* handle = hc_create(&config, &m_callbacks);
    ASSERT_NE(nullptr, handle);
    EXPECT_TRUE(hc_start(handle)); // Bind fails, but start succeeds.
    hc_destroy(handle);
}

TEST_F(HcInterfaceTest, LifecycleChurn)
{
    // The designated ThreadSanitizer workload: a fresh handle each cycle (the
    // client is single-shot) with concurrent submits from another thread,
    // exercising the full create/start/stop/destroy race surface.
    //
    constexpr int CYCLES = 20;
    constexpr int MAX_SUBMITS = 500;
    constexpr int SUBMITS_BEFORE_STOP = 50;

    for (int cycle = 0; cycle < CYCLES; cycle++)
    {
        hc_handle* handle = hc_create(&m_config, &m_callbacks);
        ASSERT_NE(nullptr, handle);
        ASSERT_TRUE(hc_start(handle));
        std::atomic<bool> submitting {true};
        std::atomic<int> submitted {0};
        std::thread producer(
            [&]
        {
            const uint8_t frame[] = "1:/var/log/syslog:churn";

            for (int n = 0; n < MAX_SUBMITS && submitting.load(); n++)
            {
                hc_submit_event(handle, frame, sizeof(frame) - 1);
                submitted.fetch_add(1, std::memory_order_relaxed);
            }
        });

        // Stop only once submits are demonstrably in flight, so the race the
        // test exists for still happens without depending on the wall clock.
        while (submitted.load(std::memory_order_relaxed) < SUBMITS_BEFORE_STOP)
        {
            std::this_thread::yield();
        }

        hc_stop(handle);
        submitting = false;
        producer.join();
        hc_destroy(handle);
    }
}

TEST_F(HcInterfaceTest, StartAfterStopIsRejected)
{
    // Single-shot: once stopped, start() fails closed rather than returning a
    // misleading success on a client that would sit dead.
    hc_handle* handle = hc_create(&m_config, &m_callbacks);
    ASSERT_NE(nullptr, handle);
    ASSERT_TRUE(hc_start(handle));
    hc_stop(handle);
    EXPECT_FALSE(hc_start(handle));
    hc_destroy(handle);
}

TEST_F(HcInterfaceTest, NullHandleIsSafeEverywhere)
{
    EXPECT_FALSE(hc_start(nullptr));
    hc_stop(nullptr);
    hc_destroy(nullptr);
    const uint8_t frame[] = "x";
    EXPECT_FALSE(hc_submit_event(nullptr, frame, 1));
    EXPECT_FALSE(hc_submit_sync_session(nullptr, "s", frame, 1));
    hc_notify_now(nullptr);
    EXPECT_FALSE(hc_set_config_hash(nullptr, "abc"));
    EXPECT_EQ(HC_STATE_STOPPED, hc_get_state(nullptr));
}

TEST_F(HcInterfaceTest, SetConfigHashAcceptsAValidHashAndRejectsNull)
{
    hc_handle* handle = hc_create(&m_config, &m_callbacks);
    ASSERT_NE(nullptr, handle);
    EXPECT_TRUE(hc_set_config_hash(handle, "d41d8cd98f00b204e9800998ecf8427e"));
    EXPECT_FALSE(hc_set_config_hash(handle, nullptr));
    hc_destroy(handle);
}

TEST_F(HcInterfaceTest, SetAgentKeyValidatesTheMaterial)
{
    hc_handle* handle = hc_create(&m_config, &m_callbacks);
    ASSERT_NE(nullptr, handle);
    EXPECT_TRUE(hc_set_agent_key(handle, "000102030405060708090a0b0c0d0e0f")); // 16 bytes.
    EXPECT_FALSE(hc_set_agent_key(handle, "abcd")); // 2 bytes: not an AES length.
    EXPECT_FALSE(hc_set_agent_key(handle, nullptr));
    EXPECT_FALSE(hc_set_agent_key(nullptr, "000102030405060708090a0b0c0d0e0f"));
    hc_destroy(handle);
}
