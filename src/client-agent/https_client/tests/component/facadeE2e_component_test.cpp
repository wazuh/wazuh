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
 * Facade end to end over the C ABI against a TLS fake manager. This is what
 * exercises the composition root's registered path: the control loop reaching
 * REGISTERED, the gate releasing the data streams, the stateless/stateful
 * sender loops flushing, and the drain-on-stop. The client speaks real HTTPS
 * (HC_VERIFY_NONE against the fake manager's self-signed cert).
 */

#include "fakeManager.hpp"
#include "https_client.h"
#include "syncIntake.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

namespace
{
    constexpr uint16_t TLS_PORT = 44861;
    const std::string KEY_HEX = "000102030405060708090a0b0c0d0e0f";

    struct Recorder
    {
        std::mutex mutex;
        std::atomic<int> startupCount {0};
        std::atomic<int> syncCount {0};
        std::atomic<int> configCount {0};
        std::vector<int> states;
    };

    void onStartup(bool accepted, const char*, void* userData)
    {
        if (accepted)
        {
            static_cast<Recorder*>(userData)->startupCount++;
        }
    }

    void onSync(const char*, int, const char*, void* userData)
    {
        static_cast<Recorder*>(userData)->syncCount++;
    }

    void onConfig(const char*, const char*, void* userData)
    {
        static_cast<Recorder*>(userData)->configCount++;
    }

    void onState(int state, void* userData)
    {
        auto* recorder = static_cast<Recorder*>(userData);
        std::lock_guard<std::mutex> lock(recorder->mutex);
        recorder->states.push_back(state);
    }

    hc_config_t tlsConfig()
    {
        hc_config_t config {};
        std::strncpy(config.server_host, "127.0.0.1", sizeof(config.server_host) - 1);
        config.server_port = TLS_PORT;
        std::strncpy(config.agent_id, "001", sizeof(config.agent_id) - 1);
        std::strncpy(config.agent_key, KEY_HEX.c_str(), sizeof(config.agent_key) - 1);
        config.verify_mode = HC_VERIFY_NONE; // Self-signed fake manager.
        config.request_timeout_ms = 3000;
        config.backoff_base_ms = 10;
        config.backoff_cap_ms = 50;
        config.notify_interval_s = 1;
        config.batch_interval_ms = 200;
        config.drain_timeout_ms = 1000;
        std::strncpy(config.version, "5.1.0", sizeof(config.version) - 1);
        return config;
    }

    bool waitFor(const std::atomic<int>& counter, int target, int timeoutMs)
    {
        for (int elapsed = 0; elapsed < timeoutMs; elapsed += 10)
        {
            if (counter.load() >= target)
            {
                return true;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds {10});
        }

        return false;
    }

    class FacadeE2eTest : public ::testing::Test
    {
        protected:
            static void SetUpTestSuite()
            {
                s_manager = new FakeManager(TLS_PORT, KEY_HEX, /*tls=*/true);
            }
            static void TearDownTestSuite()
            {
                delete s_manager;
                s_manager = nullptr;
            }
            static FakeManager* s_manager;
    };

    FakeManager* FacadeE2eTest::s_manager = nullptr;
} // namespace

TEST_F(FacadeE2eTest, LargeSyncSessionFromTheIntakeSocketReachesTheManager)
{
    // The full chain: a producer streams a multi-MB session over the local
    // STREAM intake socket -> the module spools it -> the stateful sender
    // streams it to the manager over HTTPS. Nothing hits the 64 KB cap.
    Recorder recorder;
    const std::string sockPath = "/tmp/hc_facade_si_" + std::to_string(getpid()) + ".sock";

    hc_config_t config = tlsConfig();
    std::strncpy(config.sync_socket_path, sockPath.c_str(), sizeof(config.sync_socket_path) - 1);
    hc_callbacks_t callbacks {};
    callbacks.on_startup_result = onStartup;
    callbacks.on_sync_response = onSync;
    callbacks.on_state_change = onState;
    callbacks.user_data = &recorder;

    hc_handle* handle = hc_create(&config, &callbacks);
    ASSERT_NE(nullptr, handle);
    ASSERT_TRUE(hc_start(handle));
    ASSERT_TRUE(waitFor(recorder.startupCount, 1, 3000)); // Registered.

    std::string body(2u * 1024 * 1024, 'S'); // 2 MB, far past the 64 KB DGRAM cap.
    ASSERT_TRUE(sendSyncSession(sockPath, "intake-session-1",
                                reinterpret_cast<const uint8_t*>(body.data()), body.size()));

    // The session crossed the socket, was spooled, and was POSTed to the mock.
    EXPECT_TRUE(waitFor(recorder.syncCount, 1, 5000));
    hc_destroy(handle);
}

TEST_F(FacadeE2eTest, RegistersAndRunsTheDataStreams)
{
    Recorder recorder;
    hc_config_t config = tlsConfig();
    hc_callbacks_t callbacks {};
    callbacks.log = nullptr;
    callbacks.on_startup_result = onStartup;
    callbacks.on_sync_response = onSync;
    callbacks.on_config_update = onConfig;
    callbacks.on_state_change = onState;
    callbacks.user_data = &recorder;

    hc_handle* handle = hc_create(&config, &callbacks);
    ASSERT_NE(nullptr, handle);
    ASSERT_TRUE(hc_start(handle));

    // The control loop reaches REGISTERED (Startup accepted over real TLS).
    ASSERT_TRUE(waitFor(recorder.startupCount, 1, 3000));
    EXPECT_EQ(HC_STATE_REGISTERED, hc_get_state(handle));

    // The gate is open: the stateless sender flushes submitted events, and the
    // stateful sender ships a submitted session (answered via on_sync_response).
    const uint8_t frame[] = "1:/var/log/syslog:e2e";
    EXPECT_TRUE(hc_submit_event(handle, frame, sizeof(frame) - 1));
    const uint8_t session[] = "FULLSESSION:syscollector:body";
    EXPECT_TRUE(hc_submit_sync_session(handle, "sess-e2e", session, sizeof(session) - 1));
    EXPECT_TRUE(waitFor(recorder.syncCount, 1, 3000));

    // Every notify answers with a config push (C.2): it reaches the callback.
    EXPECT_TRUE(waitFor(recorder.configCount, 1, 3000));

    hc_destroy(handle); // Drains (final flush + Notify) and joins.
    EXPECT_EQ(HC_STATE_STOPPED, recorder.states.back());
    EXPECT_NE(recorder.states.end(),
              std::find(recorder.states.begin(), recorder.states.end(), HC_STATE_REGISTERED));
}
