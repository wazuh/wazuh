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

#include <cstdio>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
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

    /// Valgrind runs this binary about six times slower (the RTR stage reports
    /// ~86 s for what takes ~14 s natively), which is enough to miss the
    /// deadlines below. A missed deadline costs more than one failed
    /// assertion: ASSERT_TRUE returns from the test body before its
    /// hc_destroy(), so the handle's threads, curl handles and OpenSSL state
    /// are never released and valgrind reports them as definitely lost. Stretch
    /// the bound when running under valgrind rather than loosening it for
    /// everyone, so a genuine hang still fails fast in a normal run.
    int scaledTimeout(int timeoutMs)
    {
        static const int factor = []
        {
            const char* preload = std::getenv("LD_PRELOAD");
            return preload != nullptr && std::strstr(preload, "valgrind") != nullptr ? 10 : 1;
        }();
        return timeoutMs * factor;
    }

    bool waitFor(const std::atomic<int>& counter, int target, int timeoutMs)
    {
        const int deadline = scaledTimeout(timeoutMs);

        for (int elapsed = 0; elapsed < deadline; elapsed += 10)
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

TEST_F(FacadeE2eTest, GracefulStopSendsControlShutdown)
{
    // Finding 3 (#37831 QA round): the manager was observed never receiving
    // {"type":"shutdown"} on a graceful stop, with HttpsClientFacade::drain()'s
    // guard (paused-or-not-registered) suspected as the likely (but, per that
    // round's own report, unconfirmed) cause. This is the direct, live
    // repro the report asked for: register for real over TLS, destroy the
    // client the same way the real agent's atexit(w_https_client_stop) does,
    // and check the manager's own record of what it received.
    const uint16_t port = TLS_PORT + 6;
    FakeManager manager {port, KEY_HEX, /*tls=*/true};

    Recorder recorder;
    hc_config_t config = tlsConfig();
    config.server_port = port;
    hc_callbacks_t callbacks {};
    callbacks.on_startup_result = onStartup;
    callbacks.user_data = &recorder;

    hc_handle* handle = hc_create(&config, &callbacks);
    ASSERT_NE(nullptr, handle);
    ASSERT_TRUE(hc_start(handle));
    ASSERT_TRUE(waitFor(recorder.startupCount, 1, 3000)); // Registered.

    hc_destroy(handle); // The same call the real agent's atexit hook makes.

    httplib::Client peek {std::string {"https://127.0.0.1:"} + std::to_string(port)};
    peek.enable_server_certificate_verification(false);
    std::string seenTypes;

    if (auto result = peek.Get("/peek/control"))
    {
        seenTypes = result->body;
    }

    // If this fails, finding 3 is confirmed live (not just suspected from
    // reading the source) and HttpsClientFacade::drain()'s guard (or
    // something upstream of it) needs an actual behavior fix, not just the
    // logging this same change adds. If it passes, the guard is NOT the
    // problem in this exact lifecycle (start -> register -> destroy), and
    // whatever the QA round observed must come from a path this test does
    // not cover (e.g. the real daemon's signal-handler-driven shutdown).
    EXPECT_NE(std::string::npos, seenTypes.find("shutdown"))
            << "manager's /control record was: " << seenTypes;
}

TEST_F(FacadeE2eTest, RegistersOverTlsAndStopsCleanly)
{
    // The full lifecycle against a real TLS listener: STARTING -> REGISTERED
    // (accepted startup, CMAC verified server-side) -> STOPPED on destroy.
    Recorder recorder;
    hc_config_t config = tlsConfig();
    hc_callbacks_t callbacks {};
    callbacks.on_startup_result = onStartup;
    callbacks.on_state_change = onState;
    callbacks.user_data = &recorder;

    hc_handle* handle = hc_create(&config, &callbacks);
    ASSERT_NE(nullptr, handle);
    ASSERT_TRUE(hc_start(handle));
    ASSERT_TRUE(waitFor(recorder.startupCount, 1, 3000)); // Registered.
    hc_destroy(handle);

    std::lock_guard<std::mutex> lock(recorder.mutex);
    EXPECT_NE(recorder.states.end(),
              std::find(recorder.states.begin(), recorder.states.end(), HC_STATE_REGISTERED));
    EXPECT_EQ(HC_STATE_STOPPED, recorder.states.back());
}

TEST_F(FacadeE2eTest, SizeThresholdFlushesBeforeTheBatchInterval)
{
    // A long interval makes the size-threshold wake observable. The 80-byte
    // request budget leaves 45 bytes after the H line, so two events cross it.
    const uint16_t port = TLS_PORT + 5;
    FakeManager manager {port, KEY_HEX, /*tls=*/true};

    Recorder recorder;
    hc_config_t config = tlsConfig();
    config.server_port = port;
    config.batch_size_bytes = 80;
    config.batch_interval_ms = 5000;
    hc_callbacks_t callbacks {};
    callbacks.on_startup_result = onStartup;
    callbacks.user_data = &recorder;

    hc_handle* handle = hc_create(&config, &callbacks);
    ASSERT_NE(nullptr, handle);
    ASSERT_TRUE(hc_start(handle));
    ASSERT_TRUE(waitFor(recorder.startupCount, 1, 3000));

    const std::string first = "1:/loc:size-wakeup-first";
    const std::string second = "1:/loc:size-wakeup-second";
    ASSERT_TRUE(hc_submit_event(handle, reinterpret_cast<const uint8_t*>(first.data()),
                                first.size()));
    ASSERT_TRUE(hc_submit_event(handle, reinterpret_cast<const uint8_t*>(second.data()),
                                second.size()));

    httplib::Client peek {std::string {"https://127.0.0.1:"} + std::to_string(port)};
    peek.enable_server_certificate_verification(false);
    std::string received;

    for (int attempt = 0; attempt < 150; attempt++)
    {
        if (auto result = peek.Get("/peek/stateless"))
        {
            received = result->body;

            if (received.find("size-wakeup-first") != std::string::npos)
            {
                break;
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds {10});
    }

    hc_destroy(handle);
    EXPECT_NE(std::string::npos, received.find("size-wakeup-first"));
}

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

namespace
{
    struct ConfigRecorder
    {
        std::atomic<int> count {0};
        std::mutex mutex;
        std::string hash;
        std::string content;
    };

    void onConfigDownloaded(const char* configHash, const char* filePath, void* userData)
    {
        auto* recorder = static_cast<ConfigRecorder*>(userData);
        std::lock_guard<std::mutex> lock(recorder->mutex);
        recorder->hash = configHash;
        std::ifstream file {filePath, std::ios::binary};
        recorder->content.assign(std::istreambuf_iterator<char>(file),
                                 std::istreambuf_iterator<char>());
        recorder->count++;
    }
} // namespace

TEST_F(FacadeE2eTest, ConfigMismatchDownloadsOverTlsAndDeliversOnce)
{
    // A dedicated manager advertising a config blob: the client (seeded with
    // a different local hash) downloads it through the chunked /download,
    // reads it inside the callback, and the optimistic hash update keeps the
    // count at one across further notifies.
    const uint16_t port = TLS_PORT + 2;
    const std::string blob = "#merged.mg v2\n<agent_config></agent_config>\n";
    FakeManager manager {port, KEY_HEX, /*tls=*/true, /*settingsFlipAfter=*/0, blob};

    ConfigRecorder recorder;
    hc_config_t config = tlsConfig();
    config.server_port = port;
    std::strncpy(config.config_checksum, "0000-local-out-of-date",
                 sizeof(config.config_checksum) - 1);
    hc_callbacks_t callbacks {};
    callbacks.on_config_downloaded = onConfigDownloaded;
    callbacks.user_data = &recorder;

    hc_handle* handle = hc_create(&config, &callbacks);
    ASSERT_NE(nullptr, handle);
    ASSERT_TRUE(hc_start(handle));

    ASSERT_TRUE(waitFor(recorder.count, 1, 5000)); // Downloaded + delivered.

    // notify_interval_s = 1: give two more notify cycles a chance to
    // (wrongly) re-download; the optimistic update must keep it at one.
    std::this_thread::sleep_for(std::chrono::milliseconds {2500});
    EXPECT_EQ(1, recorder.count.load());
    hc_destroy(handle);

    std::lock_guard<std::mutex> lock(recorder.mutex);
    EXPECT_EQ(blob, recorder.content); // Byte-exact through chunked TLS.
    EXPECT_EQ(64u, recorder.hash.size()); // A SHA-256 hex.
}

namespace
{
    struct ReenrollRecorder
    {
        std::atomic<int> reenrollCount {0};
        std::mutex mutex;
        std::atomic<int> startups {0};
        std::vector<int> states;
    };

    // A key-rotating manager stored in a global so the C callback can reach it.
    hc_handle* g_keyRotationHandle = nullptr;
    std::string g_rotatedKey;

    void onReenroll(void* userData)
    {
        static_cast<ReenrollRecorder*>(userData)->reenrollCount++;
        // The consumer's re-enrollment: swap in the new key (callback-safe).
        hc_set_agent_key(g_keyRotationHandle, g_rotatedKey.c_str());
    }

    void onReenrollStartup(bool accepted, const char*, void* userData)
    {
        if (accepted)
        {
            static_cast<ReenrollRecorder*>(userData)->startups++;
        }
    }

    void onReenrollState(int state, void* userData)
    {
        auto* recorder = static_cast<ReenrollRecorder*>(userData);
        std::lock_guard<std::mutex> lock(recorder->mutex);
        recorder->states.push_back(state);
    }
} // namespace

TEST_F(FacadeE2eTest, KeyRotationFiresReenrollAndHcSetAgentKeyRecovers)
{
    // The manager rotates its key after 2 notifies: the old key starts getting
    // 401, the module pauses + fires on_reenroll_required once, the callback
    // swaps the key via hc_set_agent_key, and the client re-registers (#37828).
    const uint16_t port = TLS_PORT + 4;
    const std::string oldKey = KEY_HEX;
    const std::string newKey = "0f0e0d0c0b0a09080706050403020100";
    FakeManager manager {port, oldKey, /*tls=*/true, 0, {}, 0, /*rotateKeyAfterNotifies=*/2, newKey};

    ReenrollRecorder recorder;
    hc_config_t config = tlsConfig();
    config.server_port = port;
    std::strncpy(config.agent_key, oldKey.c_str(), sizeof(config.agent_key) - 1);
    hc_callbacks_t callbacks {};
    callbacks.on_startup_result = onReenrollStartup;
    callbacks.on_reenroll_required = onReenroll;
    callbacks.on_state_change = onReenrollState;
    callbacks.user_data = &recorder;

    hc_handle* handle = hc_create(&config, &callbacks);
    ASSERT_NE(nullptr, handle);
    g_keyRotationHandle = handle;
    g_rotatedKey = newKey;

    ASSERT_TRUE(hc_start(handle));
    ASSERT_TRUE(waitFor(recorder.startups, 1, 3000)); // First registration (old key).

    // After the rotation the old key 401s -> exactly one re-enroll callback.
    ASSERT_TRUE(waitFor(recorder.reenrollCount, 1, 6000));
    // The swapped key re-registers: a second accepted startup.
    ASSERT_TRUE(waitFor(recorder.startups, 2, 6000));
    hc_destroy(handle);
    g_keyRotationHandle = nullptr;

    EXPECT_EQ(1, recorder.reenrollCount.load()); // Fired once, not per 401.
    std::lock_guard<std::mutex> lock(recorder.mutex);
    EXPECT_NE(recorder.states.end(),
              std::find(recorder.states.begin(), recorder.states.end(), HC_STATE_AUTH_ERROR));
    EXPECT_NE(recorder.states.end(),
              std::find(recorder.states.begin(), recorder.states.end(), HC_STATE_REGISTERED));
}

TEST_F(FacadeE2eTest, OversizedBatchIsSplitAndResentWithoutLoss)
{
    // The manager 413s any /stateless body over ~600 bytes; the client must
    // split and resend smaller so every event lands exactly once (#37835).
    const uint16_t port = TLS_PORT + 3;
    FakeManager manager {port, KEY_HEX, /*tls=*/true, 0, {}, /*statelessMaxBody=*/600};

    Recorder recorder;
    hc_config_t config = tlsConfig();
    config.server_port = port;
    // Max payload 1024 straddles the 600-byte manager limit, so a 413 halves
    // the effective size down under it and the split succeeds.
    config.batch_size_bytes = 1024;
    hc_callbacks_t callbacks {};
    callbacks.on_startup_result = onStartup;
    callbacks.on_state_change = onState;
    callbacks.user_data = &recorder;

    hc_handle* handle = hc_create(&config, &callbacks);
    ASSERT_NE(nullptr, handle);
    ASSERT_TRUE(hc_start(handle));
    ASSERT_TRUE(waitFor(recorder.startupCount, 1, 3000));

    // 40 distinctly-numbered events; each "E evt-NN:payload...\n" ~30 bytes,
    // so the full batch (~1200 B) exceeds the 600-byte limit and must split.
    constexpr int total = 40;

    for (int index = 0; index < total; index++)
    {
        char frame[64];
        const int n = std::snprintf(frame, sizeof frame, "1:/loc:evt-%02d-payload", index);
        EXPECT_TRUE(hc_submit_event(handle, reinterpret_cast<const uint8_t*>(frame),
                                    static_cast<size_t>(n)));
    }

    // Poll the manager's accumulated view until all events land (or time out).
    httplib::Client peek {std::string {"https://127.0.0.1:"} + std::to_string(port)};
    peek.enable_server_certificate_verification(false);
    std::string received;

    for (int attempt = 0; attempt < 300; attempt++)
    {
        if (auto result = peek.Get("/peek/stateless"))
        {
            received = result->body;
            int seen = 0;

            for (int index = 0; index < total; index++)
            {
                char needle[32];
                std::snprintf(needle, sizeof needle, "evt-%02d-", index);
                seen += received.find(needle) != std::string::npos ? 1 : 0;
            }

            if (seen == total)
            {
                break;
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds {20});
    }

    hc_destroy(handle);

    // Every event delivered exactly once, none dropped despite the 413s.
    for (int index = 0; index < total; index++)
    {
        char needle[32];
        std::snprintf(needle, sizeof needle, "evt-%02d-", index);
        const size_t first = received.find(needle);
        ASSERT_NE(std::string::npos, first) << "missing event " << index;
        EXPECT_EQ(std::string::npos, received.find(needle, first + 1))
                << "duplicated event " << index;
    }
}

TEST_F(FacadeE2eTest, SettingsChangeRefreshesStartupWithoutLeavingRegistered)
{
    // A dedicated manager that flips its settings after 2 notifies: the
    // client detects the settings_hash change and re-sends startup while
    // staying registered the whole time (5.1.2 / sequence diagram 7).
    const uint16_t port = TLS_PORT + 1;
    FakeManager manager {port, KEY_HEX, /*tls=*/true, /*settingsFlipAfter=*/2};

    Recorder recorder;
    hc_config_t config = tlsConfig();
    config.server_port = port;
    hc_callbacks_t callbacks {};
    callbacks.on_startup_result = onStartup;
    callbacks.on_state_change = onState;
    callbacks.user_data = &recorder;

    hc_handle* handle = hc_create(&config, &callbacks);
    ASSERT_NE(nullptr, handle);
    ASSERT_TRUE(hc_start(handle));
    ASSERT_TRUE(waitFor(recorder.startupCount, 1, 3000)); // First registration.

    // notify_interval_s = 1: the flip lands after ~2 s, the refresh follows.
    ASSERT_TRUE(waitFor(recorder.startupCount, 2, 8000)); // The refresh.
    hc_destroy(handle);

    // One STARTING only: the refresh never left REGISTERED.
    std::lock_guard<std::mutex> lock(recorder.mutex);
    EXPECT_EQ(1, std::count(recorder.states.begin(), recorder.states.end(),
                            HC_STATE_STARTING));
    EXPECT_EQ(0, std::count(recorder.states.begin(), recorder.states.end(),
                            HC_STATE_REJECTED));
    EXPECT_EQ(HC_STATE_STOPPED, recorder.states.back());
}
