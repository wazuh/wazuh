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
 * remoted_module_test style: only the public header is included; the C++
 * internals are never touched. Lifecycle, argument guards and state
 * publication are pinned here.
 */

#include "https_client.h"

#include <gtest/gtest.h>

#include <atomic>
#include <cstring>
#include <string>
#include <vector>

namespace
{
    std::atomic<int> g_logCalls {0};

    // Matches full_log_fnc_t. The log sink is DSO-global (assigned once per
    // process), so this counter is shared across all tests on purpose.
    void testLogCallback(const int level,
                         const char* tag,
                         const char* file,
                         const int line,
                         const char* func,
                         const char* msg,
                         va_list args)
    {
        (void)level;
        (void)tag;
        (void)file;
        (void)line;
        (void)func;
        (void)msg;
        (void)args;
        g_logCalls++;
    }

    // Per-test recorder wired through the callbacks' user_data.
    struct Recorder
    {
        std::vector<int> states;
    };

    void onStateChange(int state, void* userData)
    {
        static_cast<Recorder*>(userData)->states.push_back(state);
    }

    hc_config_t makeConfig()
    {
        hc_config_t config {};
        std::strncpy(config.server_host, "127.0.0.1", sizeof(config.server_host) - 1);
        config.server_port = 27840;
        std::strncpy(config.agent_id, "001", sizeof(config.agent_id) - 1);
        std::strncpy(config.agent_key, "000102030405060708090a0b0c0d0e0f", sizeof(config.agent_key) - 1);
        config.verify_mode = HC_VERIFY_NONE;
        std::strncpy(config.version, "5.1.0", sizeof(config.version) - 1);
        std::strncpy(config.config_checksum, "d41d8cd98f00b204e9800998ecf8427e",
                     sizeof(config.config_checksum) - 1);
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

TEST_F(HcInterfaceTest, StartAndStop)
{
    hc_handle* handle = hc_create(&m_config, &m_callbacks);
    ASSERT_NE(nullptr, handle);
    EXPECT_EQ(HC_STATE_STOPPED, hc_get_state(handle));

    EXPECT_TRUE(hc_start(handle));
    EXPECT_EQ(HC_STATE_STARTING, hc_get_state(handle));

    hc_stop(handle);
    EXPECT_EQ(HC_STATE_STOPPED, hc_get_state(handle));

    hc_destroy(handle);
    ASSERT_EQ(2u, m_recorder.states.size());
    EXPECT_EQ(HC_STATE_STARTING, m_recorder.states[0]);
    EXPECT_EQ(HC_STATE_STOPPED, m_recorder.states[1]);
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
    EXPECT_TRUE(hc_start(handle));
    ASSERT_EQ(1u, m_recorder.states.size());
    EXPECT_EQ(HC_STATE_STARTING, m_recorder.states[0]);
    hc_stop(handle);
    hc_destroy(handle);
}

TEST_F(HcInterfaceTest, DestroyImpliesStop)
{
    hc_handle* handle = hc_create(&m_config, &m_callbacks);
    ASSERT_NE(nullptr, handle);
    EXPECT_TRUE(hc_start(handle));
    hc_destroy(handle);
    ASSERT_EQ(2u, m_recorder.states.size());
    EXPECT_EQ(HC_STATE_STOPPED, m_recorder.states.back());
}

TEST_F(HcInterfaceTest, SubmitBeforeStartIsRejected)
{
    hc_handle* handle = hc_create(&m_config, &m_callbacks);
    ASSERT_NE(nullptr, handle);
    const uint8_t frame[] = "1:/var/log/syslog:hello";
    EXPECT_FALSE(hc_submit_event(handle, frame, sizeof(frame) - 1));
    EXPECT_FALSE(hc_submit_sync_session(handle, "sess-0001", frame, sizeof(frame) - 1));
    EXPECT_FALSE(hc_submit_task_response(handle, "task-0001", "{\"status\":\"done\"}"));
    hc_notify_now(handle); // No crash while stopped.
    EXPECT_EQ(HC_STATE_STOPPED, hc_get_state(handle));
    hc_destroy(handle);
}

TEST_F(HcInterfaceTest, SubmitNullArgumentsAreRejected)
{
    hc_handle* handle = hc_create(&m_config, &m_callbacks);
    ASSERT_NE(nullptr, handle);
    EXPECT_TRUE(hc_start(handle));
    const uint8_t frame[] = "x";
    EXPECT_FALSE(hc_submit_event(handle, nullptr, 1));
    EXPECT_FALSE(hc_submit_event(handle, frame, 0));
    EXPECT_FALSE(hc_submit_sync_session(handle, nullptr, frame, 1));
    EXPECT_FALSE(hc_submit_sync_session(handle, "sess", nullptr, 1));
    EXPECT_FALSE(hc_submit_task_response(handle, nullptr, "{}"));
    EXPECT_FALSE(hc_submit_task_response(handle, "task", nullptr));
    hc_notify_now(handle); // No crash while started either.
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

    hc_config_t noIdConfig = m_config;
    noIdConfig.agent_id[0] = '\0';
    hc_handle* other = hc_create(&noIdConfig, &m_callbacks);
    ASSERT_NE(nullptr, other);
    EXPECT_FALSE(hc_start(other));

    EXPECT_TRUE(m_recorder.states.empty());
    hc_destroy(handle);
    hc_destroy(other);
}

TEST_F(HcInterfaceTest, StartFailsClosedWithoutCaInFullMode)
{
    hc_config_t failClosed = m_config;
    failClosed.verify_mode = HC_VERIFY_FULL; // No CA configured -> must refuse to start.
    hc_handle* handle = hc_create(&failClosed, &m_callbacks);
    ASSERT_NE(nullptr, handle);
    EXPECT_FALSE(hc_start(handle));
    EXPECT_EQ(HC_STATE_STOPPED, hc_get_state(handle));
    EXPECT_TRUE(m_recorder.states.empty());
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
    EXPECT_FALSE(hc_submit_task_response(nullptr, "t", "{}"));
    hc_notify_now(nullptr);
    EXPECT_EQ(HC_STATE_STOPPED, hc_get_state(nullptr));
}
