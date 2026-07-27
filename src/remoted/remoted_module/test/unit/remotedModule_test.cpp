/*
 * Wazuh remoted module (C++ worker bridge) - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "remoted_module.h"
#include <atomic>
#include <cstdarg>
#include <gtest/gtest.h>

namespace
{
    std::atomic<int> g_logCalls {0};

    void testLogCallback(int /*level*/,
                         const char* /*tag*/,
                         const char* /*file*/,
                         int /*line*/,
                         const char* /*func*/,
                         const char* /*msg*/,
                         va_list /*args*/)
    {
        g_logCalls.fetch_add(1, std::memory_order_relaxed);
    }

    remoted_module_config_t makeConfig()
    {
        remoted_module_config_t cfg {};
        cfg.port = 1514;
        cfg.worker_node = false;
        std::snprintf(cfg.cluster_name, sizeof(cfg.cluster_name), "%s", "test-cluster");
        std::snprintf(cfg.node_name, sizeof(cfg.node_name), "%s", "test-node");
        return cfg;
    }
} // namespace

class RemotedModuleTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        g_logCalls.store(0, std::memory_order_relaxed);
    }

    void TearDown() override
    {
        // Ensure the module is stopped even if a test asserted early.
        remoted_module_stop();
    }
};

// start() must launch the worker and log, and stop() must return promptly (join succeeds).
TEST_F(RemotedModuleTest, StartAndStop)
{
    const auto cfg = makeConfig();
    remoted_module_start(testLogCallback, &cfg);
    remoted_module_stop();
    EXPECT_GT(g_logCalls.load(), 0);
}

// stop() on a module that was never started must be a safe no-op.
TEST_F(RemotedModuleTest, StopWithoutStartIsSafe)
{
    remoted_module_stop();
    SUCCEED();
}

// A NULL configuration must fall back to defaults without crashing.
TEST_F(RemotedModuleTest, StartWithNullConfig)
{
    remoted_module_start(testLogCallback, nullptr);
    remoted_module_stop();
    EXPECT_GT(g_logCalls.load(), 0);
}

// A second start() while running is ignored; a single stop() tears everything down.
TEST_F(RemotedModuleTest, DoubleStartIsIgnored)
{
    const auto cfg = makeConfig();
    remoted_module_start(testLogCallback, &cfg);
    remoted_module_start(testLogCallback, &cfg);
    remoted_module_stop();
    SUCCEED();
}
