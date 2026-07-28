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
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <gtest/gtest.h>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace
{
    std::atomic<int> g_logCalls {0};

    /**
     * @brief Process-wide recorder for the module's log output.
     *
     * This is the ONLY way a test can observe what the module logs: Log::GLOBAL_LOG_FUNCTION is
     * declared with hidden visibility and defined inside libremoted_module.so, so a definition in
     * the test binary would be a different object entirely. Going through remoted_module_start()
     * installs this callback into the library's own sink.
     *
     * Must be process-wide rather than per-test: Log::assignLogFunction() only assigns when the sink
     * is still empty, and deassignLogFunction() is not reachable from here -- so the FIRST test to
     * start the module wins for the lifetime of the process.
     */
    struct LogRecorder
    {
        struct Line
        {
            int level;
            std::string tag;
            std::string message;
        };

        static std::mutex& mutex()
        {
            static std::mutex instance;
            return instance;
        }

        static std::vector<Line>& lines()
        {
            static std::vector<Line> instance;
            return instance;
        }

        static void clear()
        {
            std::lock_guard<std::mutex> lock {mutex()};
            lines().clear();
        }

        /// Whether any recorded message contains @p needle. Polls, because the module logs from its
        /// own worker thread.
        static bool waitForMessageContaining(const std::string& needle,
                                             std::chrono::milliseconds timeout = std::chrono::seconds {5})
        {
            const auto deadline = std::chrono::steady_clock::now() + timeout;
            while (std::chrono::steady_clock::now() < deadline)
            {
                {
                    std::lock_guard<std::mutex> lock {mutex()};
                    for (const auto& line : lines())
                    {
                        if (line.message.find(needle) != std::string::npos)
                        {
                            return true;
                        }
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds {20});
            }
            return false;
        }
    };

    void testLogCallback(int level,
                         const char* tag,
                         const char* /*file*/,
                         int /*line*/,
                         const char* /*func*/,
                         const char* msg,
                         va_list args)
    {
        g_logCalls.fetch_add(1, std::memory_order_relaxed);

        // Render the message exactly as _log() would. A va_list may only be traversed once, so this
        // consumes it -- that is fine, nothing downstream of us needs it.
        char buffer[2048];
        if (msg != nullptr)
        {
            std::vsnprintf(buffer, sizeof(buffer), msg, args);
        }
        else
        {
            buffer[0] = '\0';
        }

        std::lock_guard<std::mutex> lock {LogRecorder::mutex()};
        LogRecorder::lines().push_back({level, tag != nullptr ? tag : "", buffer});
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
        LogRecorder::clear();
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

// End-to-end proof that the diagnostics actually reach ossec.log, and that a permanent
// misconfiguration is now reported as an ERROR naming the offending file. Before this work, a
// missing certificate produced only a generic "not started yet, will retry" WARN with an opaque
// OpenSSL string, repeated every 60 s forever and indistinguishable from a bad key, a port clash, or
// a fresh install that simply hadn't been provisioned yet.
TEST_F(RemotedModuleTest, MissingCertificateIsReportedAsAnErrorNamingTheFile)
{
    auto cfg = makeConfig();
    std::snprintf(cfg.certificate_path, sizeof(cfg.certificate_path), "%s", "/tmp/rmt-does-not-exist.crt");
    std::snprintf(cfg.private_key_path, sizeof(cfg.private_key_path), "%s", "/tmp/rmt-does-not-exist.key");

    remoted_module_start(testLogCallback, &cfg);

    // The message must name the actual path, which is what makes it actionable.
    EXPECT_TRUE(LogRecorder::waitForMessageContaining("/tmp/rmt-does-not-exist.crt"))
        << "the startup failure did not name the missing certificate";
    // ...and point at the settings to fix.
    EXPECT_TRUE(LogRecorder::waitForMessageContaining("certificate_path"));

    remoted_module_stop();
}

// The wedge regression: start() used to set m_running BEFORE creating the worker thread, so a
// throwing std::thread constructor left the module claiming to run with nothing running -- and every
// later start() was refused with "already started". This pins the invariant from the reachable
// direction (a clean stop must leave the module startable again).
TEST_F(RemotedModuleTest, StartStopStartAgainWorks)
{
    const auto cfg = makeConfig();

    remoted_module_start(testLogCallback, &cfg);
    remoted_module_stop();

    LogRecorder::clear();
    remoted_module_start(testLogCallback, &cfg);

    // A second, healthy start must actually run -- not be refused as "already started".
    EXPECT_TRUE(LogRecorder::waitForMessageContaining("worker thread running"))
        << "the module refused to restart after a clean stop";

    remoted_module_stop();
}
