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
#include <cstdlib>
#include <fstream>
#include <gtest/gtest.h>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>
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

    // Generates a throwaway self-signed cert/key pair (via the `openssl` CLI, already a
    // build/runtime dependency) so start() can be exercised for real instead of only against
    // the missing-certificate failure path. remoted itself would read these files while still
    // root, before dropping privileges -- here we just read them straight from the test
    // process, since the point under test is the module's in-memory PEM handling, not the
    // privilege-drop timing (that lives in remoted.c/secure.c, outside this module).
    class TempCert
    {
    public:
        TempCert()
        {
            char dirTemplate[] = "/tmp/remotedModuleTestXXXXXX";
            m_dir = mkdtemp(dirTemplate);
            const std::string certPath = m_dir + "/cert.pem";
            const std::string keyPath = m_dir + "/key.pem";

            const std::string cmd = "openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=test -keyout " +
                                     keyPath + " -out " + certPath + " >/dev/null 2>&1";
            if (std::system(cmd.c_str()) != 0)
            {
                ADD_FAILURE() << "Failed to generate a throwaway TLS certificate for testing";
            }

            m_certPem = readFile(certPath);
            m_keyPem = readFile(keyPath);

            std::remove(certPath.c_str());
            std::remove(keyPath.c_str());
            rmdir(m_dir.c_str());
        }

        const std::string& certPem() const { return m_certPem; }
        const std::string& keyPem() const { return m_keyPem; }

    private:
        static std::string readFile(const std::string& path)
        {
            std::ifstream file(path);
            std::ostringstream contents;
            contents << file.rdbuf();
            return contents.str();
        }

        std::string m_dir;
        std::string m_certPem;
        std::string m_keyPem;
    };

    remoted_module_config_t makeConfig(const std::string& certPem = "", const std::string& keyPem = "")
    {
        remoted_module_config_t cfg {};
        cfg.port = 0; // ephemeral: avoid colliding with a real listener or another test run
        cfg.worker_node = false;
        std::snprintf(cfg.cluster_name, sizeof(cfg.cluster_name), "%s", "test-cluster");
        std::snprintf(cfg.node_name, sizeof(cfg.node_name), "%s", "test-node");
        if (!certPem.empty())
        {
            std::snprintf(cfg.certificate_pem, sizeof(cfg.certificate_pem), "%s", certPem.c_str());
        }
        if (!keyPem.empty())
        {
            std::snprintf(cfg.private_key_pem, sizeof(cfg.private_key_pem), "%s", keyPem.c_str());
        }
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
    TempCert cert;
    const auto cfg = makeConfig(cert.certPem(), cert.keyPem());
    EXPECT_NO_THROW(remoted_module_start(testLogCallback, &cfg));
    remoted_module_stop();
    EXPECT_GT(g_logCalls.load(), 0);
}

// stop() on a module that was never started must be a safe no-op.
TEST_F(RemotedModuleTest, StopWithoutStartIsSafe)
{
    remoted_module_stop();
    SUCCEED();
}

// No certificate/key PEM content supplied is fatal: there is no retry/recovery anymore, so
// start() must propagate the failure instead of starting anyway. In production this content
// comes from remoted.c reading etc/https-manager.{cert,key} before dropping privileges; an
// empty config here stands in for that read having found nothing.
TEST_F(RemotedModuleTest, StartWithoutCertificateThrows)
{
    const auto cfg = makeConfig();
    EXPECT_THROW(remoted_module_start(testLogCallback, &cfg), std::exception);
    EXPECT_GT(g_logCalls.load(), 0); // the "Starting remoted module..." log still happened
}

// A NULL configuration falls back to defaults, which carry no PEM content -- so this must
// throw for the same reason as StartWithoutCertificateThrows.
TEST_F(RemotedModuleTest, StartWithNullConfigThrows)
{
    EXPECT_THROW(remoted_module_start(testLogCallback, nullptr), std::exception);
    EXPECT_GT(g_logCalls.load(), 0);
}

// A second start() while running is ignored; a single stop() tears everything down.
TEST_F(RemotedModuleTest, DoubleStartIsIgnored)
{
    TempCert cert;
    const auto cfg = makeConfig(cert.certPem(), cert.keyPem());
    EXPECT_NO_THROW(remoted_module_start(testLogCallback, &cfg));
    EXPECT_NO_THROW(remoted_module_start(testLogCallback, &cfg));
    remoted_module_stop();
    SUCCEED();
}

// The wedge regression: start() used to set m_running BEFORE creating the worker thread, so a
// throwing std::thread constructor left the module claiming to run with nothing running -- and every
// later start() was refused with "already started". This pins the invariant from the reachable
// direction (a clean stop must leave the module startable again).
TEST_F(RemotedModuleTest, StartStopStartAgainWorks)
{
    TempCert cert;
    const auto cfg = makeConfig(cert.certPem(), cert.keyPem());

    EXPECT_NO_THROW(remoted_module_start(testLogCallback, &cfg));
    remoted_module_stop();

    LogRecorder::clear();
    EXPECT_NO_THROW(remoted_module_start(testLogCallback, &cfg));

    // A second, healthy start must actually run -- not be refused as "already started".
    EXPECT_TRUE(LogRecorder::waitForMessageContaining("worker thread running"))
        << "the module refused to restart after a clean stop";

    remoted_module_stop();
}
