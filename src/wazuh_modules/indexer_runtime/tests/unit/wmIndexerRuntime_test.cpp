/*
 * Wazuh modulesd indexer client runtime bridge
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>

#include <dlfcn.h>

#include <algorithm>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "indexer_client/runtime.hpp"
#include "wmIndexerRuntime.hpp"
#include "wm_indexer_runtime_api.h"

namespace
{
    constexpr const char* kIndexer = R"({"hosts":["http://127.0.0.1:1"]})";
    constexpr const char* kSecret = "s3cr3t";

    constexpr const char* kTag = "wazuh-manager-modulesd:indexer-client";

    std::mutex g_logMutex;
    std::vector<std::string> g_lines;
    std::vector<std::string> g_tags;

    void captureLog(int, const char* tag, const char*, int, const char*, const char* msg, va_list args)
    {
        char buf[2048];
        va_list copy;
        va_copy(copy, args);
        vsnprintf(buf, sizeof(buf), msg, copy);
        va_end(copy);
        std::lock_guard<std::mutex> lock(g_logMutex);
        g_lines.emplace_back(buf);
        g_tags.emplace_back(tag != nullptr ? tag : "(null)");
    }

    std::size_t capturedLines()
    {
        std::lock_guard<std::mutex> lock(g_logMutex);
        return g_lines.size();
    }

    /// Longer than the small-string buffer: kept in the heap by the bridge's State.
    constexpr const char* kLongOptions = "analysisd.debug=0\nremoted.debug=0\nwazuh_modules.debug=0";

    /// Read at exit() by StateUsableDuringExit's child, after every destructor registered once the child started.
    const indexer_client::RuntimeRef* g_exitRef = nullptr;

    void useStateAtExit()
    {
        // What a module thread whose join expired may still do while exit() runs. Under ASAN a destroyed State (its
        // option strings freed) aborts in wmir_configure().
        char why[256] {};
        const bool configured = wmir_configure(kLongOptions, kIndexer, 1, why, sizeof(why)) == 0;
        const bool valid = g_exitRef != nullptr && g_exitRef->valid();
        const bool published = wmir_ref() != nullptr;
        std::_Exit(configured && !valid && !published ? 0 : 3);
    }

    std::vector<std::string> icThreads()
    {
        std::vector<std::string> names;
        for (const auto& e : std::filesystem::directory_iterator("/proc/self/task"))
        {
            std::ifstream f(e.path() / "comm");
            std::string name;
            std::getline(f, name);
            if (name.rfind("ic-", 0) == 0)
            {
                names.push_back(name);
            }
        }
        return names;
    }

    /// The runtime threads name themselves once running: wait for the name (up to 5 s) instead of racing them.
    bool hasThread(const std::string& name)
    {
        const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        for (;;)
        {
            const auto t = icThreads();
            if (std::find(t.begin(), t.end(), name) != t.end())
            {
                return true;
            }
            if (std::chrono::steady_clock::now() >= until)
            {
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    const indexer_client::RuntimeRef* ref()
    {
        return static_cast<const indexer_client::RuntimeRef*>(wmir_ref());
    }
} // namespace

class WmIndexerRuntime : public ::testing::Test
{
protected:
    char reason[512] {};

    void SetUp() override
    {
        wmir::resetForTests();
        std::lock_guard<std::mutex> lock(g_logMutex);
        g_lines.clear();
        g_tags.clear();
    }

    void TearDown() override
    {
        wmir::resetForTests();
    }

    void useCredentials(const std::string& user, const std::string& password)
    {
        wmir::setCredentialReaderForTests([=]() { return indexer_client::Credentials {user, password}; });
    }

    int configure(const char* text = "", int consumer = 1)
    {
        reason[0] = '\0';
        return wmir_configure(text, kIndexer, consumer, reason, sizeof(reason));
    }

    int start()
    {
        reason[0] = '\0';
        return wmir_start(captureLog, reason, sizeof(reason));
    }

    bool secretLogged()
    {
        std::lock_guard<std::mutex> lock(g_logMutex);
        for (const auto& l : g_lines)
        {
            if (l.find(kSecret) != std::string::npos)
            {
                return true;
            }
        }
        return std::string(reason).find(kSecret) != std::string::npos;
    }
};

TEST_F(WmIndexerRuntime, InvalidKeyFailsNamingIt)
{
    EXPECT_EQ(configure("wazuh_modules.indexer_client_netwrk_threads=2"), -1);
    EXPECT_NE(std::string(reason).find("wazuh_modules.indexer_client_netwrk_threads"), std::string::npos) << reason;
}

TEST_F(WmIndexerRuntime, EmptyTextIsDefaults)
{
    EXPECT_EQ(configure(""), 0) << reason;
}

TEST_F(WmIndexerRuntime, ForeignKeysIgnored)
{
    EXPECT_EQ(configure("analysisd.x=1\nremoted.y="), 0) << reason;
}

TEST_F(WmIndexerRuntime, NoConsumerNoRuntime)
{
    useCredentials("admin", kSecret);
    ASSERT_EQ(configure("", 0), 0) << reason;
    EXPECT_EQ(start(), 0) << reason;
    EXPECT_EQ(wmir_ref(), nullptr);
    EXPECT_TRUE(icThreads().empty());
}

TEST_F(WmIndexerRuntime, EmptyCredentialsFailClosed)
{
    ASSERT_EQ(configure(), 0) << reason;
    useCredentials("", kSecret);
    EXPECT_EQ(start(), -1);
    EXPECT_NE(std::string(reason).find("user"), std::string::npos) << reason;
    EXPECT_FALSE(secretLogged()) << reason;
    EXPECT_EQ(wmir_ref(), nullptr);
    EXPECT_TRUE(icThreads().empty());

    wmir::resetForTests();
    ASSERT_EQ(configure(), 0) << reason;
    useCredentials("admin", "");
    EXPECT_EQ(start(), -1);
    EXPECT_NE(std::string(reason).find("password"), std::string::npos) << reason;
    EXPECT_EQ(wmir_ref(), nullptr);
    EXPECT_TRUE(icThreads().empty());
}

TEST_F(WmIndexerRuntime, CredentialReaderThrows)
{
    ASSERT_EQ(configure(), 0) << reason;
    wmir::setCredentialReaderForTests([]() -> indexer_client::Credentials
                                      { throw std::runtime_error("keystore boom"); });
    int rc = 0;
    EXPECT_NO_THROW(rc = start());
    EXPECT_EQ(rc, -1);
    EXPECT_EQ(wmir_ref(), nullptr);
}

TEST_F(WmIndexerRuntime, PasswordNeverLogged)
{
    useCredentials("admin", kSecret);
    ASSERT_EQ(configure(), 0) << reason;
    ASSERT_EQ(start(), 0) << reason;
    EXPECT_FALSE(secretLogged());

    // The unreachable node (127.0.0.1:1) makes the library log; without at least one line the check is vacuous.
    const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (capturedLines() == 0 && std::chrono::steady_clock::now() < until)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    wmir_begin_shutdown(0);
    wmir_shutdown();
    {
        std::lock_guard<std::mutex> lock(g_logMutex);
        ASSERT_FALSE(g_lines.empty()) << "the library logged nothing in 5 s";
        for (const auto& tag : g_tags)
        {
            EXPECT_EQ(tag, kTag);
        }
    }
    EXPECT_FALSE(secretLogged());

    // A failure reason does not carry the password either.
    wmir::resetForTests();
    ASSERT_EQ(configure(), 0) << reason;
    useCredentials("", kSecret);
    EXPECT_EQ(start(), -1);
    EXPECT_NE(reason[0], '\0');
    EXPECT_FALSE(secretLogged()) << reason;
}

TEST_F(WmIndexerRuntime, StartPublishesRef)
{
    useCredentials("admin", kSecret);
    ASSERT_EQ(configure(), 0) << reason;
    ASSERT_EQ(start(), 0) << reason;
    ASSERT_NE(wmir_ref(), nullptr);
    EXPECT_TRUE(ref()->valid());
    EXPECT_TRUE(hasThread("ic-io-0"));
    EXPECT_TRUE(hasThread("ic-cpu-0"));
    EXPECT_TRUE(hasThread("ic-cpu-1"));
}

TEST_F(WmIndexerRuntime, RefStorageOutlivesShutdown)
{
    useCredentials("admin", kSecret);
    ASSERT_EQ(configure(), 0) << reason;
    ASSERT_EQ(start(), 0) << reason;
    const auto* before = ref();
    ASSERT_NE(before, nullptr);
    wmir_begin_shutdown(0);
    wmir_shutdown();
    EXPECT_FALSE(before->valid());
    EXPECT_EQ(wmir_ref(), nullptr);
}

TEST_F(WmIndexerRuntime, RefOutlivesStaticState)
{
    useCredentials("admin", kSecret);
    ASSERT_EQ(configure(), 0) << reason;
    ASSERT_EQ(start(), 0) << reason;
    const auto* taken = ref();
    ASSERT_NE(taken, nullptr);
    wmir::resetForTests();
    EXPECT_FALSE(taken->valid());
    EXPECT_EQ(wmir_ref(), nullptr);
}

// A module thread whose join expired still runs while exit() runs the static destructors: the bridge's state and the
// published reference must survive them (G-diff E7a, obj. 1). A plain TEST, so that nothing touches the bridge before
// the child registers its exit handler: a static State would register its destructor later and be destroyed first.
TEST(WmIndexerRuntimeExit, StateUsableDuringExit)
{
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
    EXPECT_EXIT(
        {
            std::atexit(useStateAtExit);
            wmir::setCredentialReaderForTests([]() { return indexer_client::Credentials {"admin", kSecret}; });
            char why[256] {};
            if (wmir_configure(kLongOptions, kIndexer, 1, why, sizeof(why)) != 0 ||
                wmir_start(nullptr, why, sizeof(why)) != 0)
            {
                std::_Exit(2);
            }
            g_exitRef = static_cast<const indexer_client::RuntimeRef*>(wmir_ref());
            wmir_begin_shutdown(0);
            wmir_shutdown();
            std::exit(0);
        },
        ::testing::ExitedWithCode(0),
        "");
}

// Issue 18: the published RuntimeRef must live on the heap, never in static storage. A static one would be destroyed by
// exit() under a module thread whose join expired; StateUsableDuringExit cannot see that (the weak_ptr's control block
// is kept alive by libindexer_client, so reading the destroyed object still looks fine, even under ASAN). dladdr()
// finds every address inside a loaded image (the test binary or a shared object, .data and .bss included) and none on
// the heap; the control check proves it tells them apart on this platform.
TEST_F(WmIndexerRuntime, PublishedRefIsOnTheHeap)
{
    static const indexer_client::RuntimeRef staticControl;
    Dl_info info {};
    ASSERT_NE(dladdr(&staticControl, &info), 0) << "dladdr() cannot tell static storage apart here";

    useCredentials("admin", kSecret);
    ASSERT_EQ(configure(), 0) << reason;
    ASSERT_EQ(start(), 0) << reason;
    const void* published = wmir_ref();
    ASSERT_NE(published, nullptr);
    info = Dl_info {};
    EXPECT_EQ(dladdr(published, &info), 0)
        << "the published RuntimeRef is in the static storage of " << (info.dli_fname ? info.dli_fname : "(unknown)");
}

TEST_F(WmIndexerRuntime, SecondStartRejected)
{
    useCredentials("admin", kSecret);
    ASSERT_EQ(configure(), 0) << reason;
    ASSERT_EQ(start(), 0) << reason;
    const auto* first = ref();
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(start(), -1);
    EXPECT_TRUE(first->valid());
    EXPECT_EQ(wmir_ref(), first);
}

TEST_F(WmIndexerRuntime, ShutdownWithoutStartIsNoop)
{
    EXPECT_NO_THROW(wmir_begin_shutdown(0));
    EXPECT_NO_THROW(wmir_shutdown());
    EXPECT_EQ(wmir_ref(), nullptr);
}
