/*
 * Wazuh remoted module - MergedMg watcher unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "control/mergedMgWatcher.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>

using namespace remoted::control;
namespace fs = std::filesystem;
using namespace std::chrono_literals;

namespace
{
    // Bounded wait for the watcher thread to notice a filesystem event and
    // deliver the corresponding callback. inotify latency is normally sub-ms
    // but the watcher polls with a 1s select(), so 3s covers a cold worst case.
    constexpr auto kMaxWait = 3000ms;

    // Thread-safe callback recorder: the watcher may fire on its own thread at
    // any moment, so producer/consumer coordination is mandatory.
    class Recorder
    {
    public:
        void push(const std::string& path)
        {
            std::lock_guard<std::mutex> lock(m_mu);
            m_paths.push_back(path);
            m_cv.notify_all();
        }

        // Wait for at least `n` total events. Returns false on timeout.
        bool waitFor(size_t n, std::chrono::milliseconds timeout)
        {
            std::unique_lock<std::mutex> lock(m_mu);
            return m_cv.wait_for(lock, timeout, [&] { return m_paths.size() >= n; });
        }

        std::deque<std::string> snapshot()
        {
            std::lock_guard<std::mutex> lock(m_mu);
            return m_paths;
        }

    private:
        std::mutex m_mu;
        std::condition_variable m_cv;
        std::deque<std::string> m_paths;
    };

    class TempRoots
    {
    public:
        TempRoots()
        {
            m_base = fs::temp_directory_path() / ("wazuh_watcher_test_" + std::to_string(::getpid()) + "_" +
                                                  std::to_string(reinterpret_cast<uintptr_t>(this)));
            fs::create_directories(m_base / "shared");
            fs::create_directories(m_base / "multi");
        }
        ~TempRoots()
        {
            std::error_code ec;
            fs::remove_all(m_base, ec);
        }

        std::string shared() const
        {
            return (m_base / "shared").string();
        }
        std::string multi() const
        {
            return (m_base / "multi").string();
        }

    private:
        fs::path m_base;
    };

    void writeFile(const fs::path& p, const std::string& content)
    {
        fs::create_directories(p.parent_path());
        std::ofstream f(p, std::ios::binary);
        f << content;
    }
} // namespace

// -----------------------------------------------------------------------------
// Baseline: creating merged.mg in a pre-existing subdir fires the callback.
// The subdir must exist BEFORE the watcher starts so the initial scan wires it.
// -----------------------------------------------------------------------------
TEST(MergedMgWatcherTest, CallbackFiresOnMergedMgCloseWrite)
{
    TempRoots roots;
    fs::create_directories(fs::path(roots.shared()) / "default");

    Recorder rec;
    MergedMgWatcher watcher(roots.shared(), roots.multi(), [&](const std::string& p) { rec.push(p); });

    // Give the watcher a beat to install its watches before we touch the fs.
    std::this_thread::sleep_for(50ms);

    const auto mergedMg = fs::path(roots.shared()) / "default" / "merged.mg";
    writeFile(mergedMg, "payload-v1");

    ASSERT_TRUE(rec.waitFor(1, kMaxWait)) << "callback never fired";
    const auto snap = rec.snapshot();
    EXPECT_EQ(snap.front(), mergedMg.string());
}

// -----------------------------------------------------------------------------
// The watcher must ignore non-merged.mg files in the same group directory:
// the callback is a targeted invalidation, not a "something changed" ping.
// -----------------------------------------------------------------------------
TEST(MergedMgWatcherTest, IgnoresNonMergedMgFilesInSubdir)
{
    TempRoots roots;
    fs::create_directories(fs::path(roots.shared()) / "default");

    Recorder rec;
    MergedMgWatcher watcher(roots.shared(), roots.multi(), [&](const std::string& p) { rec.push(p); });
    std::this_thread::sleep_for(50ms);

    // Any other file in default/ should be a no-op.
    writeFile(fs::path(roots.shared()) / "default" / "agent.conf", "irrelevant");
    writeFile(fs::path(roots.shared()) / "default" / "shared.conf", "irrelevant");

    // Nothing should have arrived within 500ms.
    EXPECT_FALSE(rec.waitFor(1, 500ms));

    // Now touch merged.mg and confirm the watcher IS still active.
    writeFile(fs::path(roots.shared()) / "default" / "merged.mg", "payload-v1");
    ASSERT_TRUE(rec.waitFor(1, kMaxWait));
    EXPECT_EQ(rec.snapshot().front(), (fs::path(roots.shared()) / "default" / "merged.mg").string());
}

// -----------------------------------------------------------------------------
// A new subdir created AFTER the watcher starts must also be watched. This is
// what makes the "add a new group at runtime" flow work without a restart.
// -----------------------------------------------------------------------------
TEST(MergedMgWatcherTest, NewSubdirWatchedAutomatically)
{
    TempRoots roots;
    Recorder rec;
    MergedMgWatcher watcher(roots.shared(), roots.multi(), [&](const std::string& p) { rec.push(p); });
    std::this_thread::sleep_for(50ms);

    // Create a new group subdir. The watcher itself watches the root for
    // IN_CREATE and installs a subdir watch on the fly.
    fs::create_directories(fs::path(roots.shared()) / "newgroup");

    // Give the watcher a moment to react to IN_CREATE and add the child watch.
    std::this_thread::sleep_for(100ms);

    // Now writing merged.mg in the new dir must fire the callback.
    const auto mergedMg = fs::path(roots.shared()) / "newgroup" / "merged.mg";
    writeFile(mergedMg, "payload");

    ASSERT_TRUE(rec.waitFor(1, kMaxWait));
    // We may see multiple events (root IN_CREATE-driven synthesis + child
    // IN_CLOSE_WRITE); we only assert one of them matches the merged.mg path.
    bool matched = false;
    for (const auto& p : rec.snapshot())
    {
        if (p == mergedMg.string())
        {
            matched = true;
            break;
        }
    }
    EXPECT_TRUE(matched);
}

// -----------------------------------------------------------------------------
// merged.mg appearing via a rename (IN_MOVED_TO) must be treated the same as
// a fresh write. Legacy Wazuh sometimes stages merged.mg elsewhere and renames.
// -----------------------------------------------------------------------------
TEST(MergedMgWatcherTest, CallbackFiresOnMergedMgMovedIntoSubdir)
{
    TempRoots roots;
    fs::create_directories(fs::path(roots.shared()) / "default");

    Recorder rec;
    MergedMgWatcher watcher(roots.shared(), roots.multi(), [&](const std::string& p) { rec.push(p); });
    std::this_thread::sleep_for(50ms);

    // Stage the payload under a scratch name in the same directory (same fs so
    // the rename is atomic and stays inotify-visible), then rename to merged.mg.
    const auto scratch = fs::path(roots.shared()) / "default" / ".merged.mg.tmp";
    const auto mergedMg = fs::path(roots.shared()) / "default" / "merged.mg";
    writeFile(scratch, "renamed");
    // .merged.mg.tmp starts with '.' -> not merged.mg, so no callback yet.
    // Rename into place.
    fs::rename(scratch, mergedMg);

    ASSERT_TRUE(rec.waitFor(1, kMaxWait));
    // At least one event should match the merged.mg path.
    bool matched = false;
    for (const auto& p : rec.snapshot())
    {
        if (p == mergedMg.string())
        {
            matched = true;
            break;
        }
    }
    EXPECT_TRUE(matched);
}

// -----------------------------------------------------------------------------
// stop() must be idempotent and safe to call from the outside before dtor.
// -----------------------------------------------------------------------------
TEST(MergedMgWatcherTest, StopIsIdempotent)
{
    TempRoots roots;
    Recorder rec;
    MergedMgWatcher watcher(roots.shared(), roots.multi(), [&](const std::string& p) { rec.push(p); });
    watcher.stop();
    watcher.stop();
    // Dtor is about to run after stop() -- must not block or crash.
    SUCCEED();
}

// -----------------------------------------------------------------------------
// After stop(), no further callbacks fire even if the filesystem is touched.
// -----------------------------------------------------------------------------
TEST(MergedMgWatcherTest, NoCallbacksAfterStop)
{
    TempRoots roots;
    fs::create_directories(fs::path(roots.shared()) / "default");

    Recorder rec;
    MergedMgWatcher watcher(roots.shared(), roots.multi(), [&](const std::string& p) { rec.push(p); });
    std::this_thread::sleep_for(50ms);
    watcher.stop();

    // Drain any late events that may have fired during setup.
    (void)rec.waitFor(1, 100ms);
    const size_t baseline = rec.snapshot().size();

    writeFile(fs::path(roots.shared()) / "default" / "merged.mg", "post-stop");
    // No new events should arrive within 500ms.
    (void)rec.waitFor(baseline + 1, 500ms);
    EXPECT_EQ(rec.snapshot().size(), baseline);
}
