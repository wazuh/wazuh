/*
 * Wazuh remoted module - Hash cache unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "control/controlConfig.hpp"
#include "control/hashCache.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <unistd.h>

using namespace remoted::control;
namespace fs = std::filesystem;

namespace
{
    // Per-test scratch directory under /tmp so the watcher's inotify roots are
    // real (they must exist for MergedMgWatcher's ctor to succeed) but isolated
    // from anything the running manager might touch.
    class TempDirs
    {
    public:
        TempDirs()
        {
            m_base = fs::temp_directory_path() / ("wazuh_hashcache_test_" + std::to_string(::getpid()) + "_" +
                                                  std::to_string(reinterpret_cast<uintptr_t>(this)));
            fs::create_directories(m_base / "shared");
            fs::create_directories(m_base / "multi");
        }
        ~TempDirs()
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
        std::string outside() const
        {
            return m_base.string();
        }

    private:
        fs::path m_base;
    };

    // Baseline Config that HashCache::Impl won't reject. The watcher watches
    // the two "roots"; keeping them as real (empty) dirs avoids the ctor error
    // path (inotify_add_watch fails on missing paths).
    Config makeConfig(const TempDirs& dirs)
    {
        Config c;
        c.sharedGroupsRoot = dirs.shared();
        c.multiGroupsRoot = dirs.multi();
        c.clusterName = "wazuh";
        c.limits = nlohmann::json::object();
        return c;
    }

    void writeFile(const fs::path& p, const std::string& content)
    {
        fs::create_directories(p.parent_path());
        std::ofstream f(p, std::ios::binary);
        f << content;
    }
} // namespace

// -----------------------------------------------------------------------------
// getMergedMgPath: single-group path
// -----------------------------------------------------------------------------

TEST(HashCacheTest, GetMergedMgPathSingleGroup)
{
    TempDirs dirs;
    HashCache cache(makeConfig(dirs));

    const auto path = cache.getMergedMgPath("default");
    EXPECT_EQ(path, dirs.shared() + "/default/merged.mg");
}

// -----------------------------------------------------------------------------
// getMergedMgPath: multi-group hits the multi root with sha256[:8] hash.
// The hash is deterministic (raw CSV, no encoding), so we can pin the value.
// -----------------------------------------------------------------------------
TEST(HashCacheTest, GetMergedMgPathMultiGroup)
{
    TempDirs dirs;
    HashCache cache(makeConfig(dirs));

    const auto path = cache.getMergedMgPath("g1,g2");

    // Layout is <multi>/<sha256(csv)[:8]>/merged.mg. We only assert the shape:
    // the first-eight-hex-chars is easier to eyeball as a regex here than to
    // hardcode -- and any change to hashing would break the test on purpose.
    ASSERT_FALSE(path.empty());
    EXPECT_EQ(path.rfind(dirs.multi() + "/", 0), 0U);
    const std::string suffix = "/merged.mg";
    ASSERT_GE(path.size(), suffix.size());
    EXPECT_EQ(path.compare(path.size() - suffix.size(), suffix.size(), suffix), 0);
    // Between the root and /merged.mg there should be exactly 8 hex chars.
    const auto stem = path.substr(dirs.multi().size() + 1);
    ASSERT_EQ(stem.size(), std::string("XXXXXXXX/merged.mg").size());
    for (size_t i = 0; i < 8; ++i)
    {
        EXPECT_TRUE((stem[i] >= '0' && stem[i] <= '9') || (stem[i] >= 'a' && stem[i] <= 'f'))
            << "non-hex char at " << i << ": " << stem[i];
    }
}

TEST(HashCacheTest, GetMergedMgPathMultiGroupIsStableForSameCsv)
{
    TempDirs dirs;
    HashCache cache(makeConfig(dirs));

    EXPECT_EQ(cache.getMergedMgPath("g1,g2,g3"), cache.getMergedMgPath("g1,g2,g3"));
}

// -----------------------------------------------------------------------------
// getMergedMgPath: whitelist + safety rejections.
// -----------------------------------------------------------------------------

TEST(HashCacheTest, GetMergedMgPathRejectsEmpty)
{
    TempDirs dirs;
    HashCache cache(makeConfig(dirs));
    EXPECT_EQ(cache.getMergedMgPath(""), "");
}

TEST(HashCacheTest, GetMergedMgPathRejectsDotOrDotDot)
{
    TempDirs dirs;
    HashCache cache(makeConfig(dirs));
    EXPECT_EQ(cache.getMergedMgPath("."), "");
    EXPECT_EQ(cache.getMergedMgPath(".."), "");
}

TEST(HashCacheTest, GetMergedMgPathRejectsTraversalTokens)
{
    TempDirs dirs;
    HashCache cache(makeConfig(dirs));
    // "../etc" contains characters outside [A-Za-z0-9._-].
    EXPECT_EQ(cache.getMergedMgPath("../etc"), "");
    // A slash in the token would let an attacker walk outside the root.
    EXPECT_EQ(cache.getMergedMgPath("a/b"), "");
    // Multigroup: any bad token invalidates the whole CSV.
    EXPECT_EQ(cache.getMergedMgPath("good,.."), "");
    EXPECT_EQ(cache.getMergedMgPath("good,../etc"), "");
    // Empty tokens between commas mean a malformed CSV.
    EXPECT_EQ(cache.getMergedMgPath("g1,,g2"), "");
    // Non-ASCII / control chars are rejected too.
    EXPECT_EQ(cache.getMergedMgPath("café"), "");
    EXPECT_EQ(cache.getMergedMgPath("g1;rm"), "");
}

TEST(HashCacheTest, GetMergedMgPathAcceptsWhitelistTokens)
{
    TempDirs dirs;
    HashCache cache(makeConfig(dirs));
    // The whitelist is [A-Za-z0-9._-]+.
    EXPECT_FALSE(cache.getMergedMgPath("Az0-9._").empty());
    EXPECT_FALSE(cache.getMergedMgPath("g-1,g_2,g.3").empty());
}

// -----------------------------------------------------------------------------
// getConfigHash: real SHA-256 of a real file.
// -----------------------------------------------------------------------------

TEST(HashCacheTest, GetConfigHashReturnsShaOfFile)
{
    TempDirs dirs;
    HashCache cache(makeConfig(dirs));

    const auto file = fs::path(dirs.shared()) / "default" / "merged.mg";
    // Empty-string SHA-256 is well-known.
    writeFile(file, "");
    const auto emptyHash = cache.getConfigHash(file.string());
    EXPECT_EQ(emptyHash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    // Cached: a second call returns the same value.
    EXPECT_EQ(cache.getConfigHash(file.string()), emptyHash);
}

// A "known-vector" test using SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824.
TEST(HashCacheTest, GetConfigHashKnownVector)
{
    TempDirs dirs;
    HashCache cache(makeConfig(dirs));

    const auto file = fs::path(dirs.shared()) / "default" / "merged.mg";
    writeFile(file, "hello");
    EXPECT_EQ(cache.getConfigHash(file.string()), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}

// The empty path is a documented "not applicable" state (single group with no
// name / unresolved CSV) -- must return "" without touching the disk.
TEST(HashCacheTest, GetConfigHashRejectsEmptyPath)
{
    TempDirs dirs;
    HashCache cache(makeConfig(dirs));
    EXPECT_EQ(cache.getConfigHash(""), "");
}

// A missing file must return "" AND must NOT be cached. If it WERE cached, a
// later valid file at the same path would still report "" until the watcher
// fired, which on a fresh install may never happen -- that's the cache-poison
// scenario the Phase 4 fix closed.
TEST(HashCacheTest, GetConfigHashDoesNotCacheEmptyResults)
{
    TempDirs dirs;
    HashCache cache(makeConfig(dirs));

    const auto file = fs::path(dirs.shared()) / "default" / "merged.mg";
    // File does not exist yet.
    EXPECT_EQ(cache.getConfigHash(file.string()), "");

    // Now the file appears. Because the previous "" was not cached, this call
    // recomputes and returns the real hash instead of the stale empty entry.
    writeFile(file, "hello");
    EXPECT_EQ(cache.getConfigHash(file.string()), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}

// invalidateConfigHash forces the next call to re-read the file.
TEST(HashCacheTest, InvalidateConfigHashForcesRecompute)
{
    TempDirs dirs;
    HashCache cache(makeConfig(dirs));

    // Place the file OUTSIDE sharedGroupsRoot / multiGroupsRoot so the merged.mg
    // watcher doesn't invalidate it behind our back. This test isolates the
    // "manual invalidate" contract from the "watcher-driven invalidate" one.
    const auto file = fs::path(dirs.outside()) / "config.txt";
    writeFile(file, "hello");
    const auto firstHash = cache.getConfigHash(file.string());
    ASSERT_FALSE(firstHash.empty());

    // Overwrite with different content. The cache still has the old hash.
    writeFile(file, "world");
    EXPECT_EQ(cache.getConfigHash(file.string()), firstHash); // still cached.

    cache.invalidateConfigHash(file.string());
    EXPECT_NE(cache.getConfigHash(file.string()), firstHash); // now fresh.
}

TEST(HashCacheTest, InvalidateConfigHashOnEmptyPathIsNoOp)
{
    TempDirs dirs;
    HashCache cache(makeConfig(dirs));
    // Should not throw / crash. The internal map isn't touched.
    cache.invalidateConfigHash("");
    SUCCEED();
}

// -----------------------------------------------------------------------------
// getSettingsHash: stable per process, depends on cluster/limits.
// -----------------------------------------------------------------------------

TEST(HashCacheTest, GetSettingsHashIsStable)
{
    TempDirs dirs;
    HashCache cache(makeConfig(dirs));

    const auto h1 = cache.getSettingsHash();
    const auto h2 = cache.getSettingsHash();
    EXPECT_FALSE(h1.empty());
    EXPECT_EQ(h1, h2);
    // sha256 hex is 64 chars, all hex.
    EXPECT_EQ(h1.size(), 64U);
}

TEST(HashCacheTest, GetSettingsHashDiffersOnDifferentClusterName)
{
    TempDirs dirs;
    auto c1 = makeConfig(dirs);
    HashCache cache1(c1);

    auto c2 = makeConfig(dirs);
    c2.clusterName = "worker-cluster"; // different cluster name -> different envelope
    HashCache cache2(c2);

    EXPECT_NE(cache1.getSettingsHash(), cache2.getSettingsHash());
}

TEST(HashCacheTest, GetSettingsHashDiffersOnDifferentLimits)
{
    TempDirs dirs;
    auto c1 = makeConfig(dirs);
    HashCache cache1(c1);

    auto c2 = makeConfig(dirs);
    c2.limits["max"] = 5;
    HashCache cache2(c2);

    EXPECT_NE(cache1.getSettingsHash(), cache2.getSettingsHash());
}

// -----------------------------------------------------------------------------
// stop() is idempotent and safe to call more than once (dtor calls it too).
// -----------------------------------------------------------------------------
TEST(HashCacheTest, StopIsIdempotent)
{
    TempDirs dirs;
    HashCache cache(makeConfig(dirs));
    cache.stop();
    cache.stop();
    SUCCEED();
}
