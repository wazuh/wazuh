/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "upgradeDoubles.hpp"

#include "upgrade/fileHash.hpp"
#include "upgrade/versionsCache.hpp"
#include "upgrade/wpkCache.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <string>
#include <thread>
#include <vector>

using namespace task_manager;
using namespace task_manager::upgrade;
using task_manager::test::FakeWpkRepository;
using task_manager::test::TempDir;

namespace
{
    // Reference digests, computed with sha1sum rather than with the code under test -- a test that
    // hashed its own fixture would agree with a broken hash function.
    constexpr const char* CONTENT_A {"WPK-CONTENT-A"};
    constexpr const char* SHA1_A {"bdac63d27983c405531b56e2cd0eafa54b2f1d42"};
    constexpr const char* CONTENT_B {"WPK-CONTENT-B"};
    constexpr const char* SHA1_B {"dab1779b13a82aee0500b194360cbb7547abeec8"};

    constexpr const char* WPK_URL {"https://packages.wazuh.com/5.x/wpk/linux/deb/amd64/agent.wpk"};
    constexpr const char* WPK_FILE {"agent.wpk"};

    WpkCache::Options optionsIn(const TempDir& dir, const int attempts = 3, const int concurrency = 2)
    {
        WpkCache::Options options;
        options.upgradeDir = dir.path();
        options.downloadAttempts = attempts;
        options.retryBackoff = std::chrono::milliseconds {1};
        options.maxConcurrentDownloads = concurrency;
        return options;
    }

    WpkCache::Request requestFor(const char* sha1)
    {
        return {WPK_URL, WPK_FILE, sha1};
    }
} // namespace

// ---- file hashing --------------------------------------------------------------------------------

TEST(UpgradeFileHash, HashesAFileInStreamedBlocks)
{
    const TempDir dir;
    dir.writeFile("small", CONTENT_A);
    EXPECT_EQ(sha1OfFile(dir.path() + "small").value_or(""), SHA1_A);

    // Larger than one read block, so the streaming path is actually exercised rather than a single
    // fread -- a WPK is 50-100 MB and must never be loaded whole.
    std::string large;
    large.reserve(200000);
    for (int index = 0; index < 20000; ++index)
    {
        large += "0123456789";
    }
    dir.writeFile("large", large);

    const auto digest {sha1OfFile(dir.path() + "large")};
    ASSERT_TRUE(digest.has_value());
    EXPECT_EQ(digest->size(), 40U);
}

TEST(UpgradeFileHash, ReportsMissingFilesRatherThanThrowing)
{
    EXPECT_FALSE(sha1OfFile("/nonexistent/path/agent.wpk").has_value());
    EXPECT_FALSE(stampOf("/nonexistent/path/agent.wpk").has_value());
}

TEST(UpgradeFileHash, ADirectoryIsNotAFile)
{
    const TempDir dir;
    // Guards the memo: stampOf() accepting a directory would let one masquerade as a cached WPK.
    EXPECT_FALSE(stampOf(dir.path()).has_value());
}

TEST(UpgradeFileHash, DigestComparisonIsCaseInsensitive)
{
    // Published `versions` files have used both cases over the years, and the retired code compared
    // with strcasecmp. Losing that would fail every upgrade against an upper-case repository.
    EXPECT_TRUE(sha1Equals("ABCDEF", "abcdef"));
    EXPECT_FALSE(sha1Equals("abcdef", "abcde"));
    EXPECT_FALSE(sha1Equals("abcdef", "abcdee"));
}

// ---- the WPK cache -------------------------------------------------------------------------------

TEST(UpgradeWpkCache, DownloadsOnceAndVerifiesTheDigest)
{
    const TempDir dir;
    FakeWpkRepository repository;
    repository.scriptDownload(WPK_URL, {true, CONTENT_A, 200, 0, {}, false});

    WpkCache cache {repository, optionsIn(dir)};
    StopToken stop;

    EXPECT_EQ(cache.ensure(requestFor(SHA1_A), stop), UpgradeError::Success);
    EXPECT_EQ(repository.downloadCalls(WPK_URL), 1U);
    EXPECT_EQ(dir.read(WPK_FILE), CONTENT_A);
}

TEST(UpgradeWpkCache, AnExpiredBatchDeadlineStopsBeforeTheFirstAttempt)
{
    // The batch deadline has to be honoured HERE, not only between packages in the orchestrator.
    // Attempts multiply -- upgrade_download_attempts x upgrade_download_timeout plus backoff is
    // ~138 s per package at the defaults -- so a batch spanning a few platforms could otherwise run
    // past the transport's 300 s response backstop, at which point the connection is torn down and
    // the per-agent envelope is discarded rather than delivered.
    const TempDir dir;
    FakeWpkRepository repository;
    repository.scriptDownload(WPK_URL, {true, CONTENT_A, 200, 0, {}, false});

    WpkCache cache {repository, optionsIn(dir)};
    StopToken stop;

    auto request {requestFor(SHA1_A)};
    request.deadline = std::chrono::steady_clock::now() - std::chrono::seconds {1};

    // "The repository is not reachable" -- the same code the orchestrator reports for a package it
    // skipped for the same reason, so the caller sees one answer for one event.
    EXPECT_EQ(cache.ensure(request, stop), UpgradeError::UrlNotFound);

    // And nothing was attempted, which is the point: the deadline is not a post-hoc verdict.
    EXPECT_EQ(repository.downloadCalls(WPK_URL), 0U);
}

TEST(UpgradeWpkCache, ConcurrentCallersForOneFileProduceOneDownload)
{
    // THE TEST THIS CLASS EXISTS FOR. The retired implementation hashed -- and could re-download --
    // the same WPK once per agent, in series, under one global mutex.
    const TempDir dir;
    FakeWpkRepository repository;
    repository.scriptDownload(WPK_URL, {true, CONTENT_A, 200, 0, std::chrono::milliseconds {20}, false});

    WpkCache cache {repository, optionsIn(dir)};
    StopToken stop;

    constexpr int CALLERS {16};
    std::atomic<int> failures {0};
    std::vector<std::thread> threads;
    threads.reserve(CALLERS);

    for (int index = 0; index < CALLERS; ++index)
    {
        threads.emplace_back(
            [&]
            {
                if (cache.ensure(requestFor(SHA1_A), stop) != UpgradeError::Success)
                {
                    ++failures;
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(failures.load(), 0);
    EXPECT_EQ(repository.downloadCalls(WPK_URL), 1U);
    // The other fifteen were answered by the stamp memo without reading the file.
    EXPECT_EQ(cache.memoHitCount(), static_cast<std::size_t>(CALLERS - 1));
}

TEST(UpgradeWpkCache, AWarmFileIsHashedOnceAndThenOnlyStatted)
{
    const TempDir dir;
    // Already on disk from a previous run, with a cold memo.
    dir.writeFile(WPK_FILE, CONTENT_A);

    FakeWpkRepository repository;
    WpkCache cache {repository, optionsIn(dir)};
    StopToken stop;

    EXPECT_EQ(cache.ensure(requestFor(SHA1_A), stop), UpgradeError::Success);
    EXPECT_EQ(repository.totalDownloadCalls(), 0U); // Nothing was fetched.
    EXPECT_EQ(cache.memoHitCount(), 0U);            // The first call had to hash it.

    EXPECT_EQ(cache.ensure(requestFor(SHA1_A), stop), UpgradeError::Success);
    EXPECT_EQ(cache.memoHitCount(), 1U); // The second did not.
}

TEST(UpgradeWpkCache, WrongContentAtTheRightPathIsReplaced)
{
    const TempDir dir;
    dir.writeFile(WPK_FILE, CONTENT_B); // A stale file from an earlier release.

    FakeWpkRepository repository;
    repository.scriptDownload(WPK_URL, {true, CONTENT_A, 200, 0, {}, false});

    WpkCache cache {repository, optionsIn(dir)};
    StopToken stop;

    EXPECT_EQ(cache.ensure(requestFor(SHA1_A), stop), UpgradeError::Success);
    EXPECT_EQ(repository.downloadCalls(WPK_URL), 1U);
    EXPECT_EQ(dir.read(WPK_FILE), CONTENT_A);
}

TEST(UpgradeWpkCache, ServedTheWrongBytesIsADigestFailureNotAMissingFile)
{
    // The distinction matters to the operator: "unreachable" means check the URL, "digest mismatch"
    // means something served content that does not match what the repository's own index claims.
    const TempDir dir;
    FakeWpkRepository repository;
    repository.scriptDownload(WPK_URL, {true, CONTENT_B, 200, 0, {}, false});

    WpkCache cache {repository, optionsIn(dir)};
    StopToken stop;

    EXPECT_EQ(cache.ensure(requestFor(SHA1_A), stop), UpgradeError::WpkSha1DoesNotMatch);
    // Retrying cannot fix wrong bytes, so it is not attempted.
    EXPECT_EQ(repository.downloadCalls(WPK_URL), 1U);
    // AND -- the point of staging -- the bad bytes never reached the path agents are served from.
    EXPECT_FALSE(dir.exists(WPK_FILE));
}

TEST(UpgradeWpkCache, NothingPartialEverReachesTheServedPath)
{
    // remoted's download endpoint carries explicit defensive code against serving a WPK that is
    // still growing, because the retired downloader wrote straight to the final path. Staging and
    // renaming removes the hazard rather than defending against it.
    const TempDir dir;
    FakeWpkRepository repository;
    repository.scriptDownload(WPK_URL, {false, "PARTIAL", 200, 0, {}, true});

    WpkCache cache {repository, optionsIn(dir, 1)};
    StopToken stop;

    EXPECT_EQ(cache.ensure(requestFor(SHA1_A), stop), UpgradeError::WpkFileDoesNotExist);
    EXPECT_FALSE(dir.exists(WPK_FILE));
    // The staging file is cleaned up too, so a later attempt cannot mistake it for a whole download.
    EXPECT_FALSE(dir.exists(std::string {".staging/"} + SHA1_A + ".part"));
}

TEST(UpgradeWpkCache, RetriesATransientFailureAndThenSucceeds)
{
    const TempDir dir;
    FakeWpkRepository repository;
    repository.scriptDownload(WPK_URL, {true, CONTENT_A, 200, 2, {}, false}); // Fails twice first.

    WpkCache cache {repository, optionsIn(dir, 3)};
    StopToken stop;

    EXPECT_EQ(cache.ensure(requestFor(SHA1_A), stop), UpgradeError::Success);
    EXPECT_EQ(repository.downloadCalls(WPK_URL), 3U);
}

TEST(UpgradeWpkCache, GivesUpAfterTheAttemptBudget)
{
    const TempDir dir;
    FakeWpkRepository repository;
    repository.scriptDownload(WPK_URL, {true, CONTENT_A, 200, 99, {}, false});

    WpkCache cache {repository, optionsIn(dir, 3)};
    StopToken stop;

    EXPECT_EQ(cache.ensure(requestFor(SHA1_A), stop), UpgradeError::WpkFileDoesNotExist);
    EXPECT_EQ(repository.downloadCalls(WPK_URL), 3U);
}

TEST(UpgradeWpkCache, AFailedDownloadIsNotRememberedAsAnAnswer)
{
    // Memoising a failure would keep a fleet-wide upgrade broken long after the repository came
    // back; the cost of being wrong is one HTTP request.
    const TempDir dir;
    FakeWpkRepository repository;
    repository.scriptDownload(WPK_URL, {true, CONTENT_A, 200, 1, {}, false});

    WpkCache cache {repository, optionsIn(dir, 1)}; // One attempt, so the first call fails.
    StopToken stop;

    EXPECT_EQ(cache.ensure(requestFor(SHA1_A), stop), UpgradeError::WpkFileDoesNotExist);
    EXPECT_EQ(cache.ensure(requestFor(SHA1_A), stop), UpgradeError::Success);
    EXPECT_EQ(repository.downloadCalls(WPK_URL), 2U);
}

TEST(UpgradeWpkCache, AStopRequestEndsTheDownloadAsRetryableWithoutBurningTheBudget)
{
    const TempDir dir;
    FakeWpkRepository repository;
    repository.scriptDownload(WPK_URL, {true, CONTENT_A, 200, 0, {}, false});

    WpkCache cache {repository, optionsIn(dir, 3)};
    StopToken stop;
    stop.requestStop();

    // RETRYABLE, not "the WPK file does not exist". Error 4 is the one code the Server API answers
    // by halving the chunk and trying again, which is the right response to a manager that is going
    // down -- and it has to be the SAME answer wherever the shutdown caught the request, whether
    // that was in the pool's queue, part-way through resolving agents, or here. Reporting a missing
    // file instead told the caller something untrue about the repository and lost the retry.
    EXPECT_EQ(cache.ensure(requestFor(SHA1_A), stop), UpgradeError::TaskManagerCommunication);
    EXPECT_EQ(repository.downloadCalls(WPK_URL), 0U);
    EXPECT_FALSE(dir.exists(WPK_FILE));
}

TEST(UpgradeWpkCache, CapsHowManyDownloadsRunAtOnce)
{
    // WPKs are 50-100 MB. Several concurrent batches on different platforms have different paths and
    // would otherwise all download at once, saturating the link and var/upgrade/.
    const TempDir dir;
    FakeWpkRepository repository;

    constexpr int DISTINCT_FILES {8};
    for (int index = 0; index < DISTINCT_FILES; ++index)
    {
        repository.scriptDownload("https://repo/" + std::to_string(index) + ".wpk",
                                  {true, CONTENT_A, 200, 0, std::chrono::milliseconds {30}, false});
    }

    WpkCache cache {repository, optionsIn(dir, 1, 2)};
    StopToken stop;

    std::vector<std::thread> threads;
    threads.reserve(DISTINCT_FILES);
    for (int index = 0; index < DISTINCT_FILES; ++index)
    {
        threads.emplace_back(
            [&, index]
            {
                cache.ensure({"https://repo/" + std::to_string(index) + ".wpk", std::to_string(index) + ".wpk", SHA1_A},
                             stop);
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(repository.totalDownloadCalls(), static_cast<std::size_t>(DISTINCT_FILES));
    EXPECT_LE(repository.peakConcurrentDownloads(), 2);
}

TEST(UpgradeWpkCache, VerifiesALocalFileWithoutDownloadingAnything)
{
    // The custom-WPK path: the operator put the file there, so there is nothing to fetch and the
    // digest is computed rather than compared.
    const TempDir dir;
    dir.writeFile("custom.wpk", CONTENT_B);

    FakeWpkRepository repository;
    WpkCache cache {repository, optionsIn(dir)};

    std::string sha1;
    EXPECT_EQ(cache.verifyLocal("custom.wpk", sha1), UpgradeError::Success);
    EXPECT_EQ(sha1, SHA1_B);
    EXPECT_EQ(repository.totalDownloadCalls(), 0U);

    EXPECT_EQ(cache.verifyLocal("absent.wpk", sha1), UpgradeError::WpkFileDoesNotExist);
}

// ---- the versions cache --------------------------------------------------------------------------

namespace
{
    constexpr const char* VERSIONS_URL {"https://packages.wazuh.com/5.x/wpk/linux/deb/amd64/versions"};
    constexpr const char* VERSIONS_BODY {"v4.14.0 aaaa1111\nv5.0.0 bbbb2222\n"};
} // namespace

TEST(UpgradeVersionsCache, ParsesAndCachesTheEntries)
{
    FakeWpkRepository repository;
    repository.scriptVersions(VERSIONS_URL, {true, VERSIONS_BODY, 200, 0});

    VersionsCache cache {repository, std::chrono::seconds {60}};

    const auto first {cache.get(VERSIONS_URL)};
    EXPECT_EQ(first.error, UpgradeError::Success);
    ASSERT_EQ(first.entries.size(), 2U);

    EXPECT_EQ(cache.get(VERSIONS_URL).error, UpgradeError::Success);
    EXPECT_EQ(repository.versionsCalls(VERSIONS_URL), 1U);
    EXPECT_EQ(cache.hitCount(), 1U);
}

TEST(UpgradeVersionsCache, AColdBatchMakesOneRequestNotFiveHundred)
{
    // The single biggest waste in the retired implementation: it fetched this file inside the
    // per-agent loop, so a 500-agent batch made 500 identical HTTPS requests -- each a fresh handle
    // and a fresh TLS handshake -- for the same few hundred bytes.
    //
    // A TTL alone would not help here. None of these callers has populated the entry yet, which is
    // why the per-URL lock exists as well.
    FakeWpkRepository repository;
    repository.scriptVersions(VERSIONS_URL, {true, VERSIONS_BODY, 200, 0});

    VersionsCache cache {repository, std::chrono::seconds {60}};

    constexpr int CALLERS {32};
    std::atomic<int> failures {0};
    std::vector<std::thread> threads;
    threads.reserve(CALLERS);

    for (int index = 0; index < CALLERS; ++index)
    {
        threads.emplace_back(
            [&]
            {
                if (cache.get(VERSIONS_URL).error != UpgradeError::Success)
                {
                    ++failures;
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(failures.load(), 0);
    EXPECT_EQ(repository.versionsCalls(VERSIONS_URL), 1U);
}

TEST(UpgradeVersionsCache, RefetchesOnceTheTtlHasPassed)
{
    // So a repository that publishes a new release is picked up without restarting modulesd.
    FakeWpkRepository repository;
    repository.scriptVersions(VERSIONS_URL, {true, VERSIONS_BODY, 200, 0});

    VersionsCache cache {repository, std::chrono::seconds {0}};

    EXPECT_EQ(cache.get(VERSIONS_URL).error, UpgradeError::Success);
    EXPECT_EQ(cache.get(VERSIONS_URL).error, UpgradeError::Success);
    EXPECT_EQ(repository.versionsCalls(VERSIONS_URL), 2U);
}

TEST(UpgradeVersionsCache, DoesNotCacheAFailure)
{
    FakeWpkRepository repository;
    repository.scriptVersions(VERSIONS_URL, {true, VERSIONS_BODY, 200, 1}); // First call fails.

    VersionsCache cache {repository, std::chrono::seconds {60}};

    EXPECT_EQ(cache.get(VERSIONS_URL).error, UpgradeError::UrlNotFound);
    EXPECT_EQ(cache.get(VERSIONS_URL).error, UpgradeError::Success);
    EXPECT_EQ(repository.versionsCalls(VERSIONS_URL), 2U);
}

TEST(UpgradeVersionsCache, AnUnusableBodyIsAsGoodAsUnreachable)
{
    // A 2xx carrying nothing parseable. Caching it as a successful empty list would fail every agent
    // for the whole TTL while reporting "this version does not exist" rather than "check the URL".
    FakeWpkRepository repository;
    repository.scriptVersions(VERSIONS_URL, {true, "<html>404 not found</html>", 200, 0});

    VersionsCache cache {repository, std::chrono::seconds {60}};

    EXPECT_EQ(cache.get(VERSIONS_URL).error, UpgradeError::UrlNotFound);
    EXPECT_EQ(cache.get(VERSIONS_URL).error, UpgradeError::UrlNotFound);
    EXPECT_EQ(repository.versionsCalls(VERSIONS_URL), 2U);
}

TEST(UpgradeVersionsCache, KeepsDistinctUrlsApart)
{
    // A mixed fleet resolves several repository paths, and each needs its own entry -- one shared
    // entry would serve deb digests to rpm agents.
    constexpr const char* OTHER_URL {"https://packages.wazuh.com/5.x/wpk/linux/rpm/x86_64/versions"};

    FakeWpkRepository repository;
    repository.scriptVersions(VERSIONS_URL, {true, VERSIONS_BODY, 200, 0});
    repository.scriptVersions(OTHER_URL, {true, "v5.0.0 cccc3333\n", 200, 0});

    VersionsCache cache {repository, std::chrono::seconds {60}};

    EXPECT_EQ(cache.get(VERSIONS_URL).entries.size(), 2U);
    ASSERT_EQ(cache.get(OTHER_URL).entries.size(), 1U);
    EXPECT_EQ(cache.get(OTHER_URL).entries[0].sha1, "cccc3333");
    EXPECT_EQ(repository.totalVersionsCalls(), 2U);
}
