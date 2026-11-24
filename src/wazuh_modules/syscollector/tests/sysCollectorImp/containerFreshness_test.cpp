/*
 * Wazuh SysCollector
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "containerFreshness.hpp"

#include <gtest/gtest.h>

#include <set>

#include <unistd.h>

namespace
{
    const auto ADMIT_ALL = [](const std::string&)
    {
        return true;
    };

    /// Liveness by a set the test edits: a holder is alive while listed.
    struct Processes
    {
        std::set<std::pair<int, std::uint64_t>> running;

        LockHolders::IsAlive isAlive() const
        {
            return [this](int pid, std::uint64_t startTime)
            {
                return running.count({pid, startTime}) != 0;
            };
        }

        /// Starts a process and returns what /proc would say about it.
        std::uint64_t start(int pid, std::uint64_t startTime)
        {
            running.insert({pid, startTime});
            return startTime;
        }

        void exit(int pid, std::uint64_t startTime)
        {
            running.erase({pid, startTime});
        }
    };

    const std::string FILLERS = " 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21";
} // namespace

TEST(ContainerFreshnessLockPathTest, EveryPackageLockMatches)
{
    for (const auto& path : packageLockPaths())
    {
        EXPECT_TRUE(isPackageLockPath(path)) << path;
    }

    EXPECT_TRUE(isPackageLockPath("/usr/lib/apk/db/lock")) << "apk's lock on a merged /usr";
}

TEST(ContainerFreshnessLockPathTest, OtherFilesNamedLikeALockDoNot)
{
    EXPECT_FALSE(isPackageLockPath("/var/lib/dpkg/lock")) << "taken by each dpkg run apt starts";
    EXPECT_FALSE(isPackageLockPath("/var/lib/apt/lists/lock"));
    EXPECT_FALSE(isPackageLockPath("/var/cache/apt/archives/lock"));
    EXPECT_FALSE(isPackageLockPath("/var/lib/docker/overlay2/abc/diff/var/lib/dpkg/lock-frontend"));
    EXPECT_FALSE(isPackageLockPath("/var/lib/dpkg/status"));
    EXPECT_FALSE(isPackageLockPath("/var/lib/rpm/rpmdb.sqlite-wal"));
}

TEST(ContainerFreshnessLockPathTest, TheFilterNamesCoverEveryLock)
{
    const std::set<std::string> names {packageLockNames().begin(), packageLockNames().end()};

    for (const auto& path : packageLockPaths())
    {
        EXPECT_EQ(names.count(path.substr(path.rfind('/') + 1)), 1u) << path;
    }
}

TEST(ContainerFreshnessStartTimeTest, ReadsTheStartTimePastAnOddComm)
{
    // Fields 4..21 are fillers; field 22 is 98765.
    EXPECT_EQ(parseProcStartTime("42 (a) b (c)) S" + FILLERS + " 98765 0 0"), 98765u);
}

TEST(ContainerFreshnessStartTimeTest, AZombieOrAShortLineIsGone)
{
    EXPECT_FALSE(parseProcStartTime("42 (dpkg) Z" + FILLERS + " 98765 0 0"));
    EXPECT_FALSE(parseProcStartTime("42 (dpkg) X" + FILLERS + " 98765 0 0"));
    EXPECT_FALSE(parseProcStartTime("42 (dpkg) S 1 2"));
    EXPECT_FALSE(parseProcStartTime(""));
}

TEST(ContainerFreshnessStartTimeTest, ARunningProcessHasAStartTimeAndAMissingOneDoesNot)
{
#if defined(__linux__)
    const auto self = processStartTime(static_cast<int>(::getpid()));
    ASSERT_TRUE(self);
    EXPECT_EQ(processStartTime(static_cast<int>(::getpid())), self) << "stable while it runs";
    EXPECT_FALSE(processStartTime(-1));
#else
    GTEST_SKIP() << "/proc is Linux-only";
#endif
}

TEST(ContainerFreshnessStartTimeTest, AProcessStartedAfterTheEventReusedThePid)
{
    // 100 ticks per second: a tick is 10 ms.
    EXPECT_FALSE(startedAfter(100, 100, 1000000000ULL)) << "started at the event";
    EXPECT_FALSE(startedAfter(101, 100, 1000000000ULL)) << "within one tick";
    EXPECT_TRUE(startedAfter(150, 100, 1000000000ULL));
}

TEST(ContainerFreshnessLockHoldersTest, AHolderIsDueOnceWhenItExits)
{
    LockHolders holders;
    Processes processes;

    holders.note("a", 10, processes.start(10, 1));
    EXPECT_TRUE(holders.takeDue(processes.isAlive(), ADMIT_ALL).empty()) << "still running";
    EXPECT_TRUE(holders.hasHolders());

    processes.exit(10, 1);
    EXPECT_EQ(holders.takeDue(processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}));
    EXPECT_TRUE(holders.takeDue(processes.isAlive(), ADMIT_ALL).empty()) << "served once";
    EXPECT_FALSE(holders.hasHolders());
}

TEST(ContainerFreshnessLockHoldersTest, ChainedInstallsAreEachDueWhenTheyEnd)
{
    LockHolders holders;
    Processes processes;

    // The next install takes the lock before the first one's exit is seen.
    holders.note("a", 10, processes.start(10, 1));
    processes.exit(10, 1);
    holders.note("a", 20, processes.start(20, 2));
    EXPECT_EQ(holders.takeDue(processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}))
            << "the first install is reported while the second runs";

    processes.exit(20, 2);
    EXPECT_EQ(holders.takeDue(processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}));
}

TEST(ContainerFreshnessLockHoldersTest, AHolderThatNeverExitsHoldsBackNoOtherInstall)
{
    LockHolders holders;
    Processes processes;

    // A process that opened the lock and stays, then an install beside it.
    holders.note("a", 10, processes.start(10, 1));
    holders.note("a", 20, processes.start(20, 2));
    processes.exit(20, 2);
    EXPECT_EQ(holders.takeDue(processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}));
    EXPECT_TRUE(holders.hasHolders()) << "still checked while it runs";
}

TEST(ContainerFreshnessLockHoldersTest, AHolderAlreadyGoneIsDueAtOnce)
{
    LockHolders holders;
    Processes processes;

    holders.note("a", 10, std::nullopt);
    EXPECT_FALSE(holders.hasHolders());
    EXPECT_EQ(holders.takeDue(processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}));

    // Even beside a holder that never exits.
    holders.note("b", 20, processes.start(20, 1));
    holders.note("b", 21, std::nullopt);
    EXPECT_EQ(holders.takeDue(processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"b"}));
}

TEST(ContainerFreshnessLockHoldersTest, ARunningPidWithAnotherStartTimeHasExited)
{
    LockHolders holders;
    Processes processes;

    holders.note("a", 10, 1);
    processes.running = {{10, 7}};
    EXPECT_EQ(holders.takeDue(processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}));
}

TEST(ContainerFreshnessLockHoldersTest, OneProcessOpeningALockSeveralTimesIsOneHolder)
{
    LockHolders holders;
    Processes processes;

    // yum opens .rpm.lock more than once in one transaction.
    const auto startTime = processes.start(10, 1);
    holders.note("a", 10, startTime);
    holders.note("a", 10, startTime);
    holders.note("a", 10, startTime);

    processes.exit(10, 1);
    EXPECT_EQ(holders.takeDue(processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}));
    EXPECT_TRUE(holders.takeDue(processes.isAlive(), ADMIT_ALL).empty());
}

TEST(ContainerFreshnessLockHoldersTest, ContainersAreIndependent)
{
    LockHolders holders;
    Processes processes;

    holders.note("a", 10, processes.start(10, 1));
    holders.note("b", 20, processes.start(20, 1));

    processes.exit(10, 1);
    EXPECT_EQ(holders.takeDue(processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}));
}

TEST(ContainerFreshnessLockHoldersTest, ANonAdmittedContainerIsDroppedNotRefreshed)
{
    LockHolders holders;
    Processes processes;

    holders.note("a", 10, std::nullopt);
    const auto due = holders.takeDue(processes.isAlive(), [](const std::string & id)
    {
        return id != "a";
    });

    EXPECT_TRUE(due.empty());
    EXPECT_TRUE(holders.takeDue(processes.isAlive(), ADMIT_ALL).empty()) << "dropped, not kept";
}

TEST(ContainerFreshnessLockHoldersTest, AChangedContainerIsDueAtOnce)
{
    LockHolders holders;
    Processes processes;

    holders.markChanged("a");
    EXPECT_EQ(holders.takeDue(processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"a"}));
    EXPECT_TRUE(holders.takeDue(processes.isAlive(), ADMIT_ALL).empty()) << "once";

    // Even while a known holder still runs: its own exit is reported later.
    holders.note("b", 10, processes.start(10, 1));
    holders.markChanged("b");
    EXPECT_EQ(holders.takeDue(processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"b"}));
    EXPECT_TRUE(holders.takeDue(processes.isAlive(), ADMIT_ALL).empty());

    processes.exit(10, 1);
    EXPECT_EQ(holders.takeDue(processes.isAlive(), ADMIT_ALL), (std::vector<std::string> {"b"})) << "the holder's exit";
}

TEST(ContainerFreshnessLockHoldersTest, ClearForgetsEverything)
{
    LockHolders holders;
    Processes processes;

    holders.note("a", 10, processes.start(10, 1));
    holders.markChanged("b");
    holders.clear();

    EXPECT_FALSE(holders.hasHolders());
    EXPECT_TRUE(holders.takeDue(processes.isAlive(), ADMIT_ALL).empty());
}
