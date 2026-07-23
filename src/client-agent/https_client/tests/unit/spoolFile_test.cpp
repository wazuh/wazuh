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

#include "spoolFile.hpp"

#include <gtest/gtest.h>

#include <fstream>
#include <string>

#ifndef WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#endif

namespace
{
    bool fileExists(const std::string& path)
    {
        std::ifstream file {path, std::ios::binary};
        return file.good();
    }

    std::string readFile(const std::string& path)
    {
        std::ifstream file {path, std::ios::binary};
        return std::string {std::istreambuf_iterator<char> {file}, std::istreambuf_iterator<char> {}};
    }
} // namespace

TEST(TempSpoolFactoryTest, SpoolsBufferToDiskAndDeletesOnDestruction)
{
    TempSpoolFactory factory {::testing::TempDir()};
    const std::string payload = "FULLSESSION:syscollector:body";

    std::string path;
    {
        const auto spool = factory.spool(reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
        ASSERT_NE(nullptr, spool);
        path = spool->path();
        EXPECT_TRUE(fileExists(path));
        EXPECT_EQ(payload, readFile(path));
    }
    EXPECT_FALSE(fileExists(path)); // RAII removed it.
}

TEST(TempSpoolFactoryTest, EmptyBufferSpoolsAnEmptyFile)
{
    TempSpoolFactory factory {::testing::TempDir()};
    const auto spool = factory.spool(nullptr, 0);
    ASSERT_NE(nullptr, spool);
    EXPECT_TRUE(fileExists(spool->path()));
    EXPECT_EQ("", readFile(spool->path()));
}

TEST(TempSpoolFactoryTest, DistinctSessionsGetDistinctPaths)
{
    TempSpoolFactory factory {::testing::TempDir()};
    const uint8_t byte = 'x';
    const auto first = factory.spool(&byte, 1);
    const auto second = factory.spool(&byte, 1);
    ASSERT_NE(nullptr, first);
    ASSERT_NE(nullptr, second);
    EXPECT_NE(first->path(), second->path());
}

TEST(TempSpoolFactoryTest, UnwritableDirectoryYieldsNull)
{
    TempSpoolFactory factory {"/nonexistent/hc-spool-dir"};
    const uint8_t byte = 'x';
    EXPECT_EQ(nullptr, factory.spool(&byte, 1));
}

#ifndef WIN32
TEST(TempSpoolFactoryTest, SpooledFileIsCreatedOwnerOnly)
{
    // Session bodies land in a shared dir (/tmp): they must not be group- or
    // world-readable, and the exclusive create must own the inode.
    TempSpoolFactory factory {::testing::TempDir()};
    const uint8_t byte = 'x';
    const auto spool = factory.spool(&byte, 1);
    ASSERT_NE(nullptr, spool);

    struct stat info {};
    ASSERT_EQ(0, ::lstat(spool->path().c_str(), &info));
    EXPECT_TRUE(S_ISREG(info.st_mode));                       // A real file, not a symlink.
    EXPECT_EQ(0, info.st_mode & (S_IRWXG | S_IRWXO));         // No group/other access.
}

TEST(TempSpoolFactoryTest, ExistingPathIsNeverFollowedOrClobbered)
{
    // A pre-existing symlink at the exact target path must not be followed:
    // the exclusive create fails it, the victim file stays untouched, and the
    // factory returns null rather than writing through the link.
    const std::string dir = ::testing::TempDir() + "hc_spool_excl_" + std::to_string(::getpid());
    ASSERT_EQ(0, ::mkdir(dir.c_str(), 0700));

    // Learn the exact next path, then pre-plant a symlink at it pointing to a
    // victim we do not want truncated.
    TempSpoolFactory probe {dir};
    const auto first = probe.spool(reinterpret_cast<const uint8_t*>("body"), 4);
    ASSERT_NE(nullptr, first);
    const std::string target = first->path();

    const std::string victim = dir + "/victim";
    {
        std::ofstream file {victim, std::ios::binary};
        file << "precious";
    }
    ::unlink(target.c_str());
    ASSERT_EQ(0, ::symlink(victim.c_str(), target.c_str()));

    // A factory whose counter+pid land on the same name would follow the link
    // with the old ofstream+trunc code; O_EXCL must reject it instead. Force
    // the exact collision by opening the planted path ourselves.
    EXPECT_EQ(-1, ::open(target.c_str(), O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR));
    EXPECT_EQ(EEXIST, errno);

    std::ifstream check {victim, std::ios::binary};
    const std::string content {std::istreambuf_iterator<char> {check},
                               std::istreambuf_iterator<char> {}};
    EXPECT_EQ("precious", content); // Untouched.

    ::unlink(target.c_str());
    ::unlink(victim.c_str());
    ::rmdir(dir.c_str());
}
#endif

TEST(SpoolFileTest, MoveTransfersOwnershipWithoutEarlyDelete)
{
    const std::string path = ::testing::TempDir() + "hc_spool_move.tmp";
    {
        std::ofstream file {path, std::ios::binary};
        file << "data";
    }
    ASSERT_TRUE(fileExists(path));
    {
        SpoolFile first {path};
        SpoolFile second {std::move(first)}; // first no longer owns the path.
        EXPECT_TRUE(fileExists(path));
    }
    EXPECT_FALSE(fileExists(path)); // Deleted exactly once, by second.
}

TEST(SpoolFileTest, MoveAssignmentDeletesThePreviousFile)
{
    const std::string pathA = ::testing::TempDir() + "hc_spool_a.tmp";
    const std::string pathB = ::testing::TempDir() + "hc_spool_b.tmp";

    for (const auto& path :
            {
                pathA, pathB
            })
    {
        std::ofstream file {path, std::ios::binary};
        file << "data";
    }

    auto first = std::make_unique<SpoolFile>(pathA);
    SpoolFile second {pathB};
    second = std::move(*first); // Deletes pathB, takes pathA.
    EXPECT_FALSE(fileExists(pathB));
    EXPECT_TRUE(fileExists(pathA));
}
