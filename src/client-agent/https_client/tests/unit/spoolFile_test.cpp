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
