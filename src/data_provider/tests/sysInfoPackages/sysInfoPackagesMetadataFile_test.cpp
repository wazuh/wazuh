/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * October 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "gtest/gtest.h"
#include "packageMetadataFile.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>

#ifndef _WIN32
#include <sys/stat.h>
#endif

class PackageMetadataFileTest : public ::testing::Test
{
    protected:
        std::filesystem::path m_dir;

        void SetUp() override
        {
            const auto suffix {std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())};
            m_dir = std::filesystem::temp_directory_path() / ("package_metadata_file_test_" + suffix);
            std::filesystem::create_directory(m_dir);
        }

        void TearDown() override
        {
            std::error_code ec;
            std::filesystem::remove_all(m_dir, ec);
        }
};

TEST_F(PackageMetadataFileTest, RegularFileIsRead)
{
    const auto path {m_dir / "METADATA"};
    std::ofstream(path) << "Name: test\nVersion: 1.0\n";

    std::string content;
    EXPECT_TRUE(PackageMetadataFile::read(path, content));
    EXPECT_EQ(content, "Name: test\nVersion: 1.0\n");
}

TEST_F(PackageMetadataFileTest, LinesAreReported)
{
    const auto path {m_dir / "METADATA"};
    std::ofstream(path) << "Name: test\nVersion: 1.0\n";

    std::vector<std::string> lines;
    PackageMetadataFileIO::readLineByLine(path, [&](const std::string & line)
    {
        lines.push_back(line);
        return true;
    });

    EXPECT_EQ(lines, (std::vector<std::string> {"Name: test", "Version: 1.0"}));
}

TEST_F(PackageMetadataFileTest, JsonIsParsed)
{
    const auto path {m_dir / "package.json"};
    std::ofstream(path) << R"({"name": "test", "version": "1.0.0"})";

    const auto json = PackageMetadataJsonReader::readJson(path);
    EXPECT_EQ(json.at("name"), "test");
    EXPECT_EQ(json.at("version"), "1.0.0");
}

TEST_F(PackageMetadataFileTest, JsonWithTrailingDataIsParsed)
{
    const auto path {m_dir / "package.json"};
    std::ofstream(path) << "{\"name\": \"test\", \"version\": \"1.0.0\"}\ntrailing";

    const auto json = PackageMetadataJsonReader::readJson(path);
    EXPECT_EQ(json.at("name"), "test");
    EXPECT_EQ(json.at("version"), "1.0.0");
}

TEST_F(PackageMetadataFileTest, MissingFileIsSkipped)
{
    std::string content;
    EXPECT_FALSE(PackageMetadataFile::read(m_dir / "METADATA", content));
    EXPECT_TRUE(PackageMetadataJsonReader::readJson(m_dir / "package.json").is_null());
}

TEST_F(PackageMetadataFileTest, EmptyFileIsSkipped)
{
    const auto path {m_dir / "METADATA"};
    std::ofstream {path};

    std::string content;
    EXPECT_FALSE(PackageMetadataFile::read(path, content));
}

TEST_F(PackageMetadataFileTest, DirectoryIsSkipped)
{
    const auto path {m_dir / "METADATA"};
    std::filesystem::create_directory(path);

    std::string content;
    EXPECT_FALSE(PackageMetadataFile::read(path, content));
}

TEST_F(PackageMetadataFileTest, OversizedFileIsSkipped)
{
    const auto path {m_dir / "METADATA"};
    std::ofstream {path};
    std::filesystem::resize_file(path, PACKAGE_METADATA_MAX_FILE_SIZE + 1);

    std::string content;
    EXPECT_FALSE(PackageMetadataFile::read(path, content));
}

TEST_F(PackageMetadataFileTest, FileAtSizeLimitIsRead)
{
    const auto path {m_dir / "METADATA"};
    std::ofstream {path};
    std::filesystem::resize_file(path, PACKAGE_METADATA_MAX_FILE_SIZE);

    std::string content;
    EXPECT_TRUE(PackageMetadataFile::read(path, content));
    EXPECT_EQ(content.size(), PACKAGE_METADATA_MAX_FILE_SIZE);
}

TEST_F(PackageMetadataFileTest, SymlinkToRegularFileIsRead)
{
#ifdef _WIN32
    GTEST_SKIP() << "Creating symbolic links needs extra privileges on Windows";
#else
    const auto target {m_dir / "target"};
    std::ofstream(target) << "Name: test\nVersion: 1.0\n";
    const auto path {m_dir / "METADATA"};
    std::filesystem::create_symlink(target, path);

    std::string content;
    EXPECT_TRUE(PackageMetadataFile::read(path, content));
    EXPECT_EQ(content, "Name: test\nVersion: 1.0\n");
#endif
}

TEST_F(PackageMetadataFileTest, SymlinkToEmptyFileIsSkipped)
{
#ifdef _WIN32
    GTEST_SKIP() << "Creating symbolic links needs extra privileges on Windows";
#else
    const auto target {m_dir / "target"};
    std::ofstream {target};
    const auto path {m_dir / "METADATA"};
    std::filesystem::create_symlink(target, path);

    std::string content;
    EXPECT_FALSE(PackageMetadataFile::read(path, content));
#endif
}

TEST_F(PackageMetadataFileTest, SymlinkToNamedPipeIsSkipped)
{
#ifdef _WIN32
    GTEST_SKIP() << "Named pipes are not created in the filesystem on Windows";
#else
    const auto target {m_dir / "target"};
    ASSERT_EQ(::mkfifo(target.c_str(), 0600), 0);
    const auto path {m_dir / "METADATA"};
    std::filesystem::create_symlink(target, path);

    std::string content;
    EXPECT_FALSE(PackageMetadataFile::read(path, content));
#endif
}

TEST_F(PackageMetadataFileTest, SymlinkToCharacterDeviceIsSkipped)
{
#ifdef _WIN32
    GTEST_SKIP() << "Character devices are not exposed in the filesystem on Windows";
#else

    if (!std::filesystem::is_character_file("/dev/zero"))
    {
        GTEST_SKIP() << "/dev/zero is not available";
    }

    const auto path {m_dir / "METADATA"};
    std::filesystem::create_symlink("/dev/zero", path);

    std::string content;
    EXPECT_FALSE(PackageMetadataFile::read(path, content));
#endif
}

TEST_F(PackageMetadataFileTest, NamedPipeIsSkipped)
{
#ifdef _WIN32
    GTEST_SKIP() << "Named pipes are not created in the filesystem on Windows";
#else
    const auto path {m_dir / "METADATA"};
    ASSERT_EQ(::mkfifo(path.c_str(), 0600), 0);

    std::string content;
    EXPECT_FALSE(PackageMetadataFile::read(path, content));
#endif
}
