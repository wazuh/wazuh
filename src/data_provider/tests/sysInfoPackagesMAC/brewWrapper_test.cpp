/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * October 9, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "gtest/gtest.h"
#include "packages/packageMac.h"
#include "packages/brewWrapper.h"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <sys/stat.h>

class BrewWrapperTest : public ::testing::Test
{
    protected:
        std::filesystem::path m_dir;
        std::filesystem::path m_versionDir;

        void SetUp() override
        {
            const auto suffix {std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())};
            m_dir = std::filesystem::temp_directory_path() / ("brew_wrapper_test_" + suffix);
            m_versionDir = m_dir / "pkg" / "1.0";
            std::filesystem::create_directories(m_versionDir / ".brew");
        }

        void TearDown() override
        {
            std::error_code ec;
            std::filesystem::remove_all(m_dir, ec);
        }

        BrewWrapper wrapper() const
        {
            return BrewWrapper(PackageContext {m_dir.string(), "pkg", "1.0"});
        }

        static void writeFile(const std::filesystem::path& path, const std::string& content)
        {
            std::ofstream file {path};
            file << content;
        }
};

TEST_F(BrewWrapperTest, ReceiptIsParsed)
{
    writeFile(m_versionDir / "INSTALL_RECEIPT.json",
              R"({"arch":"arm64","time":1700000000,"source":{"tap":"homebrew/core","version":"1.0.1"}})");

    const auto brew {wrapper()};

    EXPECT_EQ(brew.architecture(), "arm64");
    EXPECT_EQ(brew.install_time(), "1700000000");
    EXPECT_EQ(brew.vendor(), "homebrew/core");
    EXPECT_EQ(brew.version(), "1.0.1");
}

TEST_F(BrewWrapperTest, ReceiptSymlinkToRegularFileIsRead)
{
    writeFile(m_dir / "receipt.json", R"({"arch":"x86_64"})");
    std::filesystem::create_symlink(m_dir / "receipt.json", m_versionDir / "INSTALL_RECEIPT.json");

    EXPECT_EQ(wrapper().architecture(), "x86_64");
}

TEST_F(BrewWrapperTest, LargeSparseReceiptIsNotBuffered)
{
    const auto path {m_versionDir / "INSTALL_RECEIPT.json"};
    std::ofstream {path};
    std::filesystem::resize_file(path, 1024ULL * 1024 * 1024);

    const auto brew {wrapper()};

    EXPECT_EQ(brew.name(), "pkg");
    EXPECT_EQ(brew.version(), "1.0");
    EXPECT_EQ(brew.architecture(), UNKNOWN_VALUE);
}

TEST_F(BrewWrapperTest, NamedPipeReceiptIsSkipped)
{
    ASSERT_EQ(::mkfifo((m_versionDir / "INSTALL_RECEIPT.json").c_str(), 0600), 0);

    const auto brew {wrapper()};

    EXPECT_EQ(brew.version(), "1.0");
    EXPECT_EQ(brew.architecture(), UNKNOWN_VALUE);
}

TEST_F(BrewWrapperTest, ReceiptSymlinkToCharacterDeviceIsSkipped)
{
    std::filesystem::create_symlink("/dev/zero", m_versionDir / "INSTALL_RECEIPT.json");

    const auto brew {wrapper()};

    EXPECT_EQ(brew.version(), "1.0");
    EXPECT_EQ(brew.architecture(), UNKNOWN_VALUE);
}

TEST_F(BrewWrapperTest, LegacyFormulaDescriptionIsRead)
{
    writeFile(m_versionDir / ".brew" / "pkg.rb", "class Pkg < Formula\n  desc \"A test package\"\nend\n");

    EXPECT_EQ(wrapper().description(), "A test package");
}

TEST_F(BrewWrapperTest, LargeSparseLegacyFormulaIsNotBuffered)
{
    const auto path {m_versionDir / ".brew" / "pkg.rb"};
    std::ofstream {path};
    std::filesystem::resize_file(path, 1024ULL * 1024 * 1024);

    EXPECT_EQ(wrapper().description(), UNKNOWN_VALUE);
}
