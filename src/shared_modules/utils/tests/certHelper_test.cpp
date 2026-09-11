/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * August 27, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "certHelper.hpp"
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

namespace
{
    class CertHelperTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            m_dir = std::filesystem::temp_directory_path() / "certHelper_test";
            std::filesystem::remove_all(m_dir);
            std::filesystem::create_directories(m_dir);
        }

        void TearDown() override
        {
            std::filesystem::remove_all(m_dir);
        }

        std::string writeCa(const std::string& name, const std::string& content) const
        {
            const auto path {m_dir / name};
            std::ofstream file(path);
            file << content;
            return path.string();
        }

        std::filesystem::path m_dir;
    };
} // namespace

TEST_F(CertHelperTest, MergesEveryCertificateAndOwnsItAsTheRunningAccount)
{
    const auto first {writeCa("first.pem", "FIRST\n")};
    const auto second {writeCa("second.pem", "SECOND\n")};
    const auto merged {(m_dir / "root-ca-merged.pem").string()};

    std::string result;
    ASSERT_NO_THROW(Utils::CertHelper::mergeCaRootCertificates({first, second}, result, merged));
    EXPECT_EQ(merged, result);

    std::ifstream file(merged);
    const std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    EXPECT_EQ("FIRST\nSECOND\n", content);

    // Owner resolved from the process: the 5.x manager package creates 'wazuh-manager' and removes
    // 'wazuh', so a hardcoded name is wrong on whichever side does not create it.
    struct stat info {};
    ASSERT_EQ(0, stat(merged.c_str(), &info));
    EXPECT_EQ(geteuid(), info.st_uid);
    EXPECT_EQ(getegid(), info.st_gid);
}

TEST_F(CertHelperTest, CreatesTheDestinationDirectory)
{
    const auto first {writeCa("first.pem", "FIRST\n")};
    const auto merged {(m_dir / "tmp" / "root-ca-merged.pem").string()};

    std::string result;
    ASSERT_NO_THROW(Utils::CertHelper::mergeCaRootCertificates({first}, result, merged));
    EXPECT_TRUE(std::filesystem::exists(merged));
}

TEST_F(CertHelperTest, ThrowsWhenACertificateIsMissing)
{
    const auto first {writeCa("first.pem", "FIRST\n")};
    const auto missing {(m_dir / "absent.pem").string()};
    const auto merged {(m_dir / "root-ca-merged.pem").string()};

    std::string result;
    EXPECT_THROW(Utils::CertHelper::mergeCaRootCertificates({first, missing}, result, merged), std::runtime_error);
    EXPECT_FALSE(std::filesystem::exists(merged));
}
