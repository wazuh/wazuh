/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Sep 8, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "hashHelper_test.h"
#include "hashHelper.h"
#include <filesystem>

void HashHelperTest::SetUp() {};

void HashHelperTest::TearDown() {};

using ::testing::_;
using ::testing::Return;
using namespace Utils;

// Path where the test files reside.
const std::filesystem::path INPUT_FILES_DIR {std::filesystem::current_path() / "input_files" / "hashHelper"};

// Test file used for hashing.
const std::filesystem::path TEST_FILE {INPUT_FILES_DIR / "data.json"};
const std::string TEST_FILE_HASH {"9c8ff5a046322fd04e244ce92e991118f26403f1"};

TEST_F(HashHelperTest, UnsupportedHashType)
{
    EXPECT_THROW(HashData hash{static_cast<HashType>(15)}, std::runtime_error);
}

TEST_F(HashHelperTest, HashHelperHashBufferSha1)
{
    const unsigned char expected[] {0x2d, 0x53, 0x3b, 0x9d, 0x9f, 0x0f, 0x06, 0xef, 0x4e, 0x3c, 0x23, 0xfd, 0x49, 0x6c, 0xfe, 0xb2, 0x78, 0x0e, 0xda, 0x7f};
    const std::string data{"HASH"};
    HashData hash;
    hash.update(data.c_str(), data.size());
    const auto result{ hash.hash() };
    EXPECT_EQ(sizeof(expected), result.size());
    EXPECT_TRUE(!memcmp(expected, result.data(), result.size()));
}

TEST_F(HashHelperTest, HashHelperHashIterativeSha1)
{
    const unsigned char expected[] {0x2d, 0x53, 0x3b, 0x9d, 0x9f, 0x0f, 0x06, 0xef, 0x4e, 0x3c, 0x23, 0xfd, 0x49, 0x6c, 0xfe, 0xb2, 0x78, 0x0e, 0xda, 0x7f};
    const std::string data{"HASH"};
    HashData hash;

    for (const auto& value : data)
    {
        hash.update(&value, sizeof(value));
    }

    const auto result{ hash.hash() };
    EXPECT_EQ(sizeof(expected), result.size());
    EXPECT_TRUE(!memcmp(expected, result.data(), result.size()));
}

TEST_F(HashHelperTest, HashHelperHashBufferSha256)
{
    const unsigned char expected[] {0xc1, 0xfb, 0x44, 0xc7, 0x26, 0x28, 0xea, 0xe4, 0x91, 0x32, 0x06, 0x2f, 0xe5, 0x10, 0x9f, 0x65,
                                    0x0b, 0x6a, 0x7a, 0xb9, 0x03, 0x33, 0x6e, 0x7f, 0xcd, 0x2e, 0xf8, 0xf5, 0xeb, 0xa0, 0x41, 0x51
                                   };
    const std::string data{"HASH"};
    HashData hash{HashType::Sha256};
    hash.update(data.c_str(), data.size());
    const auto result{ hash.hash() };
    EXPECT_EQ(sizeof(expected), result.size());
    EXPECT_TRUE(!memcmp(expected, result.data(), result.size()));
}

TEST_F(HashHelperTest, HashHelperHashIterativeSha256)
{
    const unsigned char expected[] {0xc1, 0xfb, 0x44, 0xc7, 0x26, 0x28, 0xea, 0xe4, 0x91, 0x32, 0x06, 0x2f, 0xe5, 0x10, 0x9f, 0x65,
                                    0x0b, 0x6a, 0x7a, 0xb9, 0x03, 0x33, 0x6e, 0x7f, 0xcd, 0x2e, 0xf8, 0xf5, 0xeb, 0xa0, 0x41, 0x51
                                   };
    const std::string data{"HASH"};
    HashData hash{HashType::Sha256};

    for (const auto& value : data)
    {
        hash.update(&value, sizeof(value));
    }

    const auto result{ hash.hash() };
    EXPECT_EQ(sizeof(expected), result.size());
    EXPECT_TRUE(!memcmp(expected, result.data(), result.size()));
}

/**
 * @brief Test the hashing of a file.
 *
 */
TEST_F(HashHelperTest, HashFile)
{
    // SHA1SUM as string: 9c8ff5a046322fd04e244ce92e991118f26403f1
    const std::vector<unsigned char> expectedHash {156, 143, 245, 160, 70, 50, 47,  208, 78, 36,
                                                   76,  233, 46,  153, 17, 24, 242, 100, 3,  241};

    EXPECT_EQ(Utils::hashFile(TEST_FILE), expectedHash);
}

/**
 * @brief Test the hashing of an inexistant file.
 *
 */
TEST_F(HashHelperTest, HashFileInexistantFile)
{
    EXPECT_THROW(Utils::hashFile(INPUT_FILES_DIR / "inexistant_file.xml"), std::runtime_error);
}
