/*
 * Wazuh shared modules utils
 * Copyright (C) 2015-2021, Wazuh Inc.
 * Sep 8, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "hashHelper_test.h"
#include "hashHelper.h"


void HashHelperTest::SetUp() {};

void HashHelperTest::TearDown() {};

using ::testing::_;
using ::testing::Return;
using namespace Utils;

TEST_F(HashHelperTest, UnsupportedHashType)
{
    EXPECT_THROW(HashData hash{static_cast<HashType>(15)}, std::runtime_error);
}

TEST_F(HashHelperTest, HashHelperHashBufferSha1)
{
    const unsigned char expected[]{0x2d, 0x53, 0x3b, 0x9d, 0x9f, 0x0f, 0x06, 0xef, 0x4e, 0x3c, 0x23, 0xfd, 0x49, 0x6c, 0xfe, 0xb2, 0x78, 0x0e, 0xda, 0x7f};
    const std::string data{"HASH"};
    HashData hash;
    hash.update(data.c_str(), data.size());
    const auto result{ hash.hash() };
    EXPECT_EQ(sizeof(expected), result.size());
    EXPECT_TRUE(!memcmp(expected, result.data(), result.size()));
}

TEST_F(HashHelperTest, HashHelperHashIterativeSha1)
{
    const unsigned char expected[]{0x2d, 0x53, 0x3b, 0x9d, 0x9f, 0x0f, 0x06, 0xef, 0x4e, 0x3c, 0x23, 0xfd, 0x49, 0x6c, 0xfe, 0xb2, 0x78, 0x0e, 0xda, 0x7f};
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
    const unsigned char expected[]{0xc1, 0xfb, 0x44, 0xc7, 0x26, 0x28, 0xea, 0xe4, 0x91, 0x32, 0x06, 0x2f, 0xe5, 0x10, 0x9f, 0x65,
                                   0x0b, 0x6a, 0x7a, 0xb9, 0x03, 0x33, 0x6e, 0x7f, 0xcd, 0x2e, 0xf8, 0xf5, 0xeb, 0xa0, 0x41, 0x51};
    const std::string data{"HASH"};
    HashData hash{HashType::Sha256};
    hash.update(data.c_str(), data.size());
    const auto result{ hash.hash() };
    EXPECT_EQ(sizeof(expected), result.size());
    EXPECT_TRUE(!memcmp(expected, result.data(), result.size()));
}

TEST_F(HashHelperTest, HashHelperHashIterativeSha256)
{
    const unsigned char expected[]{0xc1, 0xfb, 0x44, 0xc7, 0x26, 0x28, 0xea, 0xe4, 0x91, 0x32, 0x06, 0x2f, 0xe5, 0x10, 0x9f, 0x65,
                                   0x0b, 0x6a, 0x7a, 0xb9, 0x03, 0x33, 0x6e, 0x7f, 0xcd, 0x2e, 0xf8, 0xf5, 0xeb, 0xa0, 0x41, 0x51};
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
