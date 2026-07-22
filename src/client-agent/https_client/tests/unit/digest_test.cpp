/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "digest.hpp"

#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <string>

TEST(DigestTest, Sha256OfEmptyInputMatchesThePinnedVector)
{
    EXPECT_EQ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
              sha256Hex("", 0));
}

TEST(DigestTest, Sha256OfAbcMatchesThePinnedVector)
{
    // FIPS 180-2 appendix B.1 test vector.
    EXPECT_EQ("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
              sha256Hex("abc", 3));
}

TEST(DigestTest, Sha256IsLowercaseHexOfExpectedLength)
{
    const std::string body = R"({"limits":{"eps":0}})";
    const auto hex = sha256Hex(body.data(), body.size());
    ASSERT_EQ(64u, hex.size());
    EXPECT_EQ(std::string::npos, hex.find_first_not_of("0123456789abcdef"));
}

TEST(DigestTest, Sha256FileHexMatchesTheBufferDigest)
{
    const std::string path = ::testing::TempDir() + "hc_digest_file.tmp";
    const std::string content = "merged-config-bytes";
    {
        std::ofstream file {path, std::ios::binary};
        file << content;
    }

    const auto fromFile = sha256FileHex(path);
    ASSERT_TRUE(fromFile.has_value());
    EXPECT_EQ(sha256Hex(content.data(), content.size()), *fromFile);
    std::remove(path.c_str());
}

TEST(DigestTest, Sha256FileHexOfAMissingFileIsNullopt)
{
    EXPECT_FALSE(sha256FileHex("/nonexistent/hc-digest/none.tmp").has_value());
}
