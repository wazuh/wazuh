/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "contentCodingGuard.hpp"

#include <gtest/gtest.h>

TEST(ContentCodingGuardTest, AdmitsTheOfferedCodingAsCurlHandsItOver)
{
    ContentCodingGuard guard {"zstd"};

    EXPECT_TRUE(guard.admit(" zstd\r\n"));
    EXPECT_TRUE(guard.refused().empty());
}

TEST(ContentCodingGuardTest, ComparesCodingsCaseInsensitively)
{
    ContentCodingGuard guard {"zstd"};

    EXPECT_TRUE(guard.admit("ZStd"));
}

TEST(ContentCodingGuardTest, AdmitsIdentityAlongsideTheOfferedCoding)
{
    ContentCodingGuard guard {"zstd"};

    EXPECT_TRUE(guard.admit("identity"));
    EXPECT_TRUE(guard.admit("identity, zstd"));
}

TEST(ContentCodingGuardTest, RefusesACodingThatWasNotOffered)
{
    ContentCodingGuard guard {"zstd"};

    EXPECT_FALSE(guard.admit(" gzip\r\n"));
    EXPECT_EQ("gzip", guard.refused());
}

// curl would stack one zstd decoder, with its own window, per listed coding.
TEST(ContentCodingGuardTest, RefusesTheSameCodingListedTwice)
{
    ContentCodingGuard guard {"zstd"};

    EXPECT_FALSE(guard.admit("zstd, zstd"));
    EXPECT_EQ("zstd, zstd", guard.refused());
}

TEST(ContentCodingGuardTest, CountsCodingsAcrossHeaderLines)
{
    ContentCodingGuard guard {"zstd"};

    EXPECT_TRUE(guard.admit("zstd"));
    EXPECT_FALSE(guard.admit("zstd"));
}

TEST(ContentCodingGuardTest, AdmitsAnyOneCodingOfAnOfferedList)
{
    ContentCodingGuard guard {"gzip, zstd"};

    EXPECT_TRUE(guard.admit("zstd"));
}

TEST(ContentCodingGuardTest, EmptyListsNameNoCoding)
{
    ContentCodingGuard guard {"zstd"};

    EXPECT_TRUE(guard.admit(" ,, "));
    EXPECT_TRUE(guard.admit("zstd"));
}
