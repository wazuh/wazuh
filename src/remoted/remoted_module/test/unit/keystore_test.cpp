/*
 * Wazuh auth middleware (framework-agnostic) - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 20, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <cstdio>
#include <fstream>
#include <unistd.h>

#include <gtest/gtest.h>

#include "auth/keystore.hpp"

using namespace remoted::auth;

namespace
{

    class KeystoreTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            const auto* testInfo = ::testing::UnitTest::GetInstance()->current_test_info();
            m_path = "/tmp/" + std::string(testInfo->test_suite_name()) + "_" + testInfo->name() + "_" +
                     std::to_string(getpid()) + ".keys";
        }

        void TearDown() override
        {
            std::remove(m_path.c_str());
        }

        void writeFile(const std::string& contents)
        {
            std::ofstream file(m_path);
            file << contents;
        }

        std::string m_path;
    };

    TEST_F(KeystoreTest, LoadsAValidEntry)
    {
        writeFile("3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        const auto key = keystore.keyFor(3824);
        ASSERT_TRUE(key.has_value());
        EXPECT_EQ(key->size(), 32u);
    }

    TEST_F(KeystoreTest, UnknownAgentIsNullopt)
    {
        writeFile("3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_FALSE(keystore.keyFor(9999).has_value());
    }

    TEST_F(KeystoreTest, NonNumericIdLineIsSkipped)
    {
        writeFile("abc debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_EQ(keystore.reload(), 0);
    }

    TEST_F(KeystoreTest, NonNumericIdLineDoesNotBlockOtherEntries)
    {
        writeFile("abc debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n"
                  "3824 debian11 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_EQ(keystore.reload(), 1);
        EXPECT_TRUE(keystore.keyFor(3824).has_value());
    }

    TEST_F(KeystoreTest, CommentAndBlankLinesAreSkipped)
    {
        writeFile("# a comment\n"
                  " # another, indented\n"
                  "3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_TRUE(keystore.keyFor(3824).has_value());
    }

    TEST_F(KeystoreTest, RemovedEntryIsSkipped)
    {
        writeFile("3824 !debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_FALSE(keystore.keyFor(3824).has_value());
    }

    TEST_F(KeystoreTest, MalformedLineIsSkipped)
    {
        writeFile("3824 debian10 any\n"); // missing key column
        Keystore keystore(m_path);

        EXPECT_FALSE(keystore.keyFor(3824).has_value());
    }

    TEST_F(KeystoreTest, NonHexKeyResolvesToAnEmptyKey)
    {
        writeFile("3824 debian10 any not-hex-at-all\n");
        Keystore keystore(m_path);

        const auto key = keystore.keyFor(3824);
        ASSERT_TRUE(key.has_value());
        EXPECT_TRUE(key->empty());
    }

    TEST_F(KeystoreTest, MissingFileLeavesKeystoreEmpty)
    {
        Keystore keystore(m_path + "-does-not-exist");
        EXPECT_FALSE(keystore.keyFor(3824).has_value());
    }

    TEST_F(KeystoreTest, ReloadPicksUpChanges)
    {
        writeFile("3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);
        ASSERT_TRUE(keystore.keyFor(3824).has_value());

        writeFile("3824 !debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        EXPECT_EQ(keystore.reload(), 0);
        EXPECT_FALSE(keystore.keyFor(3824).has_value());
    }

} // namespace
