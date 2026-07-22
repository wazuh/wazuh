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

#include "auth/clientKeysFileResolver.hpp"

using namespace wazuh_auth;

namespace
{

    class ClientKeysFileResolverTest : public ::testing::Test
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

    TEST_F(ClientKeysFileResolverTest, LoadsAValidEntry)
    {
        writeFile("3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        ClientKeysFileResolver resolver(m_path);

        const auto key = resolver.resolve("3824");
        ASSERT_TRUE(key.has_value());
        EXPECT_EQ(key->size(), 32u);
    }

    TEST_F(ClientKeysFileResolverTest, UnknownAgentIsNullopt)
    {
        writeFile("3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        ClientKeysFileResolver resolver(m_path);

        EXPECT_FALSE(resolver.resolve("9999").has_value());
    }

    TEST_F(ClientKeysFileResolverTest, CommentAndBlankLinesAreSkipped)
    {
        writeFile("# a comment\n"
                  " # another, indented\n"
                  "3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        ClientKeysFileResolver resolver(m_path);

        EXPECT_TRUE(resolver.resolve("3824").has_value());
    }

    TEST_F(ClientKeysFileResolverTest, RemovedEntryIsSkipped)
    {
        writeFile("3824 !debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        ClientKeysFileResolver resolver(m_path);

        EXPECT_FALSE(resolver.resolve("3824").has_value());
    }

    TEST_F(ClientKeysFileResolverTest, MalformedLineIsSkipped)
    {
        writeFile("3824 debian10 any\n"); // missing key column
        ClientKeysFileResolver resolver(m_path);

        EXPECT_FALSE(resolver.resolve("3824").has_value());
    }

    TEST_F(ClientKeysFileResolverTest, NonHexKeyResolvesToAnEmptyKey)
    {
        writeFile("3824 debian10 any not-hex-at-all\n");
        ClientKeysFileResolver resolver(m_path);

        const auto key = resolver.resolve("3824");
        ASSERT_TRUE(key.has_value());
        EXPECT_TRUE(key->empty());
    }

    TEST_F(ClientKeysFileResolverTest, MissingFileLeavesResolverEmpty)
    {
        ClientKeysFileResolver resolver(m_path + "-does-not-exist");
        EXPECT_FALSE(resolver.resolve("3824").has_value());
    }

    TEST_F(ClientKeysFileResolverTest, ReloadPicksUpChanges)
    {
        writeFile("3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        ClientKeysFileResolver resolver(m_path);
        ASSERT_TRUE(resolver.resolve("3824").has_value());

        writeFile("3824 !debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        EXPECT_EQ(resolver.reload(), 0);
        EXPECT_FALSE(resolver.resolve("3824").has_value());
    }

} // namespace
