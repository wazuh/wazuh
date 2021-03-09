/*
 * Wazuh SyscollectorNormalizer
 * Copyright (C) 2015-2021, Wazuh Inc.
 * January 12, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "sysNormalizer_test.h"
#include "test_config.h"
#include "test_input.h"
#include "syscollectorNormalizer.h"
#include <fstream>
#include <cstdio>


void SysNormalizerTest::SetUp()
{
    std::ofstream testConfigFile{TEST_CONFIG_FILE_NAME};

    if (testConfigFile.is_open())
    {
        testConfigFile << TEST_CONFIG_FILE_CONTENT;
    }
};

void SysNormalizerTest::TearDown()
{
    std::remove(TEST_CONFIG_FILE_NAME);
};

using ::testing::_;
using ::testing::Return;

TEST_F(SysNormalizerTest, ctor)
{
    EXPECT_NO_THROW((SysNormalizer{TEST_CONFIG_FILE_NAME, "macos"}));
}

TEST_F(SysNormalizerTest, ctorNonExistingFile)
{
    EXPECT_NO_THROW((SysNormalizer{"TEST_CONFIG_FILE_NAME", "macos"}));
}

TEST_F(SysNormalizerTest, ctorWrongFormatConfig)
{
    constexpr auto WRONG_FORMAT_FILE{"wrong_format.json"};
    std::ofstream testConfigFile{WRONG_FORMAT_FILE};

    if (testConfigFile.is_open())
    {
        testConfigFile << R"({"exclusions":[})";
    }

    EXPECT_NO_THROW((SysNormalizer{WRONG_FORMAT_FILE, "macos"}));
    std::remove(WRONG_FORMAT_FILE);
}

TEST_F(SysNormalizerTest, excludeSiriAndiTunes)
{
    const auto& inputJson{nlohmann::json::parse(TEST_INPUT_DATA)};
    const auto size{inputJson.size()};
    SysNormalizer normalizer{TEST_CONFIG_FILE_NAME, "macos"};
    const auto& result{normalizer.removeExcluded("packages", inputJson)};
    EXPECT_EQ(size, result.size() + 2);
}

TEST_F(SysNormalizerTest, excludeSingleItemNoMatch)
{
    const auto& inputJson{nlohmann::json::parse(R"(
        {
            "description": "com.apple.FaceTime",
            "group": "public.app-category.social-networking",
            "name": "FaceTime",
            "version": "3.0"
        })")};
    SysNormalizer normalizer{TEST_CONFIG_FILE_NAME, "macos"};
    const auto& result{normalizer.removeExcluded("packages", inputJson)};
    EXPECT_EQ(inputJson, result);
}

TEST_F(SysNormalizerTest, excludeSingleItemMatch)
{
    const auto& inputJson{nlohmann::json::parse(R"(
        {
            "description": "com.apple.siri.launcher",
            "group": "public.app-category.utilities",
            "name": "Siri",
            "version": "1.0"
        })")};
    SysNormalizer normalizer{TEST_CONFIG_FILE_NAME, "macos"};
    const auto& result{normalizer.removeExcluded("packages", inputJson)};
    EXPECT_NE(inputJson, result);
    EXPECT_TRUE(result.empty());
}

TEST_F(SysNormalizerTest, normalizeSingleMicosoft)
{
    const auto& inputJson{nlohmann::json::parse(R"(
        {
            "description": "com.microsoft.antivirus",
            "group": "public.app-category.security",
            "name": "Microsoft Defender",
            "version": "1.0"
        })")};
    SysNormalizer normalizer{TEST_CONFIG_FILE_NAME, "macos"};
    const auto& result{normalizer.normalize("packages", inputJson)};
    EXPECT_NE(inputJson, result);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result["vendor"], "Microsoft");
}

TEST_F(SysNormalizerTest, normalizeSingleMcAfee1)
{
    const auto& inputJson{nlohmann::json::parse(R"(
        {
            "description": "com.mcafee.antivirus",
            "group": "public.app-category.security",
            "name": "McAfee Antivirus For Mac",
            "version": "1.0"
        })")};
    SysNormalizer normalizer{TEST_CONFIG_FILE_NAME, "macos"};
    const auto& result{normalizer.normalize("packages", inputJson)};
    EXPECT_NE(inputJson, result);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result["vendor"], "McAfee");
    EXPECT_EQ(result["name"], "Antivirus");
}

TEST_F(SysNormalizerTest, normalizeSingleMcAfee2)
{
    const auto& inputJson{nlohmann::json::parse(R"(
        {
            "description": "com.mcafee.antivirus",
            "group": "public.app-category.security",
            "name": "McAfee Endpoint Protection For Mac",
            "version": "1.0"
        })")};
    SysNormalizer normalizer{TEST_CONFIG_FILE_NAME, "macos"};
    const auto& result{normalizer.normalize("packages", inputJson)};
    EXPECT_NE(inputJson, result);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result["vendor"], "McAfee");
    EXPECT_EQ(result["name"], "Endpoint Protection");
}

TEST_F(SysNormalizerTest, normalizeSingleTotalDefense1)
{
    const auto& inputJson{nlohmann::json::parse(R"(
        {
            "description": "com.totaldefense.antivirus",
            "group": "public.app-category.security",
            "name": "TotalDefenseAntivirusforMac",
            "version": "1.0"
        })")};
    SysNormalizer normalizer{TEST_CONFIG_FILE_NAME, "macos"};
    const auto& result{normalizer.normalize("packages", inputJson)};
    EXPECT_NE(inputJson, result);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result["vendor"], "TotalDefense");
    EXPECT_EQ(result["name"], "Anti-Virus");
}

TEST_F(SysNormalizerTest, normalizeSingleTotalDefense2)
{
    const auto& inputJson{nlohmann::json::parse(R"(
        {
            "description": "com.totaldefense.antivirus",
            "group": "public.app-category.security",
            "name": "TotalDefenseOtherProductforMac",
            "version": "1.0"
        })")};
    SysNormalizer normalizer{TEST_CONFIG_FILE_NAME, "macos"};
    const auto& result{normalizer.normalize("packages", inputJson)};
    EXPECT_NE(inputJson, result);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result["vendor"], "TotalDefense");
    EXPECT_EQ(result["name"], "OtherProduct");
}

TEST_F(SysNormalizerTest, normalizeSingleAVG1)
{
    const auto& inputJson{nlohmann::json::parse(R"(
        {
            "description": "com.avg.antivirus",
            "group": "public.app-category.security",
            "name": "AVGAntivirus",
            "version": "1.0"
        })")};
    SysNormalizer normalizer{TEST_CONFIG_FILE_NAME, "macos"};
    const auto& result{normalizer.normalize("packages", inputJson)};
    EXPECT_NE(inputJson, result);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result["vendor"], "AVG");
    EXPECT_EQ(result["name"], "Anti-Virus");
}

TEST_F(SysNormalizerTest, normalizeSingleAVG2)
{
    const auto& inputJson{nlohmann::json::parse(R"(
        {
            "description": "com.avg.antivirus",
            "group": "public.app-category.security",
            "name": "AVGOtherProduct",
            "version": "1.0"
        })")};
    SysNormalizer normalizer{TEST_CONFIG_FILE_NAME, "macos"};
    const auto& result{normalizer.normalize("packages", inputJson)};
    EXPECT_NE(inputJson, result);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result["vendor"], "AVG");
    EXPECT_EQ(result["name"], "OtherProduct");
}

TEST_F(SysNormalizerTest, normalizeSingleKaspersky1)
{
    const auto& inputJson{nlohmann::json::parse(R"(
        {
            "description": "com.kaspersky.antivirus",
            "group": "public.app-category.security",
            "name": "Kaspersky Antivirus For Mac",
            "version": "1.0"
        })")};
    SysNormalizer normalizer{TEST_CONFIG_FILE_NAME, "macos"};
    const auto& result{normalizer.normalize("packages", inputJson)};
    EXPECT_NE(inputJson, result);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result["name"], "Kaspersky Antivirus");
}

TEST_F(SysNormalizerTest, normalizeSingleKaspersky2)
{
    const auto& inputJson{nlohmann::json::parse(R"(
        {
            "description": "com.kaspersky.internetsecurity",
            "group": "public.app-category.security",
            "name": "Kaspersky Internet Security For Mac",
            "version": "1.0"
        })")};
    SysNormalizer normalizer{TEST_CONFIG_FILE_NAME, "macos"};
    const auto& result{normalizer.normalize("packages", inputJson)};
    EXPECT_NE(inputJson, result);
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result["name"], "Kaspersky Internet Security");
}

TEST_F(SysNormalizerTest, normalizeItemMatch)
{
    const auto& inputJson{nlohmann::json::parse(TEST_INPUT_DATA)};
    SysNormalizer normalizer{TEST_CONFIG_FILE_NAME, "macos"};
    const auto& result{normalizer.normalize("packages", inputJson)};
    EXPECT_EQ(inputJson.size(), result.size());
    EXPECT_NE(inputJson, result);
}