/*
 * Wazuh databaseFeedManager
 * Copyright (C) 2015, Wazuh Inc.
 * November 2, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "../../../src/versionMatcher/versionMatcher.hpp"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::Return;

class VersionMatcherTest : public ::testing::Test
{
protected:
    /**
     * @brief Construct a new Database Feed Manager Tests object
     *
     */
    VersionMatcherTest() = default;

    /**
     * @brief Destroy the Database Feed Manager Tests object
     *
     */
    ~VersionMatcherTest() override = default;

    /**
     * @brief SetUp.
     *
     */
    void SetUp() override;

    /**
     * @brief TearDown.
     *
     */
    void TearDown() override;
};

void VersionMatcherTest::SetUp()
{
    logging::testInit();
};

void VersionMatcherTest::TearDown() {
    // Clean up any resources used by the test.
};

TEST_F(VersionMatcherTest, windowsStrategy)
{
    VersionComparisonResult compareResult;

    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2023.11.02.1", "2023.11.02.1", VersionMatcherStrategy::Windows)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("23.11.02.1", "23.11.02.1", VersionMatcherStrategy::Windows)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2023.11.02", "2023.11.02", VersionMatcherStrategy::Windows)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2023.11", "2023.11", VersionMatcherStrategy::Windows)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2023", "2023", VersionMatcherStrategy::Windows)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2023.11.02.0", "2023.11.02.1", VersionMatcherStrategy::Windows)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("23.11.02.0", "23.11.02.1", VersionMatcherStrategy::Windows)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2023.11.01", "2023.11.02", VersionMatcherStrategy::Windows)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2023.10", "2023.11", VersionMatcherStrategy::Windows)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2022", "2023", VersionMatcherStrategy::Windows)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);

    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2023.11.02.2", "2023.11.02.1", VersionMatcherStrategy::Windows)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("23.11.02.2", "23.11.02.1", VersionMatcherStrategy::Windows)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2023.11.03", "2023.11.02", VersionMatcherStrategy::Windows)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2023.12", "2023.11", VersionMatcherStrategy::Windows)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2024", "2023", VersionMatcherStrategy::Windows)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
}

TEST_F(VersionMatcherTest, macOsStrategy)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2023.11.02.1", "2023.11.02.1", VersionMatcherStrategy::MacOS)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("23.11.02.1", "23.11.02.1", VersionMatcherStrategy::MacOS)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2023.11.02", "2023.11.02", VersionMatcherStrategy::MacOS)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2023.11", "2023.11", VersionMatcherStrategy::MacOS)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2023", "2023", VersionMatcherStrategy::MacOS)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2023.11.02.0", "2023.11.02.1", VersionMatcherStrategy::MacOS)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("23.11.02.0", "23.11.02.1", VersionMatcherStrategy::MacOS)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2023.11.01", "2023.11.02", VersionMatcherStrategy::MacOS)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2023.10", "2023.11", VersionMatcherStrategy::MacOS)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2022", "2023", VersionMatcherStrategy::MacOS)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);

    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2023.11.02.2", "2023.11.02.1", VersionMatcherStrategy::MacOS)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("23.11.02.2", "23.11.02.1", VersionMatcherStrategy::MacOS)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2023.11.03", "2023.11.02", VersionMatcherStrategy::MacOS)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2023.12", "2023.11", VersionMatcherStrategy::MacOS)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2024", "2023", VersionMatcherStrategy::MacOS)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
}

TEST_F(VersionMatcherTest, pkgStrategy)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("13.3.1", "13.3.1", VersionMatcherStrategy::PKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("13.3.1", "13.5", VersionMatcherStrategy::PKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);

    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2.0.4_419.3", "2.0.4_419.3", VersionMatcherStrategy::PKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("17.1", "2.0.4_419.3", VersionMatcherStrategy::PKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("17.1", "17.1", VersionMatcherStrategy::PKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("17.1", "17.3", VersionMatcherStrategy::PKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("126.0.1", "126.0.1", VersionMatcherStrategy::PKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0.0.1", "2.0.0.1", VersionMatcherStrategy::PKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0.0.1", "126.0.1", VersionMatcherStrategy::PKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("12", "12", VersionMatcherStrategy::PKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("11.1.2", "12", VersionMatcherStrategy::PKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("12.0.1", "12.0.1", VersionMatcherStrategy::PKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("11.1.2", "12.0.1", VersionMatcherStrategy::PKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);

    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("109.0.5414.87", "109.0.5414.87", VersionMatcherStrategy::PKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("109.0.5414.87", "109.0.5414.119", VersionMatcherStrategy::PKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("109.0.5414.87", "110.0.5481.77", VersionMatcherStrategy::PKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("109.0.5414.87", "26.0.1410.30", VersionMatcherStrategy::PKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
}

TEST_F(VersionMatcherTest, compareCalVer_OkEqual)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2023.11.02.1", "2023.11.02.1", VersionObjectType::CalVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("23.11.02.1", "23.11.02.1", VersionObjectType::CalVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2023.11.02", "2023.11.02", VersionObjectType::CalVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2023.11", "2023.11", VersionObjectType::CalVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2023", "2023", VersionObjectType::CalVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
}

TEST_F(VersionMatcherTest, compareCalVer_OkLess)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2023.11.02.0", "2023.11.02.1", VersionObjectType::CalVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("23.11.02.0", "23.11.02.1", VersionObjectType::CalVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2023.11.01", "2023.11.02", VersionObjectType::CalVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2023.10", "2023.11", VersionObjectType::CalVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2022", "2023", VersionObjectType::CalVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
}

TEST_F(VersionMatcherTest, compareCalVer_OkGreater)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2023.11.02.2", "2023.11.02.1", VersionObjectType::CalVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("23.11.02.2", "23.11.02.1", VersionObjectType::CalVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2023.11.03", "2023.11.02", VersionObjectType::CalVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2023.12", "2023.11", VersionObjectType::CalVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2024", "2023", VersionObjectType::CalVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
}

TEST_F(VersionMatcherTest, compareCalVer_ErrorInvalidVersion)
{
    EXPECT_THROW(VersionMatcher::compare("A.B.C", "2023.11.02.1", VersionObjectType::CalVer), std::invalid_argument);
    EXPECT_THROW(VersionMatcher::compare("2023.13.02.1", "2023.11.02.1", VersionObjectType::CalVer),
                 std::invalid_argument);
    EXPECT_THROW(VersionMatcher::compare("2023.12.32.1", "2023.11.02.1", VersionObjectType::CalVer),
                 std::invalid_argument);
}

TEST_F(VersionMatcherTest, comparePEP440_OkEqual)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare(
                         "1!2.0b2.post345.dev456", "1!2.0b2.post345.dev456", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare(
                         "2.0b2.post345.dev456", "2.0b2.post345.dev456", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2.0b2.post345", "2.0b2.post345", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0b2", "2.0b2", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0", "2.0", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0.1.2.3", "2.0.1.2.3", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2.0.1.2.3", "2.0.1.2.3.0.0.0", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2.0.1.2.3.0.0.0", "2.0.1.2.3", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
}

TEST_F(VersionMatcherTest, comparePEP440_AlternativeSyntax_OkEqual)
{
    VersionComparisonResult compareResult;

    // Case sensitivity
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.1RC1", "1.1rc1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.3A2", "2.3a2", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.0.Dev1", "1.0.dev1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    // Integer normalization
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("03.004.0023", "3.4.23", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2014.05.03", "2014.5.3", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    // Pre-release separators
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3.a1", "1.2.3a1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3-a1", "1.2.3a1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3_a1", "1.2.3a1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3a.1", "1.2.3a1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3a-1", "1.2.3a1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3a_1", "1.2.3a1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    // Pre-release spelling
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3alpha1", "1.2.3a1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3beta1", "1.2.3b1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3c1", "1.2.3rc1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3pre1", "1.2.3rc1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3preview1", "1.2.3rc1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    // Implicit pre-release number
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3a", "1.2.3a0", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3b", "1.2.3b0", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3rc", "1.2.3rc0", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    // Post release separators
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3-post1", "1.2.3.post1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3_post1", "1.2.3.post1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3post1", "1.2.3.post1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("1.2.3.post.1", "1.2.3.post1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("1.2.3.post-1", "1.2.3.post1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("1.2.3.post_1", "1.2.3.post1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    // Post release spelling
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3.rev1", "1.2.3.post1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3.r1", "1.2.3.post1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    // Implicit post release number
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3.post", "1.2.3.post0", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3.rev", "1.2.3.post0", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3.r", "1.2.3.post0", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    // Implicit post releases
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3-1", "1.2.3.post1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    // Development release separators
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3-dev1", "1.2.3.dev1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3_dev1", "1.2.3.dev1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3dev1", "1.2.3.dev1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    // Implicit development release number
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3.dev", "1.2.3.dev0", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    // Preceding 'v' character
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("v1.2.3", "1.2.3", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);

    // Combination of previous cases
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare(
                         "1!2.0Beta_rev345-DEV456", "1!2.0b0.post345.dev456", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare(
                         "2.0BETA2.post_dev456", "2.0b2.post0.dev456", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare(
                         "v2.0.Preview2-r.6-dev1", "2.0rc2.post6.dev1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
}

TEST_F(VersionMatcherTest, comparePEP440_OkLess)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare(
                         "1!2.0b2.post345.dev455", "1!2.0b2.post345.dev456", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare(
                         "2.0b2.post345.dev455", "1!2.0b2.post345.dev455", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare(
                         "2.0b2.post345.dev455", "2.0b2.post345.dev456", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2.0b2.post345", "2.0b2.post345.dev455", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2.0b2.post344", "2.0b2.post345", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0b2", "2.0b2.post344", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0b1", "2.0b2", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0a2", "2.0b2", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0a2", "2.0", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0", "2.1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0.1.2.2", "2.0.1.2.3", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2.0.1.2.2", "2.0.1.2.3.0.0.0", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2.0.1.2.2.0.0.0", "2.0.1.2.3", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
}

TEST_F(VersionMatcherTest, comparePEP440_AlternativeSyntax_OkLess)
{
    VersionComparisonResult compareResult;

    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.0003", "1.2.4", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0alpha2", "2.0beta2", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0beta2", "2.0preview2", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0beta", "2.0beta2", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0post0", "2.0-post.1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0post", "2.0-post1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0-DEV1", "2.0.dev2", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0.dev", "2.0.dev1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
}

TEST_F(VersionMatcherTest, comparePEP440_OkGreater)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare(
                         "1!2.0b2.post345.dev457", "1!2.0b2.post345.dev456", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare(
                         "1!2.0b2.post345.dev455", "2.0b2.post345.dev455", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare(
                         "2.0b2.post345.dev456", "2.0b2.post345.dev455", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2.0b2.post345.dev455", "2.0b2.post345", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2.0b2.post345", "2.0b2.post344", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0b2.post344", "2.0b2", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0b2", "2.0b1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0b2", "2.0a2", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0", "2.0a2", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.1", "2.0", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0.1.2.3", "2.0.1.2.2", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2.0.1.2.3.0.0.0", "2.0.1.2.2", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2.0.1.2.3", "2.0.1.2.2.0.0.0", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
}

TEST_F(VersionMatcherTest, comparePEP440_AlternativeSyntax_OkGreater)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.4", "1.2.0003", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0beta2", "2.0alpha2", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0preview2", "2.0beta2", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0beta2", "2.0beta", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0-post.1", "2.0post0", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0-post1", "2.0post", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0.dev2", "2.0-DEV1", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.0.dev1", "2.0.dev", VersionObjectType::PEP440)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
}

TEST_F(VersionMatcherTest, comparePEP440_ErrorInvalidVersion)
{
    EXPECT_THROW(VersionMatcher::compare("A.B.C", "1!2.0b2.post345.dev456", VersionObjectType::PEP440),
                 std::invalid_argument);
}

TEST_F(VersionMatcherTest, compareMajorMinor_OkEqual)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2", "1.2", VersionObjectType::MajorMinor)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1-2", "1-2", VersionObjectType::MajorMinor)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2", "1-2", VersionObjectType::MajorMinor)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
}

TEST_F(VersionMatcherTest, compareMajorMinor_OkLess)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.1", "1.2", VersionObjectType::MajorMinor)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.1", "2.1", VersionObjectType::MajorMinor)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1-1", "1-2", VersionObjectType::MajorMinor)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1-1", "1.2", VersionObjectType::MajorMinor)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
}

TEST_F(VersionMatcherTest, compareMajorMinor_OkGreater)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.3", "1.2", VersionObjectType::MajorMinor)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2.2", "1.2", VersionObjectType::MajorMinor)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1-3", "1-2", VersionObjectType::MajorMinor)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1-3", "1.2", VersionObjectType::MajorMinor)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
}

TEST_F(VersionMatcherTest, compareMajorMinor_ErrorInvalidVersion)
{
    EXPECT_THROW(VersionMatcher::compare("A.B.C", "1.2", VersionObjectType::MajorMinor), std::invalid_argument);
}

TEST_F(VersionMatcherTest, compareSemVer_OkEqual)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("1.2.3-beta+001", "1.2.3-beta+001", VersionObjectType::SemVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("1.2.3-beta+001", "1.2.3-beta", VersionObjectType::SemVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3+001", "1.2.3+001", VersionObjectType::SemVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3+001", "1.2.3", VersionObjectType::SemVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
}

TEST_F(VersionMatcherTest, compareSemVer_OkLess)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("1.2.2-beta+001", "2.2.2-beta+001", VersionObjectType::SemVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("1.2.2-beta+001", "1.3.2-beta+001", VersionObjectType::SemVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("1.2.2-beta+001", "1.2.3-beta+001", VersionObjectType::SemVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("1.2.2-beta+001", "1.2.3-beta", VersionObjectType::SemVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("1.2.3-alfa+001", "1.2.3+001", VersionObjectType::SemVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("1.2.3-alfa+001", "1.2.3-beta", VersionObjectType::SemVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.2+001", "1.2.3+001", VersionObjectType::SemVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.2+001", "1.2.3", VersionObjectType::SemVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
}

TEST_F(VersionMatcherTest, compareSemVer_OkGreater)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("1.2.4-beta+001", "1.2.3-beta+001", VersionObjectType::SemVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("1.3.2-beta+001", "1.2.2-beta+001", VersionObjectType::SemVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("2.2.2-beta+001", "1.2.2-beta+001", VersionObjectType::SemVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("1.2.3-beta", "1.2.2-beta+001", VersionObjectType::SemVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("1.2.3-beta", "1.2.3-alfa+001", VersionObjectType::SemVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3+001", "1.2.2+001", VersionObjectType::SemVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3", "1.2.2+001", VersionObjectType::SemVer)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
}

TEST_F(VersionMatcherTest, compareSemVer_ErrorInvalidVersion)
{
    EXPECT_THROW(VersionMatcher::compare("A.B.C", "1.2.3-beta+001", VersionObjectType::SemVer), std::invalid_argument);
}

TEST_F(VersionMatcherTest, compareUnspecified_OkCalVer)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2023.11.02.1", "2023.11.02.1")));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
}

TEST_F(VersionMatcherTest, compareUnspecified_OkPEP440)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1!2.0b2.post345.dev456", "1!2.0b2.post345.dev456")));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
}

TEST_F(VersionMatcherTest, compareUnspecified_OkMajorMinor)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2", "1.2")));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
}

TEST_F(VersionMatcherTest, compareUnspecified_OkSemVer)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1.2.3-beta+001", "1.2.3-beta+001")));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
}

TEST_F(VersionMatcherTest, compareUnspecified_ErrorInvalidFormat)
{
    EXPECT_THROW(VersionMatcher::compare("A.B.C", "2023.11.02.1"), std::invalid_argument);
}

TEST_F(VersionMatcherTest, compareUnspecified_ErrorDifferentFormats)
{
    EXPECT_THROW(VersionMatcher::compare("2023.11.02.1", "1!2.0b2.post345.dev456"), std::invalid_argument);
}

TEST_F(VersionMatcherTest, compareUnexistingVersionObjectType)
{
    EXPECT_THROW(VersionMatcher::compare("A.B.C", "A.B.C", static_cast<VersionObjectType>(1000)),
                 std::invalid_argument);
}

TEST_F(VersionMatcherTest, compareDpkgVer_OkEqual)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare(
                         "1:5.15.8-2ubuntu2.0", "1:5.15.8-2ubuntu2.0", VersionObjectType::DPKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("5.15.8-2", "5.15.8-2", VersionObjectType::DPKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("2:5.15.8-2", "2:5.15.8-2", VersionObjectType::DPKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("5.15.16-0+deb10u1", "5.15.16-0+deb10u1", VersionObjectType::DPKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("7.3.0+dfsg-1", "7.3.0+dfsg-1", VersionObjectType::DPKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
}

TEST_F(VersionMatcherTest, compareDpkgVer_OkLess)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare(
                         "1:4.15.8-2ubuntu2.0", "1:5.15.8-2ubuntu2.0", VersionObjectType::DPKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("5.15.8-1", "5.15.8-2", VersionObjectType::DPKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("1:5.15.8-2", "2:5.15.8-2", VersionObjectType::DPKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("5.14.16-0+deb10u1", "5.15.16-0+deb10u1", VersionObjectType::DPKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("7.2.0+dfsg-1", "7.3.0+dfsg-1", VersionObjectType::DPKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
}

TEST_F(VersionMatcherTest, compareDpkgVer_OkGreater)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare(
                         "1:6.15.8-2ubuntu2.0", "1:5.15.8-2ubuntu2.0", VersionObjectType::DPKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("5.15.8-3", "5.15.8-2", VersionObjectType::DPKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("3:5.15.8-2", "2:5.15.8-2", VersionObjectType::DPKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW(
        (compareResult = VersionMatcher::compare("5.16.16-0+deb10u1", "5.15.16-0+deb10u1", VersionObjectType::DPKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("7.3.1+dfsg-1", "7.3.0+dfsg-1", VersionObjectType::DPKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("4.4.3-P1-2", "4.4.3-P1-1", VersionObjectType::DPKG),
              VersionComparisonResult::A_GREATER_THAN_B);
}

TEST_F(VersionMatcherTest, compareDpkgVer_ErrorInvalidVersion)
{
    EXPECT_THROW(VersionMatcher::compare("A.B.C", "2023.11.02-1", VersionObjectType::DPKG), std::invalid_argument);
    EXPECT_THROW(VersionMatcher::compare("2.9.4+dfsg1-3.1, 2.9.5", "2.9.4+dfsg1-3.1, 2.9.5", VersionObjectType::DPKG),
                 std::invalid_argument);
}

TEST_F(VersionMatcherTest, compareDpkgVer_dpkgLib)
{
    VersionComparisonResult compareResult;
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("0:1.1-1", "0:1.1-1", VersionObjectType::DPKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("0:1.1-0", "0:2.1-0", VersionObjectType::DPKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("0:2.1-0", "0:1.1-0", VersionObjectType::DPKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("0:1.0-0", "0:1.0-0", VersionObjectType::DPKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
    EXPECT_NO_THROW((compareResult = VersionMatcher::compare("0:0.0-0", "0:0.0-0", VersionObjectType::DPKG)));
    EXPECT_EQ(compareResult, VersionComparisonResult::A_EQUAL_B);
}

TEST_F(VersionMatcherTest, compareRpmVer_rmpPackages)
{
    EXPECT_EQ(VersionMatcher::compare(
                  "4.2.5_02_3.0.101_0.46-0.7.9.i586", "4.2.5_02_3.0.101_0.46-0.7.9.i586", VersionObjectType::RPM),
              VersionComparisonResult::A_EQUAL_B); // Suse
    EXPECT_EQ(VersionMatcher::compare("4.1.0-18.el7_1.3.x86_64", "4.1.0-18.el7_1.3.x86_64", VersionObjectType::RPM),
              VersionComparisonResult::A_EQUAL_B); // Redhat
    EXPECT_EQ(VersionMatcher::compare("1.0.1-10.module_el8.5.0+150+5f0dbea0.alma.ppc64le",
                                      "1.0.1-10.module_el8.5.0+150+5f0dbea0.alma.ppc64le",
                                      VersionObjectType::RPM),
              VersionComparisonResult::A_EQUAL_B); // Alma
    EXPECT_EQ(VersionMatcher::compare("2.2.20", "2.2.20-2.el8", VersionObjectType::RPM),
              VersionComparisonResult::A_LESS_THAN_B); // No release
}

TEST_F(VersionMatcherTest, matchCalVer)
{
    EXPECT_TRUE(VersionMatcher::match("2023.11.02.1", VersionObjectType::CalVer));
    EXPECT_TRUE(VersionMatcher::match("2021.01", VersionObjectType::CalVer));
    EXPECT_TRUE(VersionMatcher::match("2023.2.5", VersionObjectType::CalVer));
    EXPECT_TRUE(VersionMatcher::match("2021.12.17", VersionObjectType::CalVer));

    EXPECT_FALSE(VersionMatcher::match("21.0.0", VersionObjectType::CalVer));
    EXPECT_FALSE(VersionMatcher::match("202.11.02.1", VersionObjectType::CalVer));
}

TEST_F(VersionMatcherTest, matchPEP440)
{
    EXPECT_TRUE(VersionMatcher::match("1!2.0b2.post345.dev456", VersionObjectType::PEP440));
    EXPECT_TRUE(VersionMatcher::match("1.0b2.post345.dev456", VersionObjectType::PEP440));

    EXPECT_FALSE(VersionMatcher::match("1!2.0b2.345.dev456", VersionObjectType::PEP440));
}

TEST_F(VersionMatcherTest, matchMajorMinor)
{
    EXPECT_TRUE(VersionMatcher::match("3.0", VersionObjectType::MajorMinor));
    EXPECT_TRUE(VersionMatcher::match("1-6", VersionObjectType::MajorMinor));

    EXPECT_FALSE(VersionMatcher::match("3.A", VersionObjectType::MajorMinor));
    EXPECT_FALSE(VersionMatcher::match("3.0.1", VersionObjectType::MajorMinor));
    EXPECT_FALSE(VersionMatcher::match("B.3", VersionObjectType::MajorMinor));
    EXPECT_FALSE(VersionMatcher::match("C-6", VersionObjectType::MajorMinor));
    EXPECT_FALSE(VersionMatcher::match("7", VersionObjectType::MajorMinor));
    EXPECT_FALSE(VersionMatcher::match("7.", VersionObjectType::MajorMinor));
    EXPECT_FALSE(VersionMatcher::match("7-", VersionObjectType::MajorMinor));
}

TEST_F(VersionMatcherTest, matchSemVer)
{
    EXPECT_TRUE(VersionMatcher::match("1.2.2-beta+001", VersionObjectType::SemVer));
    EXPECT_TRUE(VersionMatcher::match("1.0.1-alpha", VersionObjectType::SemVer));
    EXPECT_TRUE(VersionMatcher::match("2.1.0-dev", VersionObjectType::SemVer));
    EXPECT_TRUE(VersionMatcher::match("2.1.0-RC1", VersionObjectType::SemVer));
    EXPECT_TRUE(VersionMatcher::match("1.2.3", VersionObjectType::SemVer));

    EXPECT_FALSE(VersionMatcher::match("1.2.B", VersionObjectType::SemVer));
    EXPECT_FALSE(VersionMatcher::match("1:5.15.8-2ubuntu2.0", VersionObjectType::SemVer));
}

TEST_F(VersionMatcherTest, matchDPKG)
{
    EXPECT_TRUE(VersionMatcher::match("1:5.15.8-2ubuntu2.0", VersionObjectType::DPKG));
    EXPECT_TRUE(VersionMatcher::match("20230206.0~ds2-1.1", VersionObjectType::DPKG));
    EXPECT_TRUE(VersionMatcher::match("5.15.0-1052.57~20.04.1", VersionObjectType::DPKG));

    EXPECT_TRUE(VersionMatcher::match("21.1-19-gbad84ad4-0ubuntu1~16.04.1", VersionObjectType::DPKG));
    EXPECT_TRUE(VersionMatcher::match("19.4-56-g06e324ff-0ubuntu1", VersionObjectType::DPKG));
    EXPECT_TRUE(VersionMatcher::match("1.39+1.40-WIP-2006.11.14+dfsg-2ubuntu1.1", VersionObjectType::DPKG));
}

TEST_F(VersionMatcherTest, matchRPM)
{
    EXPECT_TRUE(VersionMatcher::match("1:4.8.0-2.amzn2023.0.2", VersionObjectType::RPM));
    EXPECT_TRUE(VersionMatcher::match("2020.3-8.el92", VersionObjectType::RPM));
    EXPECT_TRUE(VersionMatcher::match("3.1.2-1.el9", VersionObjectType::RPM));
    EXPECT_TRUE(VersionMatcher::match("20180407-10.el9", VersionObjectType::RPM));

    EXPECT_TRUE(VersionMatcher::match("5.5.6.0_2003-04-09", VersionObjectType::RPM));
    EXPECT_TRUE(VersionMatcher::match("6.9-11-0", VersionObjectType::RPM));

    EXPECT_TRUE(VersionMatcher::match("1:4.8.0-2.amzn2023.0.2", VersionObjectType::RPM));
    EXPECT_TRUE(VersionMatcher::match("2020.3-8.el92", VersionObjectType::RPM));
    EXPECT_TRUE(VersionMatcher::match("3.1.2-1.el9", VersionObjectType::RPM));
    EXPECT_TRUE(VersionMatcher::match("20180407-10.el9", VersionObjectType::RPM));
    EXPECT_TRUE(VersionMatcher::match("5.5.6.0_2003-04-09", VersionObjectType::RPM));
    EXPECT_TRUE(VersionMatcher::match("6.9-11-0", VersionObjectType::RPM));
    EXPECT_TRUE(VersionMatcher::match("1!2.0b2.post345.dev45", VersionObjectType::RPM));
    EXPECT_TRUE(VersionMatcher::match("16.04.1", VersionObjectType::RPM));

    EXPECT_TRUE(VersionMatcher::match("A.B.C", VersionObjectType::RPM));

    EXPECT_EQ(VersionMatcher::compare("1:4.8.0-2.amzn2023.0.2", "1:4.8.0-2.amzn2023.0.2", VersionObjectType::RPM),
              VersionComparisonResult::A_EQUAL_B);
    EXPECT_EQ(VersionMatcher::compare("5-4.amzn2023.0.5", "5-4.amzn2023.0.5", VersionObjectType::RPM),
              VersionComparisonResult::A_EQUAL_B);
    EXPECT_EQ(VersionMatcher::compare("3.14-5.amzn2023.0.3", "3.14-5.amzn2023.0.3", VersionObjectType::RPM),
              VersionComparisonResult::A_EQUAL_B);
    EXPECT_EQ(VersionMatcher::compare("1:2.0.5-12.amzn2023.0.2", "1:2.0.5-12.amzn2023.0.2", VersionObjectType::RPM),
              VersionComparisonResult::A_EQUAL_B);
    EXPECT_EQ(VersionMatcher::compare("2.37.4-1.amzn2023.0.3", "2.37.4-1.amzn2023.0.3", VersionObjectType::RPM),
              VersionComparisonResult::A_EQUAL_B);
    EXPECT_EQ(VersionMatcher::compare("2:9.0.2120-1.amzn2023", "2:9.0.2120-1.amzn2023", VersionObjectType::RPM),
              VersionComparisonResult::A_EQUAL_B);
    EXPECT_EQ(VersionMatcher::compare("2.21-26.amzn2023.0.2", "2.21-26.amzn2023.0.2", VersionObjectType::RPM),
              VersionComparisonResult::A_EQUAL_B);

    EXPECT_EQ(VersionMatcher::compare("1:4.8.0-2.amzn2023.0.2", "2:4.8.0-2.amzn2023.0.2", VersionObjectType::RPM),
              VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("5-4.amzn2023.0.5", "6-4.amzn2023.0.5", VersionObjectType::RPM),
              VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("3.14-5.amzn2023.0.3", "3.15-5.amzn2023.0.3", VersionObjectType::RPM),
              VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("1:2.0.5-12.amzn2023.0.2", "1:2.0.6-12.amzn2023.0.2", VersionObjectType::RPM),
              VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("2.37.4-1.amzn2023.0.3", "2.37.4-2.amzn2023.0.3", VersionObjectType::RPM),
              VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("2:9.0.2120-1.amzn2023", "2:9.0.2120-2.amzn2023", VersionObjectType::RPM),
              VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("2.21-26.amzn2023.0.2", "2.22-26.amzn2023.0.2", VersionObjectType::RPM),
              VersionComparisonResult::A_LESS_THAN_B);

    EXPECT_EQ(VersionMatcher::compare("2:4.8.0-2.amzn2023.0.2", "1:4.8.0-2.amzn2023.0.2", VersionObjectType::RPM),
              VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("6-4.amzn2023.0.5", "5-4.amzn2023.0.5", VersionObjectType::RPM),
              VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("3.15-5.amzn2023.0.3", "3.14-5.amzn2023.0.3", VersionObjectType::RPM),
              VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("1:2.0.5-13.amzn2023.0.2", "1:2.0.5-12.amzn2023.0.2", VersionObjectType::RPM),
              VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("3.37.4-1.amzn2023.0.3", "2.37.4-1.amzn2023.0.3", VersionObjectType::RPM),
              VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("2:9.1.2120-1.amzn2023", "2:9.0.2120-1.amzn2023", VersionObjectType::RPM),
              VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("2.21-29.amzn2023.0.2", "2.21-26.amzn2023.0.2", VersionObjectType::RPM),
              VersionComparisonResult::A_GREATER_THAN_B);

    EXPECT_EQ(VersionMatcher::compare("1.15.1-6.amzn2023.0.3", "gpgme-1.4.3-5.15", VersionObjectType::RPM),
              VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("1.57.0-1.amzn2023.0.1", "1.41.0-1.amzn2.0.4", VersionObjectType::RPM),
              VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("5.4.4-3.amzn2023.0.2", "5.4.4-3.amzn2022", VersionObjectType::RPM),
              VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("2~almost^post", "2.0.1", VersionObjectType::RPM),
              VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("3.9.18-1.el9_3", "3.9.18-1.el9_3.1", VersionObjectType::RPM),
              VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("0.9.1+git.20181118-bp156.3.5", "0.9.1-16.fc39", VersionObjectType::RPM),
              VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("4.5.1-bp156.4.2", "4.5.1-bp155.3.7", VersionObjectType::RPM),
              VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("11.1-2.git3118496.2.mga10", "11.1-2.git3118496.1.mga9", VersionObjectType::RPM),
              VersionComparisonResult::A_GREATER_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("0.0.26-bp156.3.5", "0.0.26-9", VersionObjectType::RPM),
              VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("0.9.1+git.20181118-bp156.3.5", "0.9.1+git.20181118-1.3", VersionObjectType::RPM),
              VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("0.2-bp156.4.5", "0.2-3.2", VersionObjectType::RPM),
              VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("2.15.6-1.mga10", "2.15.6-1.1", VersionObjectType::RPM),
              VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("0.5.2-5.el4.at", "0.5.2-5.0.el5", VersionObjectType::RPM),
              VersionComparisonResult::A_LESS_THAN_B);
    EXPECT_EQ(VersionMatcher::compare("2:3.28.1-3.el8", "3:2.3.15-24.el8", VersionObjectType::RPM),
              VersionComparisonResult::A_LESS_THAN_B);

    EXPECT_NO_THROW(VersionMatcher::compare("invalid", "3:2.3.15-24.el8", VersionObjectType::RPM));
}
