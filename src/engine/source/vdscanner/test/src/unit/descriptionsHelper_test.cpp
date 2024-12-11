/*
 * Wazuh Vulnerability Scanner - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 25, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../../../vdscanner/src/descriptionsHelper.hpp"
#include "feedmanager/mockDatabaseFeedManager.hpp"
#include "vulnerabilityDescription_generated.h"
#include <base/json.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

/**
 * @brief Runs unit tests for the DescriptionsHelper class.
 *
 */
class DescriptionsHelperTest : public ::testing::Test
{
protected:
    // LCOV_EXCL_START
    DescriptionsHelperTest() = default;
    ~DescriptionsHelperTest() override = default;
    /**
     * @brief Set the environment for testing.
     *
     */
    void SetUp() override;
    // LCOV_EXCL_STOP
};

void DescriptionsHelperTest::SetUp()
{
    logging::testInit();
}

namespace
{
const nlohmann::json ADP_DESCRIPTIONS =
    R"#(
    {
        "adp_descriptions": {
            "ADP_1": {
                "description": "A",
                "cvss": "A"
            },
            "ADP_2": {
                "description": "A",
                "cvss": "B"
            },
            "nvd": {
                "description": "nvd",
                "cvss": "nvd"
            }
        }
    }
)#"_json;

const std::string CVE_ID = "CVE-1234-1234";
const std::string ADP_INEXISTENT = "non_existent";
const std::string ADP_CVSS_EQUALS_DESCRIPTION = "ADP_1";
const std::string ADP_CVSS_DIFFERS_DESCRIPTION = "ADP_2";
const std::string ADP_EXPANDED_POSTFIX = "_expanded";

const auto createVulnerabilityDescriptiveInformationFail =
    [](FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
{
    resultContainer.data = nullptr;
    return false;
};

const auto createVulnerabilityDescriptiveInformation =
    [](FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer,
       flatbuffers::DetachedBuffer& detachedBuffer,
       float scoreBase = 3.0f,
       const char* description = "descriptionData.description",
       const char* severity = "cvssData.severity")
{
    flatbuffers::FlatBufferBuilder fbBuilder;
    const auto vulnerabilityDescriptiveInformation =
        NSVulnerabilityScanner::CreateVulnerabilityDescriptionDirect(fbBuilder,
                                                                     "cvssData.accessComplexity",
                                                                     "descriptionData.assignerShortName",
                                                                     "cvssData.attackVector",
                                                                     "cvssData.authentication",
                                                                     "cvssData.availabilityImpact",
                                                                     "cvssData.classification",
                                                                     "cvssData.confidentialityImpact",
                                                                     "descriptionData.cweId",
                                                                     "descriptionData.datePublished",
                                                                     "descriptionData.dateUpdated",
                                                                     description,
                                                                     "cvssData.integrityImpact",
                                                                     "cvssData.privilegesRequired",
                                                                     "descriptionData.reference",
                                                                     "cvssData.scope",
                                                                     scoreBase,
                                                                     "cvssData.scoreVersion",
                                                                     severity,
                                                                     "cvssData.userInteraction");

    fbBuilder.Finish(vulnerabilityDescriptiveInformation);
    detachedBuffer = fbBuilder.Release();
    resultContainer.data = NSVulnerabilityScanner::GetVulnerabilityDescription(detachedBuffer.data());

    return true;
};

const auto validateVulnerabilityDescriptiveInformation = [](const CveDescription& description)
{
    EXPECT_EQ(description.accessComplexity, "cvssData.accessComplexity");
    EXPECT_EQ(description.assignerShortName, "descriptionData.assignerShortName");
    EXPECT_EQ(description.attackVector, "cvssData.attackVector");
    EXPECT_EQ(description.authentication, "cvssData.authentication");
    EXPECT_EQ(description.availabilityImpact, "cvssData.availabilityImpact");
    EXPECT_EQ(description.classification, "cvssData.classification");
    EXPECT_EQ(description.confidentialityImpact, "cvssData.confidentialityImpact");
    EXPECT_EQ(description.cweId, "descriptionData.cweId");
    EXPECT_EQ(description.datePublished, "descriptionData.datePublished");
    EXPECT_EQ(description.dateUpdated, "descriptionData.dateUpdated");
    EXPECT_EQ(description.description, "descriptionData.description");
    EXPECT_EQ(description.integrityImpact, "cvssData.integrityImpact");
    EXPECT_EQ(description.privilegesRequired, "cvssData.privilegesRequired");
    EXPECT_EQ(description.reference, "descriptionData.reference");
    EXPECT_EQ(description.scope, "cvssData.scope");
    EXPECT_EQ(description.scoreBase, 3.0f);
    EXPECT_EQ(description.scoreVersion, "cvssData.scoreVersion");
    EXPECT_EQ(description.severity, "cvssData.severity");
    EXPECT_EQ(description.userInteraction, "cvssData.userInteraction");
};

} // namespace

/**
 * @brief Attempt to retrieve the information from an ADP in which the CVSS and description are obtained from the same
 * source.
 *
 */
TEST_F(DescriptionsHelperTest, cvssAndDescriptionFromSameSource)
{
    const auto sources =
        std::make_pair(ADP_CVSS_EQUALS_DESCRIPTION, ADP_CVSS_EQUALS_DESCRIPTION + ADP_EXPANDED_POSTFIX);

    const auto& adpDescriptionsData = ADP_DESCRIPTIONS.at("adp_descriptions").at(ADP_CVSS_EQUALS_DESCRIPTION);
    const auto expectedAdpDescriptionSource = adpDescriptionsData.at("description").get<std::string>();

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();

    // Create a detached buffer to store the vulnerability descriptive information for the test duration
    flatbuffers::DetachedBuffer detachedBuffer;

    // We expect one call to the database manager for both the CVSS and description
    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, expectedAdpDescriptionSource, testing::_))
        .WillOnce(
            ::testing::Invoke([&](const std::string&,
                                  const std::string&,
                                  FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
                              { return createVulnerabilityDescriptiveInformation(resultContainer, detachedBuffer); }));

    // We don't expect the database manager to be called with the default ADP
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilityDescriptiveInformation(CVE_ID, DEFAULT_ADP, testing::_))
        .Times(0);

    EXPECT_CALL(*spDatabaseFeedManagerMock, vendorsMap()).WillRepeatedly(testing::ReturnRef(ADP_DESCRIPTIONS));

    DescriptionsHelper::vulnerabilityDescription<MockDatabaseFeedManager>(
        CVE_ID, sources, spDatabaseFeedManagerMock, validateVulnerabilityDescriptiveInformation);

    // Reset the mocks
    spDatabaseFeedManagerMock.reset();
}

/**
 * @brief Attempt to retrieve the information from an ADP in which the CVSS and description are obtained from the same
 * source.
 *
 */
TEST_F(DescriptionsHelperTest, cvssAndDescriptionFromDifferentSource)
{
    const auto sources =
        std::make_pair(ADP_CVSS_DIFFERS_DESCRIPTION, ADP_CVSS_DIFFERS_DESCRIPTION + ADP_EXPANDED_POSTFIX);

    const auto& adpDescriptionsData = ADP_DESCRIPTIONS.at("adp_descriptions").at(ADP_CVSS_DIFFERS_DESCRIPTION);
    const auto expectedAdpDescriptionSource = adpDescriptionsData.at("description").get<std::string>();
    const auto expectedAdpCvssSource = adpDescriptionsData.at("cvss").get<std::string>();

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();

    // Create two detached buffers to store the vulnerability descriptive information for the test duration
    flatbuffers::DetachedBuffer detachedBufferDescription;
    flatbuffers::DetachedBuffer detachedBufferCvss;

    // Expect two calls to the database manager, one for the description and one for the CVSS
    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, expectedAdpDescriptionSource, testing::_))
        .WillOnce(::testing::Invoke(
            [&](const std::string&,
                const std::string&,
                FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
            { return createVulnerabilityDescriptiveInformation(resultContainer, detachedBufferDescription); }));

    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, expectedAdpCvssSource, testing::_))
        .WillOnce(::testing::Invoke(
            [&](const std::string&,
                const std::string&,
                FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
            {
                createVulnerabilityDescriptiveInformation(resultContainer, detachedBufferCvss);
                return true;
            }));

    // We don't expect the database manager to be called with the default ADP
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilityDescriptiveInformation(CVE_ID, DEFAULT_ADP, testing::_))
        .Times(0);

    EXPECT_CALL(*spDatabaseFeedManagerMock, vendorsMap()).WillRepeatedly(testing::ReturnRef(ADP_DESCRIPTIONS));

    DescriptionsHelper::vulnerabilityDescription<MockDatabaseFeedManager>(
        CVE_ID, sources, spDatabaseFeedManagerMock, validateVulnerabilityDescriptiveInformation);

    // Reset the mocks
    spDatabaseFeedManagerMock.reset();
}

/**
 * @brief Attempt to retrieve the information from an ADP that is not present in the ADP descriptions map. We should
 * fallback to the default ADP.
 *
 */
TEST_F(DescriptionsHelperTest, nonExistentAdp)
{
    const auto sources = std::make_pair(ADP_INEXISTENT, ADP_INEXISTENT + ADP_EXPANDED_POSTFIX);

    const auto expectedAdpDescriptionSource =
        ADP_DESCRIPTIONS.at("adp_descriptions").at(DEFAULT_ADP).at("description").get<std::string>();

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();

    // Create a detached buffer to store the vulnerability descriptive information for the test duration
    flatbuffers::DetachedBuffer detachedBuffer;

    // We get the information from the default ADP
    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, expectedAdpDescriptionSource, testing::_))
        .WillOnce(
            ::testing::Invoke([&](const std::string&,
                                  const std::string&,
                                  FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
                              { return createVulnerabilityDescriptiveInformation(resultContainer, detachedBuffer); }));

    EXPECT_CALL(*spDatabaseFeedManagerMock, vendorsMap()).WillRepeatedly(testing::ReturnRef(ADP_DESCRIPTIONS));

    DescriptionsHelper::vulnerabilityDescription<MockDatabaseFeedManager>(
        CVE_ID, sources, spDatabaseFeedManagerMock, validateVulnerabilityDescriptiveInformation);

    // Reset the mocks
    spDatabaseFeedManagerMock.reset();
}

/**
 * @brief The database doesn't contain the information for the requested ADP, so we fallback to the default ADP.
 *
 */
TEST_F(DescriptionsHelperTest, informationNotFoundOnDB)
{
    const auto sources =
        std::make_pair(ADP_CVSS_DIFFERS_DESCRIPTION, ADP_CVSS_DIFFERS_DESCRIPTION + ADP_EXPANDED_POSTFIX);

    const auto adpDescriptionSource =
        ADP_DESCRIPTIONS.at("adp_descriptions").at(ADP_CVSS_DIFFERS_DESCRIPTION).at("description").get<std::string>();
    const auto adpCvssSource =
        ADP_DESCRIPTIONS.at("adp_descriptions").at(ADP_CVSS_DIFFERS_DESCRIPTION).at("cvss").get<std::string>();
    const auto defaultAdpSource =
        ADP_DESCRIPTIONS.at("adp_descriptions").at(DEFAULT_ADP).at("description").get<std::string>();

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();

    // Two calls to the default ADP fail, so we fallback to the default ADP
    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, adpDescriptionSource, testing::_))
        .WillOnce(::testing::Invoke(
            [&](const std::string&,
                const std::string&,
                FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
            {
                flatbuffers::DetachedBuffer detachedBuffer;
                return createVulnerabilityDescriptiveInformationFail(resultContainer);
            }));

    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilityDescriptiveInformation(CVE_ID, adpCvssSource, testing::_))
        .WillOnce(::testing::Invoke(
            [&](const std::string&,
                const std::string&,
                FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
            {
                flatbuffers::DetachedBuffer detachedBuffer;
                return createVulnerabilityDescriptiveInformationFail(resultContainer);
            }));

    // Create two detached buffers to store the vulnerability descriptive information for the test duration
    flatbuffers::DetachedBuffer detachedBufferDescription;
    flatbuffers::DetachedBuffer detachedBufferCvss;

    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, defaultAdpSource, testing::_))
        .WillOnce(::testing::Invoke(
            [&](const std::string&,
                const std::string&,
                FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
            { return createVulnerabilityDescriptiveInformation(resultContainer, detachedBufferDescription); }))
        .WillOnce(::testing::Invoke(
            [&](const std::string&,
                const std::string&,
                FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
            { return createVulnerabilityDescriptiveInformation(resultContainer, detachedBufferCvss); }));

    EXPECT_CALL(*spDatabaseFeedManagerMock, vendorsMap()).WillRepeatedly(testing::ReturnRef(ADP_DESCRIPTIONS));

    DescriptionsHelper::vulnerabilityDescription<MockDatabaseFeedManager>(
        CVE_ID, sources, spDatabaseFeedManagerMock, validateVulnerabilityDescriptiveInformation);

    // Reset the mocks
    spDatabaseFeedManagerMock.reset();
}

/**
 * @brief The CVSS information is not reliable, so we fallback to the default ADP (due to the CVSS score being near 0).
 *
 */
TEST_F(DescriptionsHelperTest, notReliableCvssInformationNoScore)
{
    const auto sources =
        std::make_pair(ADP_CVSS_DIFFERS_DESCRIPTION, ADP_CVSS_DIFFERS_DESCRIPTION + ADP_EXPANDED_POSTFIX);

    const auto& adpDescriptionsData = ADP_DESCRIPTIONS.at("adp_descriptions").at(ADP_CVSS_DIFFERS_DESCRIPTION);
    const auto expectedAdpDescriptionSource = adpDescriptionsData.at("description").get<std::string>();
    const auto expectedAdpCvssSource = adpDescriptionsData.at("cvss").get<std::string>();
    const auto defaultAdpCvssSource =
        ADP_DESCRIPTIONS.at("adp_descriptions").at(DEFAULT_ADP).at("cvss").get<std::string>();

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();

    // Create three detached buffers to store the vulnerability descriptive information for the test duration
    flatbuffers::DetachedBuffer detachedBufferDescription;
    flatbuffers::DetachedBuffer detachedBufferCvss;
    flatbuffers::DetachedBuffer detachedBufferDefaultCvss;

    // Expect three calls to the database manager, one for the description and two for the CVSS (one for the unreliable
    // ADP and one for the default ADP)
    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, expectedAdpDescriptionSource, testing::_))
        .WillOnce(::testing::Invoke(
            [&](const std::string&,
                const std::string&,
                FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
            { return createVulnerabilityDescriptiveInformation(resultContainer, detachedBufferDescription, 0.0f); }));

    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, expectedAdpCvssSource, testing::_))
        .WillOnce(::testing::Invoke(
            [&](const std::string&,
                const std::string&,
                FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
            { return createVulnerabilityDescriptiveInformation(resultContainer, detachedBufferCvss, 0.0f); }));

    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, defaultAdpCvssSource, testing::_))
        .WillOnce(::testing::Invoke(
            [&](const std::string&,
                const std::string&,
                FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
            { return createVulnerabilityDescriptiveInformation(resultContainer, detachedBufferDefaultCvss); }));

    EXPECT_CALL(*spDatabaseFeedManagerMock, vendorsMap()).WillRepeatedly(testing::ReturnRef(ADP_DESCRIPTIONS));

    DescriptionsHelper::vulnerabilityDescription<MockDatabaseFeedManager>(
        CVE_ID, sources, spDatabaseFeedManagerMock, validateVulnerabilityDescriptiveInformation);

    // Reset the mocks
    spDatabaseFeedManagerMock.reset();
}

/**
 * @brief The CVSS information is not reliable, so we fallback to the default ADP (due to the CVSS severity being
 * empty).
 *
 */
TEST_F(DescriptionsHelperTest, notReliableCvssInformationEmptySeverity)
{
    const auto sources =
        std::make_pair(ADP_CVSS_DIFFERS_DESCRIPTION, ADP_CVSS_DIFFERS_DESCRIPTION + ADP_EXPANDED_POSTFIX);

    const auto& adpDescriptionsData = ADP_DESCRIPTIONS.at("adp_descriptions").at(ADP_CVSS_DIFFERS_DESCRIPTION);
    const auto expectedAdpDescriptionSource = adpDescriptionsData.at("description").get<std::string>();
    const auto expectedAdpCvssSource = adpDescriptionsData.at("cvss").get<std::string>();
    const auto defaultAdpCvssSource =
        ADP_DESCRIPTIONS.at("adp_descriptions").at(DEFAULT_ADP).at("cvss").get<std::string>();

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();

    // Create three detached buffers to store the vulnerability descriptive information for the test duration
    flatbuffers::DetachedBuffer detachedBufferDescription;
    flatbuffers::DetachedBuffer detachedBufferCvss;
    flatbuffers::DetachedBuffer detachedBufferDefaultCvss;

    // Expect three calls to the database manager, one for the description and two for the CVSS (one for the unreliable
    // ADP and one for the default ADP)
    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, expectedAdpDescriptionSource, testing::_))
        .WillOnce(::testing::Invoke(
            [&](const std::string&,
                const std::string&,
                FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
            {
                return createVulnerabilityDescriptiveInformation(resultContainer,
                                                                 detachedBufferDescription,
                                                                 3.0f,
                                                                 "descriptionData.description",
                                                                 CveDescription::DEFAULT_STR_VALUE);
            }));

    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, expectedAdpCvssSource, testing::_))
        .WillOnce(::testing::Invoke(
            [&](const std::string&,
                const std::string&,
                FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
            {
                return createVulnerabilityDescriptiveInformation(resultContainer,
                                                                 detachedBufferCvss,
                                                                 3.0f,
                                                                 "descriptionData.description",
                                                                 CveDescription::DEFAULT_STR_VALUE);
            }));

    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, defaultAdpCvssSource, testing::_))
        .WillOnce(::testing::Invoke(
            [&](const std::string&,
                const std::string&,
                FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
            { return createVulnerabilityDescriptiveInformation(resultContainer, detachedBufferDefaultCvss); }));

    EXPECT_CALL(*spDatabaseFeedManagerMock, vendorsMap()).WillRepeatedly(testing::ReturnRef(ADP_DESCRIPTIONS));

    DescriptionsHelper::vulnerabilityDescription<MockDatabaseFeedManager>(
        CVE_ID, sources, spDatabaseFeedManagerMock, validateVulnerabilityDescriptiveInformation);

    // Reset the mocks
    spDatabaseFeedManagerMock.reset();
}

/**
 * @brief The Description information is not reliable, so we fallback to the default ADP.
 *
 */
TEST_F(DescriptionsHelperTest, notReliableDescriptionInformation)
{
    const auto sources =
        std::make_pair(ADP_CVSS_DIFFERS_DESCRIPTION, ADP_CVSS_DIFFERS_DESCRIPTION + ADP_EXPANDED_POSTFIX);

    const auto& adpDescriptionsData = ADP_DESCRIPTIONS.at("adp_descriptions").at(ADP_CVSS_DIFFERS_DESCRIPTION);
    const auto expectedAdpDescriptionSource = adpDescriptionsData.at("description").get<std::string>();
    const auto expectedAdpCvssSource = adpDescriptionsData.at("cvss").get<std::string>();
    const auto defaultAdpDescriptionSource =
        ADP_DESCRIPTIONS.at("adp_descriptions").at(DEFAULT_ADP).at("description").get<std::string>();

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();

    // Create three detached buffers to store the vulnerability descriptive information for the test duration
    flatbuffers::DetachedBuffer detachedBufferDescription;
    flatbuffers::DetachedBuffer detachedBufferDefaultDescription;
    flatbuffers::DetachedBuffer detachedBufferCvss;

    // Expect three calls to the database manager, one for the CVSS and two for the description (one for the unreliable
    // ADP and one for the default ADP)
    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, expectedAdpDescriptionSource, testing::_))
        .WillOnce(::testing::Invoke(
            [&](const std::string&,
                const std::string&,
                FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
            {
                return createVulnerabilityDescriptiveInformation(
                    resultContainer, detachedBufferDescription, 3.0f, "not defined");
            }));

    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, defaultAdpDescriptionSource, testing::_))
        .WillOnce(::testing::Invoke(
            [&](const std::string&,
                const std::string&,
                FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
            { return createVulnerabilityDescriptiveInformation(resultContainer, detachedBufferDefaultDescription); }));

    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, expectedAdpCvssSource, testing::_))
        .WillOnce(::testing::Invoke(
            [&](const std::string&,
                const std::string&,
                FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
            { return createVulnerabilityDescriptiveInformation(resultContainer, detachedBufferCvss); }));

    EXPECT_CALL(*spDatabaseFeedManagerMock, vendorsMap()).WillRepeatedly(testing::ReturnRef(ADP_DESCRIPTIONS));

    DescriptionsHelper::vulnerabilityDescription<MockDatabaseFeedManager>(
        CVE_ID, sources, spDatabaseFeedManagerMock, validateVulnerabilityDescriptiveInformation);

    // Reset the mocks
    spDatabaseFeedManagerMock.reset();
}

/**
 * @brief Attempt to retrieve the information from an ADP in which the CVSS and description are obtained from the same
 * source but fails.
 *
 */
TEST_F(DescriptionsHelperTest, cvssAndDescriptionFromSameSourceCouldNotBeObtained)
{
    const auto sources =
        std::make_pair(ADP_CVSS_EQUALS_DESCRIPTION, ADP_CVSS_EQUALS_DESCRIPTION + ADP_EXPANDED_POSTFIX);

    const auto& adpDescriptionsData = ADP_DESCRIPTIONS.at("adp_descriptions").at(ADP_CVSS_EQUALS_DESCRIPTION);
    const auto expectedAdpDescriptionSource = adpDescriptionsData.at("description").get<std::string>();

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();

    // We expect a call to the database manager to retrieve description information but fails.
    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, expectedAdpDescriptionSource, testing::_))
        .WillOnce(
            ::testing::Invoke([&](const std::string&,
                                  const std::string&,
                                  FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
                              { return createVulnerabilityDescriptiveInformationFail(resultContainer); }));

    // We expect the database manager to be called with the default ADP because no information could be found with the
    // specific ADP and also fails.
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilityDescriptiveInformation(CVE_ID, DEFAULT_ADP, testing::_))
        .WillOnce(
            ::testing::Invoke([&](const std::string&,
                                  const std::string&,
                                  FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
                              { return createVulnerabilityDescriptiveInformationFail(resultContainer); }));

    EXPECT_CALL(*spDatabaseFeedManagerMock, vendorsMap()).WillRepeatedly(testing::ReturnRef(ADP_DESCRIPTIONS));

    // Information couldn't be retrieved. Default values asigned.
    const auto validateVulnerabilityDescriptiveInformationFail = [](const CveDescription& description)
    {
        EXPECT_EQ(description.accessComplexity, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.assignerShortName, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.attackVector, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.authentication, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.availabilityImpact, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.classification, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.confidentialityImpact, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.cweId, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.datePublished, CveDescription::DEFAULT_TIMESTAMP);
        EXPECT_EQ(description.dateUpdated, CveDescription::DEFAULT_TIMESTAMP);
        EXPECT_EQ(description.description, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.integrityImpact, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.privilegesRequired, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.reference, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.scope, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.scoreBase, 0);
        EXPECT_EQ(description.scoreVersion, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.severity, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.userInteraction, CveDescription::DEFAULT_STR_VALUE);
    };

    DescriptionsHelper::vulnerabilityDescription<MockDatabaseFeedManager>(
        CVE_ID, sources, spDatabaseFeedManagerMock, validateVulnerabilityDescriptiveInformationFail);

    // Reset the mocks
    spDatabaseFeedManagerMock.reset();
}

/**
 * @brief Attempt to retrieve the information from an ADP in which the CVSS and description are obtained from different
 * sources. Description information retrieval fails.
 *
 */
TEST_F(DescriptionsHelperTest, cvssAndDescriptionFromDifferentSourceCDescriptionFails)
{
    const auto sources =
        std::make_pair(ADP_CVSS_DIFFERS_DESCRIPTION, ADP_CVSS_DIFFERS_DESCRIPTION + ADP_EXPANDED_POSTFIX);

    const auto& adpDescriptionsData = ADP_DESCRIPTIONS.at("adp_descriptions").at(ADP_CVSS_DIFFERS_DESCRIPTION);
    const auto expectedAdpDescriptionSource = adpDescriptionsData.at("description").get<std::string>();
    const auto expectedAdpCvssSource = adpDescriptionsData.at("cvss").get<std::string>();

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();

    // Create a detached buffer to store the CVSS descriptive information for the test duration
    flatbuffers::DetachedBuffer detachedBufferCvss;

    // We expect a call to retrieve the description information but fails.
    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, expectedAdpDescriptionSource, testing::_))
        .WillOnce(
            ::testing::Invoke([&](const std::string&,
                                  const std::string&,
                                  FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
                              { return createVulnerabilityDescriptiveInformationFail(resultContainer); }));

    // We expect the database manager to be called with the default ADP but fails.
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilityDescriptiveInformation(CVE_ID, DEFAULT_ADP, testing::_))
        .WillOnce(
            ::testing::Invoke([&](const std::string&,
                                  const std::string&,
                                  FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
                              { return createVulnerabilityDescriptiveInformationFail(resultContainer); }));

    // We expect a call to retrieve information from CVSS source.
    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, expectedAdpCvssSource, testing::_))
        .WillOnce(::testing::Invoke(
            [&](const std::string&,
                const std::string&,
                FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
            { return createVulnerabilityDescriptiveInformation(resultContainer, detachedBufferCvss); }));

    EXPECT_CALL(*spDatabaseFeedManagerMock, vendorsMap()).WillRepeatedly(testing::ReturnRef(ADP_DESCRIPTIONS));

    // Only information from description is set to default values.
    const auto validateVulnerabilityDescriptiveInformationFail = [](const CveDescription& description)
    {
        EXPECT_EQ(description.accessComplexity, "cvssData.accessComplexity");
        EXPECT_EQ(description.assignerShortName, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.attackVector, "cvssData.attackVector");
        EXPECT_EQ(description.authentication, "cvssData.authentication");
        EXPECT_EQ(description.availabilityImpact, "cvssData.availabilityImpact");
        EXPECT_EQ(description.classification, "cvssData.classification");
        EXPECT_EQ(description.confidentialityImpact, "cvssData.confidentialityImpact");
        EXPECT_EQ(description.cweId, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.datePublished, CveDescription::DEFAULT_TIMESTAMP);
        EXPECT_EQ(description.dateUpdated, CveDescription::DEFAULT_TIMESTAMP);
        EXPECT_EQ(description.description, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.integrityImpact, "cvssData.integrityImpact");
        EXPECT_EQ(description.privilegesRequired, "cvssData.privilegesRequired");
        EXPECT_EQ(description.reference, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.scope, "cvssData.scope");
        EXPECT_EQ(description.scoreBase, 3.0f);
        EXPECT_EQ(description.scoreVersion, "cvssData.scoreVersion");
        EXPECT_EQ(description.severity, "cvssData.severity");
        EXPECT_EQ(description.userInteraction, "cvssData.userInteraction");
    };

    DescriptionsHelper::vulnerabilityDescription<MockDatabaseFeedManager>(
        CVE_ID, sources, spDatabaseFeedManagerMock, validateVulnerabilityDescriptiveInformationFail);

    // Reset the mocks
    spDatabaseFeedManagerMock.reset();
}

/**
 * @brief Attempt to retrieve the information from an ADP in which the CVSS and description are obtained from different
 * sources. CVSS information fails.
 *
 */
TEST_F(DescriptionsHelperTest, cvssAndDescriptionFromDifferentSourceCVSSFails)
{
    const auto sources =
        std::make_pair(ADP_CVSS_DIFFERS_DESCRIPTION, ADP_CVSS_DIFFERS_DESCRIPTION + ADP_EXPANDED_POSTFIX);

    const auto& adpDescriptionsData = ADP_DESCRIPTIONS.at("adp_descriptions").at(ADP_CVSS_DIFFERS_DESCRIPTION);
    const auto expectedAdpDescriptionSource = adpDescriptionsData.at("description").get<std::string>();
    const auto expectedAdpCvssSource = adpDescriptionsData.at("cvss").get<std::string>();

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();

    // Create a detached buffer to store the vulnerability description information for the test duration
    flatbuffers::DetachedBuffer detachedBufferDescription;

    // Expect a calls to the database manager to retrieve the description information.
    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, expectedAdpDescriptionSource, testing::_))
        .WillOnce(::testing::Invoke(
            [&](const std::string&,
                const std::string&,
                FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
            { return createVulnerabilityDescriptiveInformation(resultContainer, detachedBufferDescription); }));

    // Couldn't retrieve information from CVSS source.
    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, expectedAdpCvssSource, testing::_))
        .WillOnce(
            ::testing::Invoke([&](const std::string&,
                                  const std::string&,
                                  FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
                              { return createVulnerabilityDescriptiveInformationFail(resultContainer); }));

    // We expect the database manager to be called with the default ADP but fails.
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilityDescriptiveInformation(CVE_ID, DEFAULT_ADP, testing::_))
        .WillOnce(
            ::testing::Invoke([&](const std::string&,
                                  const std::string&,
                                  FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
                              { return createVulnerabilityDescriptiveInformationFail(resultContainer); }));

    EXPECT_CALL(*spDatabaseFeedManagerMock, vendorsMap()).WillRepeatedly(testing::ReturnRef(ADP_DESCRIPTIONS));

    const auto validateVulnerabilityDescriptiveInformationFail = [](const CveDescription& description)
    {
        EXPECT_EQ(description.accessComplexity, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.assignerShortName, "descriptionData.assignerShortName");
        EXPECT_EQ(description.attackVector, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.authentication, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.availabilityImpact, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.classification, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.confidentialityImpact, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.cweId, "descriptionData.cweId");
        EXPECT_EQ(description.datePublished, "descriptionData.datePublished");
        EXPECT_EQ(description.dateUpdated, "descriptionData.dateUpdated");
        EXPECT_EQ(description.description, "descriptionData.description");
        EXPECT_EQ(description.integrityImpact, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.privilegesRequired, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.reference, "descriptionData.reference");
        EXPECT_EQ(description.scope, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.scoreBase, 0);
        EXPECT_EQ(description.scoreVersion, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.severity, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.userInteraction, CveDescription::DEFAULT_STR_VALUE);
    };

    DescriptionsHelper::vulnerabilityDescription<MockDatabaseFeedManager>(
        CVE_ID, sources, spDatabaseFeedManagerMock, validateVulnerabilityDescriptiveInformationFail);

    // Reset the mocks
    spDatabaseFeedManagerMock.reset();
}

/**
 * @brief Attempt to retrieve the information from an ADP in which the CVSS and description are obtained from different
 * sources. Both fails.
 *
 */
TEST_F(DescriptionsHelperTest, cvssAndDescriptionFromDifferentSourceBothFails)
{
    const auto sources =
        std::make_pair(ADP_CVSS_DIFFERS_DESCRIPTION, ADP_CVSS_DIFFERS_DESCRIPTION + ADP_EXPANDED_POSTFIX);

    const auto& adpDescriptionsData = ADP_DESCRIPTIONS.at("adp_descriptions").at(ADP_CVSS_DIFFERS_DESCRIPTION);
    const auto expectedAdpDescriptionSource = adpDescriptionsData.at("description").get<std::string>();
    const auto expectedAdpCvssSource = adpDescriptionsData.at("cvss").get<std::string>();

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();

    // We expect a call to retrieve the description information but fails.
    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, expectedAdpDescriptionSource, testing::_))
        .WillOnce(
            ::testing::Invoke([&](const std::string&,
                                  const std::string&,
                                  FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
                              { return createVulnerabilityDescriptiveInformationFail(resultContainer); }));

    // We expect the database manager to be called with the default ADP but fails.
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilityDescriptiveInformation(CVE_ID, DEFAULT_ADP, testing::_))
        .WillOnce(
            ::testing::Invoke([&](const std::string&,
                                  const std::string&,
                                  FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
                              { return createVulnerabilityDescriptiveInformationFail(resultContainer); }));

    // Couldn't retrieve information from CVSS source.
    EXPECT_CALL(*spDatabaseFeedManagerMock,
                getVulnerabilityDescriptiveInformation(CVE_ID, expectedAdpCvssSource, testing::_))
        .WillOnce(
            ::testing::Invoke([&](const std::string&,
                                  const std::string&,
                                  FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
                              { return createVulnerabilityDescriptiveInformationFail(resultContainer); }));

    EXPECT_CALL(*spDatabaseFeedManagerMock, vendorsMap()).WillRepeatedly(testing::ReturnRef(ADP_DESCRIPTIONS));

    const auto validateVulnerabilityDescriptiveInformationFail = [](const CveDescription& description)
    {
        EXPECT_EQ(description.accessComplexity, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.assignerShortName, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.attackVector, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.authentication, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.availabilityImpact, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.classification, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.confidentialityImpact, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.cweId, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.datePublished, CveDescription::DEFAULT_TIMESTAMP);
        EXPECT_EQ(description.dateUpdated, CveDescription::DEFAULT_TIMESTAMP);
        EXPECT_EQ(description.description, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.integrityImpact, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.privilegesRequired, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.reference, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.scope, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.scoreBase, 0);
        EXPECT_EQ(description.scoreVersion, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.severity, CveDescription::DEFAULT_STR_VALUE);
        EXPECT_EQ(description.userInteraction, CveDescription::DEFAULT_STR_VALUE);
    };

    DescriptionsHelper::vulnerabilityDescription<MockDatabaseFeedManager>(
        CVE_ID, sources, spDatabaseFeedManagerMock, validateVulnerabilityDescriptiveInformationFail);

    // Reset the mocks
    spDatabaseFeedManagerMock.reset();
}
