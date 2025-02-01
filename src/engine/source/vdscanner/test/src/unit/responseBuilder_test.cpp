/*
 * Wazuh Vulnerability Scanner - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * January 2, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../../../src/responseBuilder.hpp"
#include "../../../src/scanContext.hpp"
#include "base/utils/timeUtils.hpp"
#include "feedmanager/mockDatabaseFeedManager.hpp"
#include "flatbuffers/flatbuffer_builder.h"
#include "flatbuffers/flatbuffers.h"
#include "flatbuffers/idl.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

using ::testing::_;
using ::testing::HasSubstr;
using ::testing::ThrowsMessage;

class ResponseBuilderTest : public ::testing::Test
{
protected:
    // LCOV_EXCL_START
    ResponseBuilderTest() = default;
    ~ResponseBuilderTest() override = default;

    /**
     * @brief Set the environment for testing.
     *
     */
    void SetUp() override;

    /**
     * @brief Clean the environment after testing.
     *
     */
    void TearDown() override;
    // LCOV_EXCL_STOP
};
namespace NSresponseBuilderTest
{
constexpr auto TEST_DESCRIPTION_DATABASE_PATH {"queue/vd/descriptions"};

const auto PACKAGES_001_MSG =
    R"(
        {
            "architecture": "amd64",
            "checksum": "1e6ce14f97f57d1bbd46ff8e5d3e133171a1bbce",
            "description": "library for GIF images library",
            "format": "deb",
            "groups": "libs",
            "item_id": "ec465b7eb5fa011a336e95614072e4c7f1a65a53",
            "multiarch": "same",
            "name": "libgif7",
            "priority": "optional",
            "scan_time": "2023/08/04 19:56:11",
            "size": 72,
            "source": "giflib",
            "vendor": "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
            "version": "5.1.9-1",
            "install_time": "1577890801",
            "location":" "
        })"_json;

const auto PACKAGES_NO_ITEM_ID_001_MSG =
    R"(
        {
            "architecture": "amd64",
            "checksum": "1e6ce14f97f57d1bbd46ff8e5d3e133171a1bbce",
            "description": "library for GIF images library",
            "format": "deb",
            "groups": "libs",
            "multiarch": "same",
            "name": "libgif7",
            "priority": "optional",
            "scan_time": "2023/08/04 19:56:11",
            "size": 72,
            "source": "giflib",
            "vendor": "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
            "version": "5.1.9-1",
            "install_time": "1577890801",
            "location":" "
        })"_json;

const auto PACKAGES_EMPTY_ITEM_ID_001_MSG =
    R"(
        {
            "architecture": "amd64",
            "checksum": "1e6ce14f97f57d1bbd46ff8e5d3e133171a1bbce",
            "description": "library for GIF images library",
            "format": "deb",
            "item_id": "",
            "groups": "libs",
            "multiarch": "same",
            "name": "libgif7",
            "priority": "optional",
            "scan_time": "2023/08/04 19:56:11",
            "size": 72,
            "source": "giflib",
            "vendor": "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
            "version": "5.1.9-1",
            "install_time": "1577890801",
            "location":" "
        })"_json;

const auto AGENT_001_MSG =
    R"({
        "id": "001",
        "ip": "192.168.33.20",
        "version": "4.7.1",
        "name": "focal"
    })"_json;

const auto OS_001_MSG =
    R"({
            "hostname":"osdata_hostname",
            "architecture":"osdata_architecture",
            "name":"osdata_name",
            "codename":"osdata_codename",
            "major_version":"osdata_majorVersion",
            "minor_version":"osdata_minorVersion",
            "patch":"osdata_patch",
            "build":"osdata_build",
            "platform":"osdata_platform",
            "version":"osdata_version",
            "release":"osdata_release",
            "display_version":"osdata_displayVersion",
            "sysname":"osdata_sysName",
            "kernel_version":"osdata_kernelVersion",
            "kernel_release":"osdata_kernelRelease"
    })"_json;

const auto FEED_GLOBAL_MOCK =
    R"(
  {
    "prefix": [
      {"Canonical": {"cna":"canonical", "platforms":["ubuntu","linuxmint","pop"]}},
      {"Ubuntu":  {"cna":"canonical", "platforms":["ubuntu","linuxmint","pop"]}},
      {"Debian": {"cna":"debian", "platforms":["debian","linuxmint","pop"]}},
      {"Red Hat, Inc.": {"cna":"redhat", "platforms":["rhel","centos"]}},
      {"CentOS": {"cna":"redhat", "platforms":["centos","rhel"]}},
      {"Amazon Linux": {"cna":"alas", "platforms":["amzn"]}},
      {"Amazon.com": {"cna":"alas", "platforms":["amzn"]}},
      {"Amazon AWS": {"cna":"alas", "platforms":["amzn"]}},
      {"Arch Linux": {"cna":"arch", "platforms":["arch"]}},
      {"suse": {"cna":"suse", "platforms":["sles","sled"]}},
      {"SUSE": {"cna":"suse", "platforms":["sles","sled"]}},
      {"openSUSE": {"cna":"opensuse", "platforms":["opensuse-leap","opensuse-tumbleweed"]}},
      {"AlmaLinux": {"cna":"alma", "platforms":["almalinux"]}},
      {"CloudLinux": {"cna":"alma", "platforms":["almalinux"]}},
      {"Rocky": {"cna": "rocky","platforms": ["rocky"]}}
    ],
    "contains": [
      {"@ubuntu.com":  {"cna":"canonical", "platforms":["ubuntu","linuxmint","pop"]}},
      {"@canonical.com":  {"cna":"canonical", "platforms":["ubuntu","linuxmint","pop"]}},
      {"debian.org": {"cna":"debian", "platforms":["debian","linuxmint","pop"]}},
      {"debian.net": {"cna":"debian", "platforms":["debian","linuxmint","pop"]}}
    ],
    "format": [
      {"pypi": "pypi"},
      {"npm": "npm"},
      {"snap": "nvd"}
    ],
    "source": [
      {"homebrew": "homebrew"}
    ],
    "adp_descriptions": {
      "alas": {
        "adp": "Amazon Linux Security Center",
        "description": "cisa",
        "cvss": "alas"
      },
      "alma": {
        "adp": "Alma Linux Security Oval",
        "description": "alma",
        "cvss": "alma"
      },
      "arch": {
        "adp": "Arch Linux Security Tracker",
        "description": "cisa",
        "cvss": "cisa"
      },
      "debian": {
        "adp": "Debian Security Tracker",
        "description": "debian",
        "cvss": "cisa"
      },
      "oracle": {
        "adp": "Oracle Linux Security",
        "description": "cisa",
        "cvss": "oracle"
      },
      "npm": {
        "adp": "Open Source Vulnerabilities",
        "description": "npm",
        "cvss": "npm"
      },
      "nvd": {
        "adp": "National Vulnerability Database",
        "description": "nvd",
        "cvss": "nvd"
      },
      "pypi": {
        "adp": "Open Source Vulnerabilities",
        "description": "pypi",
        "cvss": "pypi"
      },
      "redhat": {
        "adp": "Red Hat CVE Database",
        "description": "redhat",
        "cvss": "redhat"
      },
      "rocky": {
        "adp": "Rocky Enterprise Product Errata",
        "description": "rocky",
        "cvss": "rocky"
      },
      "suse": {
        "adp": "SUSE CVE Database",
        "description": "suse",
        "cvss": "suse"
      },
      "opensuse": {
        "adp": "SUSE CVE Database",
        "description": "suse",
        "cvss": "suse"
      },
      "canonical": {
        "adp": "Canonical Security Tracker",
        "description": "canonical",
        "cvss": "canonical"
      },
      "homebrew": {
        "adp": "Homebrew Security Audit",
        "description": "homebrew",
        "cvss": "nvd"
      },
      "cisa": {
          "adp": "Cybersecurity and Infrastructure Security Agency",
          "description": "cisa",
          "cvss": "cisa"
      }
    }
  })"_json;

const std::string CVEID {"CVE-2024-1234"};
} // namespace NSresponseBuilderTest

using namespace NSresponseBuilderTest;

void ResponseBuilderTest::SetUp()
{
    logging::testInit();
}

void ResponseBuilderTest::TearDown()
{
    // Clean up any resources used by the test.
}

TEST_F(ResponseBuilderTest, TestSuccessfulPackageResponseCVSS2)
{
    flatbuffers::FlatBufferBuilder fbBuilder;
    auto vulnerabilityDescriptionData =
        NSVulnerabilityScanner::CreateVulnerabilityDescriptionDirect(fbBuilder,
                                                                     "accessComplexity_test_string",
                                                                     "assignerShortName_test_string",
                                                                     "attackVector_test_string",
                                                                     "authentication_test_string",
                                                                     "availabilityImpact_test_string",
                                                                     "classification_test_string",
                                                                     "confidentialityImpact_test_string",
                                                                     "cweId_test_string",
                                                                     "datePublished_test_string",
                                                                     "dateUpdated_test_string",
                                                                     "description_test_string",
                                                                     "integrityImpact_test_string",
                                                                     "privilegesRequired_test_string",
                                                                     "reference_test_string",
                                                                     "scope_test_string",
                                                                     8.3,
                                                                     "2",
                                                                     "severity_test_string",
                                                                     "userInteraction_test_string");
    fbBuilder.Finish(vulnerabilityDescriptionData);

    auto mockgetVulnerabilityDescriptiveInformation =
        [&](const std::string& cveId,
            const std::string& subShortName,
            FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer) -> bool
    {
        rocksdb::Slice value(reinterpret_cast<const char*>(fbBuilder.GetBufferPointer()), fbBuilder.GetSize());
        resultContainer.data = const_cast<NSVulnerabilityScanner::VulnerabilityDescription*>(
            NSVulnerabilityScanner::GetVulnerabilityDescription(value.data()));

        return true;
    };

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilityDescriptiveInformation(_, _, _))
        .WillRepeatedly(testing::Invoke(mockgetVulnerabilityDescriptiveInformation));
    EXPECT_CALL(*spDatabaseFeedManagerMock, vendorsMap()).WillRepeatedly(testing::ReturnRef(FEED_GLOBAL_MOCK));

    nlohmann::json response;
    auto scanContext = std::make_shared<ScanContext>(
        ScannerType::Package, AGENT_001_MSG, OS_001_MSG, PACKAGES_001_MSG, "{}"_json, response);
    // Mock one vulnerability
    scanContext->m_elements[CVEID] = R"({})"_json;
    scanContext->m_matchConditions[CVEID] = {"1.0.0", MatchRuleCondition::Equal};

    TResponseBuilder<MockDatabaseFeedManager, ScanContext> responseBuilder(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(responseBuilder.handleRequest(scanContext));

    EXPECT_EQ(response.size(), 1);

    auto& elementData = *response.begin();

    EXPECT_STREQ(elementData.at("category").get_ref<const std::string&>().c_str(), "Packages");
    EXPECT_STREQ(
        elementData.at("classification").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->classification()->c_str());
    EXPECT_STREQ(
        elementData.at("description").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->description()->c_str());
    EXPECT_STREQ(elementData.at("enumeration").get_ref<const std::string&>().c_str(), "CVE");
    EXPECT_STREQ(elementData.at("id").get_ref<const std::string&>().c_str(), CVEID.c_str());
    EXPECT_STREQ(
        elementData.at("reference").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->reference()->c_str());
    EXPECT_DOUBLE_EQ(
        elementData.at("score").at("base").get_ref<const double&>(),
        base::utils::numeric::floatToDoubleRound(
            NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->scoreBase(), 2));
    EXPECT_STREQ(
        elementData.at("score").at("version").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->scoreVersion()->c_str());
    EXPECT_STREQ(
        elementData.at("severity").get_ref<const std::string&>().c_str(),
        base::utils::string::toSentenceCase(
            NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->severity()->str())
            .c_str());
    EXPECT_STREQ(
        elementData.at("published_at").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->datePublished()->c_str());
    EXPECT_TRUE(elementData.at("detected_at").get_ref<const std::string&>() <= base::utils::time::getCurrentISO8601());
    EXPECT_STREQ(elementData.at("source").get_ref<const std::string&>().c_str(),
                 spDatabaseFeedManagerMock->vendorsMap()
                     .at("adp_descriptions")
                     .at(scanContext->m_vulnerabilitySource.first)
                     .at("adp")
                     .get_ref<const std::string&>()
                     .c_str());
    EXPECT_FALSE(elementData.at("under_evaluation").get_ref<const bool&>());
}

TEST_F(ResponseBuilderTest, TestSuccessfulPackageResponseCVSS3)
{
    flatbuffers::FlatBufferBuilder fbBuilder;
    auto vulnerabilityDescriptionData =
        NSVulnerabilityScanner::CreateVulnerabilityDescriptionDirect(fbBuilder,
                                                                     "accessComplexity_test_string",
                                                                     "assignerShortName_test_string",
                                                                     "attackVector_test_string",
                                                                     "authentication_test_string",
                                                                     "availabilityImpact_test_string",
                                                                     "classification_test_string",
                                                                     "confidentialityImpact_test_string",
                                                                     "cweId_test_string",
                                                                     "datePublished_test_string",
                                                                     "dateUpdated_test_string",
                                                                     "description_test_string",
                                                                     "integrityImpact_test_string",
                                                                     "privilegesRequired_test_string",
                                                                     "reference_test_string",
                                                                     "scope_test_string",
                                                                     8.3,
                                                                     "3",
                                                                     "severity_test_string",
                                                                     "userInteraction_test_string");
    fbBuilder.Finish(vulnerabilityDescriptionData);

    auto mockgetVulnerabilityDescriptiveInformation =
        [&](const std::string& cveId,
            const std::string& subShortName,
            FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer) -> bool
    {
        rocksdb::Slice value(reinterpret_cast<const char*>(fbBuilder.GetBufferPointer()), fbBuilder.GetSize());
        resultContainer.data = const_cast<NSVulnerabilityScanner::VulnerabilityDescription*>(
            NSVulnerabilityScanner::GetVulnerabilityDescription(value.data()));

        return true;
    };

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilityDescriptiveInformation(_, _, _))
        .WillRepeatedly(testing::Invoke(mockgetVulnerabilityDescriptiveInformation));
    EXPECT_CALL(*spDatabaseFeedManagerMock, vendorsMap()).WillRepeatedly(testing::ReturnRef(FEED_GLOBAL_MOCK));

    nlohmann::json response;
    auto scanContext = std::make_shared<ScanContext>(
        ScannerType::Package, AGENT_001_MSG, OS_001_MSG, PACKAGES_001_MSG, "{}"_json, response);
    // Mock one vulnerability
    scanContext->m_elements[CVEID] = R"({})"_json;
    scanContext->m_matchConditions[CVEID] = {"1.0.0", MatchRuleCondition::Equal};
    scanContext->m_vulnerabilitySource = {"nvd", "nvd"};

    TResponseBuilder<MockDatabaseFeedManager, ScanContext> responseBuilder(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(responseBuilder.handleRequest(scanContext));

    EXPECT_EQ(response.size(), 1);

    auto& elementData = *response.begin();

    EXPECT_STREQ(elementData.at("category").get_ref<const std::string&>().c_str(), "Packages");
    EXPECT_STREQ(
        elementData.at("classification").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->classification()->c_str());
    EXPECT_STREQ(
        elementData.at("description").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->description()->c_str());
    EXPECT_STREQ(elementData.at("enumeration").get_ref<const std::string&>().c_str(), "CVE");
    EXPECT_STREQ(elementData.at("id").get_ref<const std::string&>().c_str(), CVEID.c_str());
    EXPECT_STREQ(
        elementData.at("reference").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->reference()->c_str());
    EXPECT_DOUBLE_EQ(
        elementData.at("score").at("base").get_ref<const double&>(),
        base::utils::numeric::floatToDoubleRound(
            NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->scoreBase(), 2));
    EXPECT_STREQ(
        elementData.at("score").at("version").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->scoreVersion()->c_str());
    EXPECT_STREQ(
        elementData.at("severity").get_ref<const std::string&>().c_str(),
        base::utils::string::toSentenceCase(
            NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->severity()->str())
            .c_str());
    EXPECT_STREQ(
        elementData.at("published_at").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->datePublished()->c_str());
    EXPECT_TRUE(elementData.at("detected_at").get_ref<const std::string&>() <= base::utils::time::getCurrentISO8601());
    EXPECT_STREQ(elementData.at("source").get_ref<const std::string&>().c_str(),
                 spDatabaseFeedManagerMock->vendorsMap()
                     .at("adp_descriptions")
                     .at(scanContext->m_vulnerabilitySource.first)
                     .at("adp")
                     .get_ref<const std::string&>()
                     .c_str());
    EXPECT_FALSE(elementData.at("under_evaluation").get_ref<const bool&>());
}

TEST_F(ResponseBuilderTest, TestEmptyResponse)
{
    nlohmann::json response;
    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    auto scanContext = std::make_shared<ScanContext>(
        ScannerType::Package, AGENT_001_MSG, OS_001_MSG, PACKAGES_001_MSG, "{}"_json, response);

    TResponseBuilder<MockDatabaseFeedManager, ScanContext> responseBuilder(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(responseBuilder.handleRequest(scanContext));

    EXPECT_TRUE(response.empty());
}

TEST_F(ResponseBuilderTest, TestEmptyItemID)
{
    nlohmann::json response;
    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    auto scanContext = std::make_shared<ScanContext>(
        ScannerType::Package, AGENT_001_MSG, OS_001_MSG, PACKAGES_EMPTY_ITEM_ID_001_MSG, "{}"_json, response);

    TResponseBuilder<MockDatabaseFeedManager, ScanContext> responseBuilder(spDatabaseFeedManagerMock);
    scanContext->m_elements[CVEID] = R"({})"_json;
    EXPECT_ANY_THROW(responseBuilder.handleRequest(scanContext));
}

TEST_F(ResponseBuilderTest, TestNoItemID)
{
    nlohmann::json response;
    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    auto scanContext = std::make_shared<ScanContext>(
        ScannerType::Package, AGENT_001_MSG, OS_001_MSG, PACKAGES_NO_ITEM_ID_001_MSG, "{}"_json, response);

    TResponseBuilder<MockDatabaseFeedManager, ScanContext> responseBuilder(spDatabaseFeedManagerMock);
    scanContext->m_elements[CVEID] = R"({})"_json;
    EXPECT_ANY_THROW(responseBuilder.handleRequest(scanContext));
}

TEST_F(ResponseBuilderTest, TestSuccessfulOSResponseCVSS3)
{
    flatbuffers::FlatBufferBuilder fbBuilder;
    auto vulnerabilityDescriptionData =
        NSVulnerabilityScanner::CreateVulnerabilityDescriptionDirect(fbBuilder,
                                                                     "accessComplexity_test_string",
                                                                     "assignerShortName_test_string",
                                                                     "attackVector_test_string",
                                                                     "authentication_test_string",
                                                                     "availabilityImpact_test_string",
                                                                     "classification_test_string",
                                                                     "confidentialityImpact_test_string",
                                                                     "cweId_test_string",
                                                                     "datePublished_test_string",
                                                                     "dateUpdated_test_string",
                                                                     "description_test_string",
                                                                     "integrityImpact_test_string",
                                                                     "privilegesRequired_test_string",
                                                                     "reference_test_string",
                                                                     "scope_test_string",
                                                                     8.3,
                                                                     "3",
                                                                     "severity_test_string",
                                                                     "userInteraction_test_string");
    fbBuilder.Finish(vulnerabilityDescriptionData);

    auto mockgetVulnerabilityDescriptiveInformation =
        [&](const std::string& cveId,
            const std::string& subShortName,
            FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer) -> bool
    {
        rocksdb::Slice value(reinterpret_cast<const char*>(fbBuilder.GetBufferPointer()), fbBuilder.GetSize());
        resultContainer.data = const_cast<NSVulnerabilityScanner::VulnerabilityDescription*>(
            NSVulnerabilityScanner::GetVulnerabilityDescription(value.data()));

        return true;
    };

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilityDescriptiveInformation(_, _, _))
        .WillRepeatedly(testing::Invoke(mockgetVulnerabilityDescriptiveInformation));
    EXPECT_CALL(*spDatabaseFeedManagerMock, vendorsMap()).WillRepeatedly(testing::ReturnRef(FEED_GLOBAL_MOCK));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Os, AGENT_001_MSG, OS_001_MSG, "{}"_json, "{}"_json, response);
    // Mock one vulnerability
    scanContext->m_elements[CVEID] = R"({})"_json;
    scanContext->m_matchConditions[CVEID] = {"1.0.0", MatchRuleCondition::Equal};

    TResponseBuilder<MockDatabaseFeedManager, ScanContext> responseBuilder(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(responseBuilder.handleRequest(scanContext));

    EXPECT_EQ(response.size(), 1);

    auto& elementData = *response.begin();

    EXPECT_STREQ(elementData.at("category").get_ref<const std::string&>().c_str(), "OS");
    EXPECT_STREQ(
        elementData.at("classification").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->classification()->c_str());
    EXPECT_STREQ(
        elementData.at("description").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->description()->c_str());
    EXPECT_STREQ(elementData.at("enumeration").get_ref<const std::string&>().c_str(), "CVE");
    EXPECT_STREQ(elementData.at("id").get_ref<const std::string&>().c_str(), CVEID.c_str());
    EXPECT_STREQ(
        elementData.at("reference").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->reference()->c_str());
    EXPECT_DOUBLE_EQ(
        elementData.at("score").at("base").get_ref<const double&>(),
        base::utils::numeric::floatToDoubleRound(
            NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->scoreBase(), 2));
    EXPECT_STREQ(
        elementData.at("score").at("version").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->scoreVersion()->c_str());
    EXPECT_STREQ(
        elementData.at("severity").get_ref<const std::string&>().c_str(),
        base::utils::string::toSentenceCase(
            NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->severity()->str())
            .c_str());
    EXPECT_STREQ(
        elementData.at("published_at").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->datePublished()->c_str());
    EXPECT_TRUE(elementData.at("detected_at").get_ref<const std::string&>() <= base::utils::time::getCurrentISO8601());
    EXPECT_STREQ(elementData.at("source").get_ref<const std::string&>().c_str(),
                 spDatabaseFeedManagerMock->vendorsMap()
                     .at("adp_descriptions")
                     .at(scanContext->m_vulnerabilitySource.first)
                     .at("adp")
                     .get_ref<const std::string&>()
                     .c_str());
    EXPECT_FALSE(elementData.at("under_evaluation").get_ref<const bool&>());
}

TEST_F(ResponseBuilderTest, TestSuccessfulPackageResponseNonDefaultCna)
{
    flatbuffers::FlatBufferBuilder fbBuilder;
    auto vulnerabilityDescriptionData =
        NSVulnerabilityScanner::CreateVulnerabilityDescriptionDirect(fbBuilder,
                                                                     "accessComplexity_test_string",
                                                                     "assignerShortName_test_string",
                                                                     "attackVector_test_string",
                                                                     "authentication_test_string",
                                                                     "availabilityImpact_test_string",
                                                                     "classification_test_string",
                                                                     "confidentialityImpact_test_string",
                                                                     "cweId_test_string",
                                                                     "datePublished_test_string",
                                                                     "dateUpdated_test_string",
                                                                     "description_test_string",
                                                                     "integrityImpact_test_string",
                                                                     "privilegesRequired_test_string",
                                                                     "reference_test_string",
                                                                     "scope_test_string",
                                                                     8.3,
                                                                     "3",
                                                                     "severity_test_string",
                                                                     "userInteraction_test_string");
    fbBuilder.Finish(vulnerabilityDescriptionData);

    auto mockgetVulnerabilityDescriptiveInformation =
        [&](const std::string& cveId,
            const std::string& subShortName,
            FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer) -> bool
    {
        rocksdb::Slice value(reinterpret_cast<const char*>(fbBuilder.GetBufferPointer()), fbBuilder.GetSize());
        resultContainer.data = const_cast<NSVulnerabilityScanner::VulnerabilityDescription*>(
            NSVulnerabilityScanner::GetVulnerabilityDescription(value.data()));

        return true;
    };

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilityDescriptiveInformation(_, _, _))
        .WillRepeatedly(testing::Invoke(mockgetVulnerabilityDescriptiveInformation));
    EXPECT_CALL(*spDatabaseFeedManagerMock, vendorsMap()).WillRepeatedly(testing::ReturnRef(FEED_GLOBAL_MOCK));

    nlohmann::json response;
    auto scanContext = std::make_shared<ScanContext>(
        ScannerType::Package, AGENT_001_MSG, OS_001_MSG, PACKAGES_001_MSG, "{}"_json, response);
    // Mock one vulnerability
    scanContext->m_elements[CVEID] = R"({})"_json;
    scanContext->m_matchConditions[CVEID] = {"1.0.0", MatchRuleCondition::Equal};
    scanContext->m_vulnerabilitySource = {"redhat", "redhat"};

    TResponseBuilder<MockDatabaseFeedManager, ScanContext> responseBuilder(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(responseBuilder.handleRequest(scanContext));

    EXPECT_EQ(response.size(), 1);

    auto& elementData = *response.begin();

    EXPECT_STREQ(elementData.at("category").get_ref<const std::string&>().c_str(), "Packages");
    EXPECT_STREQ(
        elementData.at("classification").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->classification()->c_str());
    EXPECT_STREQ(
        elementData.at("description").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->description()->c_str());
    EXPECT_STREQ(elementData.at("enumeration").get_ref<const std::string&>().c_str(), "CVE");
    EXPECT_STREQ(elementData.at("id").get_ref<const std::string&>().c_str(), CVEID.c_str());
    EXPECT_STREQ(
        elementData.at("reference").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->reference()->c_str());
    EXPECT_DOUBLE_EQ(
        elementData.at("score").at("base").get_ref<const double&>(),
        base::utils::numeric::floatToDoubleRound(
            NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->scoreBase(), 2));
    EXPECT_STREQ(
        elementData.at("score").at("version").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->scoreVersion()->c_str());
    EXPECT_STREQ(
        elementData.at("severity").get_ref<const std::string&>().c_str(),
        base::utils::string::toSentenceCase(
            NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->severity()->str())
            .c_str());
    EXPECT_STREQ(
        elementData.at("published_at").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->datePublished()->c_str());
    EXPECT_TRUE(elementData.at("detected_at").get_ref<const std::string&>() <= base::utils::time::getCurrentISO8601());
    EXPECT_STREQ(elementData.at("source").get_ref<const std::string&>().c_str(),
                 spDatabaseFeedManagerMock->vendorsMap()
                     .at("adp_descriptions")
                     .at(scanContext->m_vulnerabilitySource.first)
                     .at("adp")
                     .get_ref<const std::string&>()
                     .c_str());
    EXPECT_FALSE(elementData.at("under_evaluation").get_ref<const bool&>());
}

TEST_F(ResponseBuilderTest, TestSuccessfulPackageResponseUnderEvaluation)
{
    flatbuffers::FlatBufferBuilder fbBuilder;
    auto vulnerabilityDescriptionData =
        NSVulnerabilityScanner::CreateVulnerabilityDescriptionDirect(fbBuilder,
                                                                     "accessComplexity_test_string",
                                                                     "assignerShortName_test_string",
                                                                     "attackVector_test_string",
                                                                     "authentication_test_string",
                                                                     "availabilityImpact_test_string",
                                                                     "classification_test_string",
                                                                     "confidentialityImpact_test_string",
                                                                     "cweId_test_string",
                                                                     "datePublished_test_string",
                                                                     "dateUpdated_test_string",
                                                                     "description_test_string",
                                                                     "integrityImpact_test_string",
                                                                     "privilegesRequired_test_string",
                                                                     "reference_test_string",
                                                                     "scope_test_string",
                                                                     0,
                                                                     "3",
                                                                     "severity_test_string",
                                                                     "userInteraction_test_string");
    fbBuilder.Finish(vulnerabilityDescriptionData);

    auto mockgetVulnerabilityDescriptiveInformation =
        [&](const std::string& cveId,
            const std::string& subShortName,
            FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer) -> bool
    {
        rocksdb::Slice value(reinterpret_cast<const char*>(fbBuilder.GetBufferPointer()), fbBuilder.GetSize());
        resultContainer.data = const_cast<NSVulnerabilityScanner::VulnerabilityDescription*>(
            NSVulnerabilityScanner::GetVulnerabilityDescription(value.data()));

        return true;
    };

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilityDescriptiveInformation(_, _, _))
        .WillRepeatedly(testing::Invoke(mockgetVulnerabilityDescriptiveInformation));
    EXPECT_CALL(*spDatabaseFeedManagerMock, vendorsMap()).WillRepeatedly(testing::ReturnRef(FEED_GLOBAL_MOCK));

    nlohmann::json response;
    auto scanContext = std::make_shared<ScanContext>(
        ScannerType::Package, AGENT_001_MSG, OS_001_MSG, PACKAGES_001_MSG, "{}"_json, response);
    // Mock one vulnerability
    scanContext->m_elements[CVEID] = R"({})"_json;
    scanContext->m_matchConditions[CVEID] = {"1.0.0", MatchRuleCondition::Equal};
    scanContext->m_vulnerabilitySource = {"redhat", "redhat"};

    TResponseBuilder<MockDatabaseFeedManager, ScanContext> responseBuilder(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(responseBuilder.handleRequest(scanContext));

    EXPECT_EQ(response.size(), 1);

    auto& elementData = *response.begin();

    EXPECT_STREQ(elementData.at("category").get_ref<const std::string&>().c_str(), "Packages");
    EXPECT_STREQ(
        elementData.at("classification").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->classification()->c_str());
    EXPECT_STREQ(
        elementData.at("description").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->description()->c_str());
    EXPECT_STREQ(elementData.at("enumeration").get_ref<const std::string&>().c_str(), "CVE");
    EXPECT_STREQ(elementData.at("id").get_ref<const std::string&>().c_str(), CVEID.c_str());
    EXPECT_STREQ(
        elementData.at("reference").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->reference()->c_str());
    EXPECT_DOUBLE_EQ(elementData.at("score").at("base").get_ref<const double&>(), -1);
    EXPECT_STREQ(
        elementData.at("score").at("version").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->scoreVersion()->c_str());
    EXPECT_STREQ(
        elementData.at("severity").get_ref<const std::string&>().c_str(),
        base::utils::string::toSentenceCase(
            NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->severity()->str())
            .c_str());
    EXPECT_STREQ(
        elementData.at("published_at").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->datePublished()->c_str());
    EXPECT_TRUE(elementData.at("detected_at").get_ref<const std::string&>() <= base::utils::time::getCurrentISO8601());
    EXPECT_STREQ(elementData.at("source").get_ref<const std::string&>().c_str(),
                 spDatabaseFeedManagerMock->vendorsMap()
                     .at("adp_descriptions")
                     .at(scanContext->m_vulnerabilitySource.first)
                     .at("adp")
                     .get_ref<const std::string&>()
                     .c_str());
    EXPECT_TRUE(elementData.at("under_evaluation").get_ref<const bool&>());
}

TEST_F(ResponseBuilderTest, TestSuccessfulPackageResponseDefaultValues)
{
    flatbuffers::FlatBufferBuilder fbBuilder;
    auto vulnerabilityDescriptionData =
        NSVulnerabilityScanner::CreateVulnerabilityDescriptionDirect(fbBuilder,
                                                                     "accessComplexity_test_string",
                                                                     "assignerShortName_test_string",
                                                                     "attackVector_test_string",
                                                                     "authentication_test_string",
                                                                     "availabilityImpact_test_string",
                                                                     "",
                                                                     "confidentialityImpact_test_string",
                                                                     "cweId_test_string",
                                                                     "datePublished_test_string",
                                                                     "dateUpdated_test_string",
                                                                     "description_test_string",
                                                                     "integrityImpact_test_string",
                                                                     "privilegesRequired_test_string",
                                                                     "reference_test_string",
                                                                     "scope_test_string",
                                                                     0,
                                                                     "",
                                                                     "",
                                                                     "userInteraction_test_string");
    fbBuilder.Finish(vulnerabilityDescriptionData);

    auto mockgetVulnerabilityDescriptiveInformation =
        [&](const std::string& cveId,
            const std::string& subShortName,
            FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer) -> bool
    {
        rocksdb::Slice value(reinterpret_cast<const char*>(fbBuilder.GetBufferPointer()), fbBuilder.GetSize());
        resultContainer.data = const_cast<NSVulnerabilityScanner::VulnerabilityDescription*>(
            NSVulnerabilityScanner::GetVulnerabilityDescription(value.data()));

        return true;
    };

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilityDescriptiveInformation(_, _, _))
        .WillRepeatedly(testing::Invoke(mockgetVulnerabilityDescriptiveInformation));
    EXPECT_CALL(*spDatabaseFeedManagerMock, vendorsMap()).WillRepeatedly(testing::ReturnRef(FEED_GLOBAL_MOCK));

    nlohmann::json response;
    auto scanContext = std::make_shared<ScanContext>(
        ScannerType::Package, AGENT_001_MSG, OS_001_MSG, PACKAGES_001_MSG, "{}"_json, response);
    // Mock one vulnerability
    scanContext->m_elements[CVEID] = R"({})"_json;
    scanContext->m_matchConditions[CVEID] = {"1.0.0", MatchRuleCondition::Equal};
    scanContext->m_vulnerabilitySource = {"redhat", "redhat"};

    TResponseBuilder<MockDatabaseFeedManager, ScanContext> responseBuilder(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(responseBuilder.handleRequest(scanContext));

    EXPECT_EQ(response.size(), 1);

    auto& elementData = *response.begin();

    EXPECT_STREQ(elementData.at("category").get_ref<const std::string&>().c_str(), "Packages");
    EXPECT_STREQ(elementData.at("classification").get_ref<const std::string&>().c_str(), "-");
    EXPECT_STREQ(
        elementData.at("description").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->description()->c_str());
    EXPECT_STREQ(elementData.at("enumeration").get_ref<const std::string&>().c_str(), "CVE");
    EXPECT_STREQ(elementData.at("id").get_ref<const std::string&>().c_str(), CVEID.c_str());
    EXPECT_STREQ(
        elementData.at("reference").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->reference()->c_str());
    EXPECT_DOUBLE_EQ(elementData.at("score").at("base").get_ref<const double&>(), -1);
    EXPECT_STREQ(elementData.at("score").at("version").get_ref<const std::string&>().c_str(), "-");
    EXPECT_STREQ(elementData.at("severity").get_ref<const std::string&>().c_str(), "-");
    EXPECT_STREQ(
        elementData.at("published_at").get_ref<const std::string&>().c_str(),
        NSVulnerabilityScanner::GetVulnerabilityDescription(fbBuilder.GetBufferPointer())->datePublished()->c_str());
    EXPECT_TRUE(elementData.at("detected_at").get_ref<const std::string&>() <= base::utils::time::getCurrentISO8601());
    EXPECT_STREQ(elementData.at("source").get_ref<const std::string&>().c_str(),
                 spDatabaseFeedManagerMock->vendorsMap()
                     .at("adp_descriptions")
                     .at(scanContext->m_vulnerabilitySource.first)
                     .at("adp")
                     .get_ref<const std::string&>()
                     .c_str());
    EXPECT_TRUE(elementData.at("under_evaluation").get_ref<const bool&>());
}
