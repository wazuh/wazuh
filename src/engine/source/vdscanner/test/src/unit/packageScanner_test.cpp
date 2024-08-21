/*
 * Wazuh Vulnerability Scanner - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 21, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../../../../feedmanager/include/databaseFeedManager.hpp"
#include "../../../src/packageScanner.hpp"
#include "../../../src/scanContext.hpp"
#include "feedmanager/mockDatabaseFeedManager.hpp"
#include <array>
#include <flatbuffers/flatbuffer_builder.h>
#include <flatbuffers/idl.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

using ::testing::_;
class PackageScannerTest : public ::testing::Test
{
protected:
    // LCOV_EXCL_START
    PackageScannerTest() = default;
    ~PackageScannerTest() override = default;

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

namespace NSPackageScannerTest
{
const auto PACKAGES_MSG =
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
            "version": "5.1.9",
            "install_time": "1577890801"
        })"_json;

const auto AGENT_MSG =
    R"({
        "id": "001",
        "ip": "192.168.33.20",
        "name": "focal"
    })"_json;

const auto OS_MSG =
    R"({
            "hostname":"osdata_hostname",
            "architecture":"osdata_architecture",
            "name":"osdata_name",
            "codename":"upstream",
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
const auto PACKAGES_WITHOUT_VENDOR_MSG =
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
            "vendor": " ",
            "version": "5.1.9",
            "install_time": "1577890801"
        })"_json;

const auto PACKAGES_WRONG_VERSION_MSG =
    R"({
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
            "version": "2016",
            "install_time": "1577890801"
        })"_json;

const auto CPE_MAPS = R"***(
        {
            "opensuse-leap": "suse:sles:15",
            "opensuse-tumbleweed": "suse:sles:15",
            "rhel": "redhat:enterprise_linux:$(MAJOR_VERSION)",
            "centos": "redhat:enterprise_linux:$(MAJOR_VERSION)",
            "fedora": "fedoraproject:fedora:$(MAJOR_VERSION)",
            "rocky": "rocky:rocky:$(MAJOR_VERSION)",
            "amzn": "amazon:amazon_linux:$(MAJOR_VERSION)",
            "ol": "oracle:linux:$(MAJOR_VERSION):$(MINOR_VERSION)",
            "sles": "suse:sles:$(VERSION_UPDATE_HYPHEN)",
            "sled": "suse:sled:$(VERSION_UPDATE_HYPHEN)",
            "almalinux": "almalinux:almalinux:$(MAJOR_VERSION)",
            "Microsoft Windows Server 2003": "microsoft:windows_server_2003::$(RELEASE)::::",
            "Microsoft Windows Server 2003 R2": "microsoft:windows_server_2003:r2:$(RELEASE)::::",
            "Microsoft Windows XP": "microsoft:windows_xp::$(RELEASE)::::",
            "Microsoft Windows Vista": "microsoft:windows_vista:$(RELEASE):::::",
            "Microsoft Windows 7": "microsoft:windows_7:$(RELEASE):::::",
            "Microsoft Windows 8": "microsoft:windows_8::::::",
            "Microsoft Windows 8.1": "microsoft:windows_8.1::::::",
            "Microsoft Windows 10": "microsoft:windows_10_$(DISPLAY_VERSION):$(VERSION):::::",
            "Microsoft Windows 11": "microsoft:windows_11_$(DISPLAY_VERSION):$(VERSION):::::",
            "Microsoft Windows Server 2008": "microsoft:windows_server_2008::$(RELEASE)::::",
            "Microsoft Windows Server 2008 R2": "microsoft:windows_server_2008:r2:$(RELEASE)::::",
            "Microsoft Windows Server 2012": "microsoft:windows_server_2012::::::",
            "Microsoft Windows Server 2012 R2": "microsoft:windows_server_2012:r2:::::",
            "Microsoft Windows Server 2012 23H2": "microsoft:windows_server_2022_23h2:*:::::",
            "Microsoft Windows Server 2016": "microsoft:windows_server_2016:$(RELEASE):::::",
            "Microsoft Windows Server 2019": "microsoft:windows_server_2019:$(RELEASE):::::",
            "Microsoft Windows Server 2022": "microsoft:windows_server_2022:$(RELEASE):::::",
            "macOS": "apple:macos:::::"
        })***"_json;

const std::string CANDIDATES_AFFECTED_LESS_THAN_INPUT =
    R"(
            {
                "candidates": [
                    {
                        "cveId": "CVE-2024-1234",
                        "defaultStatus": 0,
                        "platforms": [
                            "upstream"
                        ],
                        "versions": [
                            {
                                "lessThan": "5.2.0",
                                "status": "affected",
                                "version": "0",
                                "versionType": "custom"
                            }
                        ]
                    }
                ]
            }
        )";

const std::string CANDIDATES_AFFECTED_LESS_THAN_INPUT_WITH_GENERIC_VENDOR =
    R"(
            {
                "candidates": [
                    {
                        "cveId": "CVE-2024-1234",
                        "defaultStatus": 0,
                        "platforms": [
                            "upstream"
                        ],
                        "versions": [
                            {
                                "lessThan": "5.2.0",
                                "status": "affected",
                                "version": "0",
                                "versionType": "custom"
                            }
                        ],
                        "vendor" : "testVendor"
                    }
                ]
            }
        )";

const std::string CANDIDATES_AFFECTED_LESS_THAN_INPUT_WITH_UBUNTU_VENDOR =
    R"(
            {
                "candidates": [
                    {
                        "cveId": "CVE-2024-1234",
                        "defaultStatus": 0,
                        "platforms": [
                            "upstream"
                        ],
                        "versions": [
                            {
                                "lessThan": "5.2.0",
                                "status": "affected",
                                "version": "0",
                                "versionType": "custom"
                            }
                        ],
                        "vendor" : "ubuntu developers <ubuntu-devel-discuss@lists.ubuntu.com>"
                    }
                ]
            }
        )";

const std::string CANDIDATES_AFFECTED_LESS_THAN_OR_EQUAL_INPUT =
    R"(
            {
                "candidates": [
                    {
                        "cveId": "CVE-2024-1234",
                        "defaultStatus": 0,
                        "platforms": [
                            "upstream"
                        ],
                        "versions": [
                            {
                                "lessThanOrEqual": "5.2.0",
                                "status": "affected",
                                "version": "0",
                                "versionType": "custom"
                            }
                        ]
                    }
                ]
            }
        )";

const std::string CANDIDATES_AFFECTED_LESS_THAN_WITH_VERSION_NOT_ZERO_INPUT =
    R"(
            {
                "candidates": [
                    {
                        "cveId": "CVE-2024-1234",
                        "defaultStatus": 0,
                        "platforms": [
                            "upstream"
                        ],
                        "versions": [
                            {
                                "lessThan": "5.2.0",
                                "status": "affected",
                                "version": "5.1.0",
                                "versionType": "custom"
                            }
                        ]
                    }
                ]
            }
        )";

const std::string CANDIDATES_UNAFFECTED_LESS_THAN_INPUT =
    R"(
            {
                "candidates": [
                    {
                        "cveId": "CVE-2024-1234",
                        "defaultStatus": 0,
                        "platforms": [
                            "upstream"
                        ],
                        "versions": [
                            {
                                "lessThan": "5.2.0",
                                "status": "unaffected",
                                "version": "0",
                                "versionType": "custom"
                            }
                        ]
                    }
                ]
            }
        )";

const std::string CANDIDATES_AFFECTED_EQUAL_TO_INPUT =
    R"(
            {
                "candidates": [
                    {
                        "cveId": "CVE-2024-1234",
                        "defaultStatus": 0,
                        "platforms": [
                            "upstream"
                        ],
                        "versions": [
                            {
                                "status": "affected",
                                "version": "5.1.9",
                                "versionType": "custom"
                            }
                        ]
                    }
                ]
            }
        )";

const std::string CANDIDATES_UNAFFECTED_EQUAL_TO_INPUT =
    R"(
            {
                "candidates": [
                    {
                        "cveId": "CVE-2024-1234",
                        "defaultStatus": 0,
                        "platforms": [
                            "upstream"
                        ],
                        "versions": [
                            {
                                "status": "unaffected",
                                "version": "5.1.9",
                                "versionType": "custom"
                            }
                        ]
                    }
                ]
            }
        )";

const std::string CANDIDATES_DEFAULT_STATUS_AFFECTED_INPUT =
    R"(
            {
                "candidates": [
                    {
                        "cveId": "CVE-2024-1234",
                        "defaultStatus": 0,
                        "platforms": [
                            "upstream"
                        ],
                        "versions": [
                            {
                                "lessThan": "5.1.0",
                                "status": "affected",
                                "version": "0",
                                "versionType": "custom"
                            }
                        ]
                    }
                ]
            }
        )";

const std::string CANDIDATES_DEFAULT_STATUS_UNAFFECTED_INPUT =
    R"(
            {
                "candidates": [
                    {
                        "cveId": "CVE-2024-1234",
                        "defaultStatus": 1,
                        "platforms": [
                            "upstream"
                        ],
                        "versions": [
                            {
                                "lessThan": "5.1.0",
                                "status": "affected",
                                "version": "0",
                                "versionType": "custom"
                            }
                        ]
                    }
                ]
            }
        )";

const std::vector<const char*> INCLUDE_DIRECTORIES = {FLATBUFFER_SCHEMAS_DIR, nullptr};

const std::string CANDIDATES_FLATBUFFER_SCHEMA_PATH {std::string(FLATBUFFER_SCHEMAS_DIR)
                                                     + "/vulnerabilityCandidate.fbs"};

const std::string CVEID {"CVE-2024-1234"};

const nlohmann::json CNA_MAPPINGS = R"***(
    {
      "cnaMapping": {
        "alas": "alas_$(MAJOR_VERSION)",
        "alma": "alma_$(MAJOR_VERSION)",
        "redhat": "redhat_$(MAJOR_VERSION)",
        "suse": "$(PLATFORM)_$(MAJOR_VERSION)"
      },
      "majorVersionEquivalence": {
        "amzn": {
          "2018": "1"
        }
      },
      "platformEquivalence": {
        "sled": "suse_desktop",
        "sles": "suse_server"
      }
    }
    )***"_json;

} // namespace NSPackageScannerTest

using namespace NSPackageScannerTest;

void PackageScannerTest::SetUp()
{
    logging::testInit();
}

void PackageScannerTest::TearDown()
{
    // This method is empty because there is no teardown logic needed for this test case.
}

TEST_F(PackageScannerTest, TestPackageAffectedEqualTo)
{
    auto mockGetVulnerabilitiesCandidates =
        [&](const std::string& cnaName,
            const PackageData& package,
            const std::function<bool(const std::string& cnaName,
                                     const PackageData& package,
                                     const NSVulnerabilityScanner::ScanVulnerabilityCandidate&)>& callback)
    {
        std::string candidatesFlatbufferSchemaStr;

        // Read schemas from filesystem.
        bool valid =
            flatbuffers::LoadFile(CANDIDATES_FLATBUFFER_SCHEMA_PATH.c_str(), false, &candidatesFlatbufferSchemaStr);
        ASSERT_EQ(valid, true);

        // Parse schemas and JSON example.
        flatbuffers::Parser fbParser;
        const char* includeDirectories[] = {INCLUDE_DIRECTORIES[0], INCLUDE_DIRECTORIES[1]};
        valid = (fbParser.Parse(candidatesFlatbufferSchemaStr.c_str(), includeDirectories)
                 && fbParser.Parse(CANDIDATES_AFFECTED_EQUAL_TO_INPUT.c_str()));
        ASSERT_EQ(valid, true);

        auto candidatesArray = NSVulnerabilityScanner::GetScanVulnerabilityCandidateArray(
            reinterpret_cast<const uint8_t*>(fbParser.builder_.GetBufferPointer()));

        if (candidatesArray)
        {
            for (const auto& candidate : *candidatesArray->candidates())
            {
                if (callback(cnaName, package, *candidate))
                {
                    // If the candidate is vulnerable, we stop looking for.
                    break;
                }
            }
        }
    };
    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("cnaName"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates(_, _, _))
        .WillOnce(testing::Invoke(mockGetVulnerabilitiesCandidates));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));
    EXPECT_CALL(*spDatabaseFeedManagerMock, cpeMappings()).WillOnce(testing::ReturnRef(CPE_MAPS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));

    ASSERT_TRUE(scanContext != nullptr);

    EXPECT_EQ(scanContext->m_elements.size(), 1);
    EXPECT_NE(scanContext->m_elements.find(CVEID), scanContext->m_elements.end());

    EXPECT_EQ(scanContext->m_matchConditions.size(), 1);
    EXPECT_NE(scanContext->m_matchConditions.find(CVEID), scanContext->m_matchConditions.end());

    const auto& matchCondition = scanContext->m_matchConditions[CVEID];
    EXPECT_EQ(matchCondition.condition, MatchRuleCondition::Equal);
    EXPECT_STREQ(matchCondition.version.c_str(), "5.1.9");
}

TEST_F(PackageScannerTest, TestPackageUnaffectedEqualTo)
{
    auto mockGetVulnerabilitiesCandidates =
        [&](const std::string& cnaName,
            const PackageData& package,
            const std::function<bool(const std::string& cnaName,
                                     const PackageData& package,
                                     const NSVulnerabilityScanner::ScanVulnerabilityCandidate&)>& callback)
    {
        std::string candidatesFlatbufferSchemaStr;

        // Read schemas from filesystem.
        bool valid =
            flatbuffers::LoadFile(CANDIDATES_FLATBUFFER_SCHEMA_PATH.c_str(), false, &candidatesFlatbufferSchemaStr);
        ASSERT_EQ(valid, true);

        // Parse schemas and JSON example.
        flatbuffers::Parser fbParser;
        std::array<const char*, 2> includeDirectories = {INCLUDE_DIRECTORIES[0], INCLUDE_DIRECTORIES[1]};
        valid = (fbParser.Parse(candidatesFlatbufferSchemaStr.c_str(), includeDirectories.data())
                 && fbParser.Parse(CANDIDATES_UNAFFECTED_EQUAL_TO_INPUT.c_str()));
        ASSERT_EQ(valid, true);

        auto candidatesArray = NSVulnerabilityScanner::GetScanVulnerabilityCandidateArray(
            reinterpret_cast<const uint8_t*>(fbParser.builder_.GetBufferPointer()));

        if (candidatesArray)
        {
            for (const auto& candidate : *candidatesArray->candidates())
            {
                if (callback(cnaName, package, *candidate))
                {
                    // If the candidate is vulnerable, we stop looking for.
                    break;
                }
            }
        }
    };

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("cnaName"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates(_, _, _))
        .WillOnce(testing::Invoke(mockGetVulnerabilitiesCandidates));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));
    EXPECT_CALL(*spDatabaseFeedManagerMock, cpeMappings()).WillOnce(testing::ReturnRef(CPE_MAPS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));

    EXPECT_TRUE(scanContext->m_elements.empty());
}

TEST_F(PackageScannerTest, TestPackageAffectedLessThan)
{
    auto mockGetVulnerabilitiesCandidates =
        [&](const std::string& cnaName,
            const PackageData& package,
            const std::function<bool(const std::string& cnaName,
                                     const PackageData& package,
                                     const NSVulnerabilityScanner::ScanVulnerabilityCandidate&)>& callback)
    {
        std::string candidatesFlatbufferSchemaStr;

        // Read schemas from filesystem.
        bool valid =
            flatbuffers::LoadFile(CANDIDATES_FLATBUFFER_SCHEMA_PATH.c_str(), false, &candidatesFlatbufferSchemaStr);
        ASSERT_EQ(valid, true);

        // Parse schemas and JSON example.
        flatbuffers::Parser fbParser;
        std::vector<const char*> includeDirectories = {INCLUDE_DIRECTORIES[0], INCLUDE_DIRECTORIES[1]};
        valid = (fbParser.Parse(candidatesFlatbufferSchemaStr.c_str(), includeDirectories.data())
                 && fbParser.Parse(CANDIDATES_AFFECTED_LESS_THAN_INPUT.c_str()));
        ASSERT_EQ(valid, true);

        auto candidatesArray = NSVulnerabilityScanner::GetScanVulnerabilityCandidateArray(
            reinterpret_cast<const uint8_t*>(fbParser.builder_.GetBufferPointer()));

        if (candidatesArray)
        {
            for (const auto& candidate : *candidatesArray->candidates())
            {
                if (callback(cnaName, package, *candidate))
                {
                    // If the candidate is vulnerable, we stop looking for.
                    break;
                }
            }
        }
    };

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("cnaName"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates(_, _, _))
        .WillOnce(testing::Invoke(mockGetVulnerabilitiesCandidates));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));
    EXPECT_CALL(*spDatabaseFeedManagerMock, cpeMappings()).WillOnce(testing::ReturnRef(CPE_MAPS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));

    ASSERT_TRUE(scanContext != nullptr);

    EXPECT_EQ(scanContext->m_elements.size(), 1);
    EXPECT_NE(scanContext->m_elements.find(CVEID), scanContext->m_elements.end());

    EXPECT_EQ(scanContext->m_matchConditions.size(), 1);
    EXPECT_NE(scanContext->m_matchConditions.find(CVEID), scanContext->m_matchConditions.end());

    const auto& matchCondition = scanContext->m_matchConditions[CVEID];
    EXPECT_EQ(matchCondition.condition, MatchRuleCondition::LessThan);
    EXPECT_STREQ(matchCondition.version.c_str(), "5.2.0");
}

TEST_F(PackageScannerTest, TestPackageAffectedLessThanVendorMissing)
{
    auto mockGetVulnerabilitiesCandidates =
        [&](const std::string& cnaName,
            const PackageData& package,
            const std::function<bool(const std::string& cnaName,
                                     const PackageData& package,
                                     const NSVulnerabilityScanner::ScanVulnerabilityCandidate&)>& callback)
    {
        std::string candidatesFlatbufferSchemaStr;

        // Read schemas from filesystem.
        bool valid =
            flatbuffers::LoadFile(CANDIDATES_FLATBUFFER_SCHEMA_PATH.c_str(), false, &candidatesFlatbufferSchemaStr);
        ASSERT_EQ(valid, true);

        // Parse schemas and JSON example.
        flatbuffers::Parser fbParser;
        const char* includeDirectories[] = {INCLUDE_DIRECTORIES[0], INCLUDE_DIRECTORIES[1]};
        valid = (fbParser.Parse(candidatesFlatbufferSchemaStr.c_str(), &includeDirectories[0])
                 && fbParser.Parse(CANDIDATES_AFFECTED_LESS_THAN_INPUT_WITH_UBUNTU_VENDOR.c_str()));
        ASSERT_EQ(valid, true);

        auto candidatesArray = NSVulnerabilityScanner::GetScanVulnerabilityCandidateArray(
            reinterpret_cast<const uint8_t*>(fbParser.builder_.GetBufferPointer()));

        if (candidatesArray)
        {
            for (const auto& candidate : *candidatesArray->candidates())
            {
                if (callback(cnaName, package, *candidate))
                {
                    // If the candidate is vulnerable, we stop looking for.
                    break;
                }
            }
        }
    };

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("cnaName"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates(_, _, _))
        .WillOnce(testing::Invoke(mockGetVulnerabilitiesCandidates));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext = std::make_shared<ScanContext>(
        ScannerType::Package, AGENT_MSG, OS_MSG, PACKAGES_WITHOUT_VENDOR_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));
    EXPECT_CALL(*spDatabaseFeedManagerMock, cpeMappings()).WillOnce(testing::ReturnRef(CPE_MAPS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));

    ASSERT_TRUE(scanContext->m_elements.empty());
}

TEST_F(PackageScannerTest, TestPackageAffectedLessThanVendorMismatch)
{
    auto mockGetVulnerabilitiesCandidates =
        [&](const std::string& cnaName,
            const PackageData& package,
            const std::function<bool(const std::string& cnaName,
                                     const PackageData& package,
                                     const NSVulnerabilityScanner::ScanVulnerabilityCandidate&)>& callback)
    {
        std::string candidatesFlatbufferSchemaStr;

        // Read schemas from filesystem.
        bool valid =
            flatbuffers::LoadFile(CANDIDATES_FLATBUFFER_SCHEMA_PATH.c_str(), false, &candidatesFlatbufferSchemaStr);
        ASSERT_EQ(valid, true);

        // Parse schemas and JSON example.
        flatbuffers::Parser fbParser;
        std::array<const char*, 2> includeDirectories = {INCLUDE_DIRECTORIES[0], INCLUDE_DIRECTORIES[1]};
        valid = (fbParser.Parse(candidatesFlatbufferSchemaStr.c_str(), includeDirectories.data())
                 && fbParser.Parse(CANDIDATES_AFFECTED_LESS_THAN_INPUT_WITH_GENERIC_VENDOR.c_str()));
        ASSERT_EQ(valid, true);

        auto candidatesArray = NSVulnerabilityScanner::GetScanVulnerabilityCandidateArray(
            reinterpret_cast<const uint8_t*>(fbParser.builder_.GetBufferPointer()));

        if (candidatesArray)
        {
            for (const auto& candidate : *candidatesArray->candidates())
            {
                if (callback(cnaName, package, *candidate))
                {
                    // If the candidate is vulnerable, we stop looking for.
                    break;
                }
            }
        }
    };

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("cnaName"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates(_, _, _))
        .WillOnce(testing::Invoke(mockGetVulnerabilitiesCandidates));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));
    EXPECT_CALL(*spDatabaseFeedManagerMock, cpeMappings()).WillOnce(testing::ReturnRef(CPE_MAPS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));

    ASSERT_TRUE(scanContext->m_elements.empty());
}

TEST_F(PackageScannerTest, TestPackageAffectedLessThanVendorMatch)
{
    auto mockGetVulnerabilitiesCandidates =
        [&](const std::string& cnaName,
            const PackageData& package,
            const std::function<bool(const std::string& cnaName,
                                     const PackageData& package,
                                     const NSVulnerabilityScanner::ScanVulnerabilityCandidate&)>& callback)
    {
        std::string candidatesFlatbufferSchemaStr;

        // Read schemas from filesystem.
        bool valid =
            flatbuffers::LoadFile(CANDIDATES_FLATBUFFER_SCHEMA_PATH.c_str(), false, &candidatesFlatbufferSchemaStr);
        ASSERT_EQ(valid, true);

        // Parse schemas and JSON example.
        flatbuffers::Parser fbParser;
        std::array<const char*, 2> includeDirectories = {INCLUDE_DIRECTORIES[0], INCLUDE_DIRECTORIES[1]};
        valid = (fbParser.Parse(candidatesFlatbufferSchemaStr.c_str(), includeDirectories.data())
                 && fbParser.Parse(CANDIDATES_AFFECTED_LESS_THAN_INPUT_WITH_UBUNTU_VENDOR.c_str()));
        ASSERT_EQ(valid, true);

        auto candidatesArray = NSVulnerabilityScanner::GetScanVulnerabilityCandidateArray(
            reinterpret_cast<const uint8_t*>(fbParser.builder_.GetBufferPointer()));

        if (candidatesArray)
        {
            for (const auto& candidate : *candidatesArray->candidates())
            {
                if (callback(cnaName, package, *candidate))
                {
                    // If the candidate is vulnerable, we stop looking for.
                    break;
                }
            }
        }
    };

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("cnaName"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates(_, _, _))
        .WillOnce(testing::Invoke(mockGetVulnerabilitiesCandidates));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));
    EXPECT_CALL(*spDatabaseFeedManagerMock, cpeMappings()).WillOnce(testing::ReturnRef(CPE_MAPS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));

    ASSERT_TRUE(scanContext != nullptr);

    EXPECT_EQ(scanContext->m_elements.size(), 1);
    EXPECT_NE(scanContext->m_elements.find(CVEID), scanContext->m_elements.end());

    EXPECT_EQ(scanContext->m_matchConditions.size(), 1);
    EXPECT_NE(scanContext->m_matchConditions.find(CVEID), scanContext->m_matchConditions.end());

    auto& matchCondition = scanContext->m_matchConditions[CVEID];
    EXPECT_EQ(matchCondition.condition, MatchRuleCondition::LessThan);
    EXPECT_STREQ(matchCondition.version.c_str(), "5.2.0");
}

TEST_F(PackageScannerTest, TestPackageAffectedLessThanOrEqual)
{
    auto mockGetVulnerabilitiesCandidates =
        [&](const std::string& cnaName,
            const PackageData& package,
            const std::function<bool(const std::string& cnaName,
                                     const PackageData& package,
                                     const NSVulnerabilityScanner::ScanVulnerabilityCandidate&)>& callback)
    {
        std::string candidatesFlatbufferSchemaStr;

        // Read schemas from filesystem.
        bool valid =
            flatbuffers::LoadFile(CANDIDATES_FLATBUFFER_SCHEMA_PATH.c_str(), false, &candidatesFlatbufferSchemaStr);
        ASSERT_EQ(valid, true);

        // Parse schemas and JSON example.
        flatbuffers::Parser fbParser;
        std::array<const char*, 2> includeDirectories = {INCLUDE_DIRECTORIES[0], INCLUDE_DIRECTORIES[1]};
        valid = (fbParser.Parse(candidatesFlatbufferSchemaStr.c_str(), includeDirectories.data())
                 && fbParser.Parse(CANDIDATES_AFFECTED_LESS_THAN_OR_EQUAL_INPUT.c_str()));
        ASSERT_EQ(valid, true);

        auto candidatesArray = NSVulnerabilityScanner::GetScanVulnerabilityCandidateArray(
            reinterpret_cast<const uint8_t*>(fbParser.builder_.GetBufferPointer()));

        if (candidatesArray)
        {
            for (const auto& candidate : *candidatesArray->candidates())
            {
                if (callback(cnaName, package, *candidate))
                {
                    // If the candidate is vulnerable, we stop looking for.
                    break;
                }
            }
        }
    };

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("cnaName"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates(_, _, _))
        .WillOnce(testing::Invoke(mockGetVulnerabilitiesCandidates));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));
    EXPECT_CALL(*spDatabaseFeedManagerMock, cpeMappings()).WillOnce(testing::ReturnRef(CPE_MAPS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));

    ASSERT_TRUE(scanContext != nullptr);

    EXPECT_EQ(scanContext->m_elements.size(), 1);
    EXPECT_NE(scanContext->m_elements.find(CVEID), scanContext->m_elements.end());

    EXPECT_EQ(scanContext->m_matchConditions.size(), 1);
    EXPECT_NE(scanContext->m_matchConditions.find(CVEID), scanContext->m_matchConditions.end());

    auto& matchCondition = scanContext->m_matchConditions[CVEID];
    EXPECT_EQ(matchCondition.condition, MatchRuleCondition::LessThanOrEqual);
    EXPECT_STREQ(matchCondition.version.c_str(), "5.2.0");
}

TEST_F(PackageScannerTest, TestPackageAffectedLessThanWithVersionNotZero)
{
    auto mockGetVulnerabilitiesCandidates =
        [&](const std::string& cnaName,
            const PackageData& package,
            const std::function<bool(const std::string& cnaName,
                                     const PackageData& package,
                                     const NSVulnerabilityScanner::ScanVulnerabilityCandidate&)>& callback)
    {
        std::string candidatesFlatbufferSchemaStr;

        // Read schemas from filesystem.
        bool valid =
            flatbuffers::LoadFile(CANDIDATES_FLATBUFFER_SCHEMA_PATH.c_str(), false, &candidatesFlatbufferSchemaStr);
        ASSERT_EQ(valid, true);

        // Parse schemas and JSON example.
        flatbuffers::Parser fbParser;
        const char* includeDirectories[] = {INCLUDE_DIRECTORIES[0], INCLUDE_DIRECTORIES[1]};
        valid = (fbParser.Parse(candidatesFlatbufferSchemaStr.c_str(), includeDirectories)
                 && fbParser.Parse(CANDIDATES_AFFECTED_LESS_THAN_WITH_VERSION_NOT_ZERO_INPUT.c_str()));
        ASSERT_EQ(valid, true);

        auto candidatesArray = NSVulnerabilityScanner::GetScanVulnerabilityCandidateArray(
            reinterpret_cast<const uint8_t*>(fbParser.builder_.GetBufferPointer()));

        if (candidatesArray)
        {
            for (const auto& candidate : *candidatesArray->candidates())
            {
                if (callback(cnaName, package, *candidate))
                {
                    // If the candidate is vulnerable, we stop looking for.
                    break;
                }
            }
        }
    };

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("cnaName"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates(_, _, _))
        .WillOnce(testing::Invoke(mockGetVulnerabilitiesCandidates));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));
    EXPECT_CALL(*spDatabaseFeedManagerMock, cpeMappings()).WillOnce(testing::ReturnRef(CPE_MAPS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));

    ASSERT_TRUE(scanContext != nullptr);

    EXPECT_EQ(scanContext->m_elements.size(), 1);
    EXPECT_NE(scanContext->m_elements.find(CVEID), scanContext->m_elements.end());

    EXPECT_EQ(scanContext->m_matchConditions.size(), 1);
    EXPECT_NE(scanContext->m_matchConditions.find(CVEID), scanContext->m_matchConditions.end());

    auto& matchCondition = scanContext->m_matchConditions[CVEID];
    EXPECT_EQ(matchCondition.condition, MatchRuleCondition::LessThan);
    EXPECT_STREQ(matchCondition.version.c_str(), "5.2.0");
}

TEST_F(PackageScannerTest, TestPackageUnaffectedLessThan)
{
    auto mockGetVulnerabilitiesCandidates =
        [&](const std::string& cnaName,
            const PackageData& package,
            const std::function<bool(const std::string& cnaName,
                                     const PackageData& package,
                                     const NSVulnerabilityScanner::ScanVulnerabilityCandidate&)>& callback)
    {
        std::string candidatesFlatbufferSchemaStr;

        // Read schemas from filesystem.
        bool valid =
            flatbuffers::LoadFile(CANDIDATES_FLATBUFFER_SCHEMA_PATH.c_str(), false, &candidatesFlatbufferSchemaStr);
        ASSERT_EQ(valid, true);

        // Parse schemas and JSON example.
        flatbuffers::Parser fbParser;
        const char* includeDirectories[] = {INCLUDE_DIRECTORIES[0], INCLUDE_DIRECTORIES[1]};
        valid = (fbParser.Parse(candidatesFlatbufferSchemaStr.c_str(), includeDirectories)
                 && fbParser.Parse(CANDIDATES_UNAFFECTED_LESS_THAN_INPUT.c_str()));
        ASSERT_EQ(valid, true);

        auto candidatesArray = NSVulnerabilityScanner::GetScanVulnerabilityCandidateArray(
            reinterpret_cast<const uint8_t*>(fbParser.builder_.GetBufferPointer()));

        if (candidatesArray)
        {
            for (const auto& candidate : *candidatesArray->candidates())
            {
                if (callback(cnaName, package, *candidate))
                {
                    // If the candidate is vulnerable, we stop looking for.
                    break;
                }
            }
        }
    };

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("cnaName"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates(_, _, _))
        .WillOnce(testing::Invoke(mockGetVulnerabilitiesCandidates));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));
    EXPECT_CALL(*spDatabaseFeedManagerMock, cpeMappings()).WillOnce(testing::ReturnRef(CPE_MAPS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));

    EXPECT_TRUE(scanContext->m_elements.empty());
}

TEST_F(PackageScannerTest, TestPackageDefaultStatusAffected)
{
    auto mockGetVulnerabilitiesCandidates =
        [&](const std::string& cnaName,
            const PackageData& package,
            const std::function<bool(const std::string& cnaName,
                                     const PackageData& package,
                                     const NSVulnerabilityScanner::ScanVulnerabilityCandidate&)>& callback)
    {
        std::string candidatesFlatbufferSchemaStr;

        // Read schemas from filesystem.
        bool valid =
            flatbuffers::LoadFile(CANDIDATES_FLATBUFFER_SCHEMA_PATH.c_str(), false, &candidatesFlatbufferSchemaStr);
        ASSERT_EQ(valid, true);

        // Parse schemas and JSON example.
        flatbuffers::Parser fbParser;
        const char* includeDirectories[] = {INCLUDE_DIRECTORIES[0], INCLUDE_DIRECTORIES[1]};
        valid = (fbParser.Parse(candidatesFlatbufferSchemaStr.c_str(), includeDirectories)
                 && fbParser.Parse(CANDIDATES_DEFAULT_STATUS_AFFECTED_INPUT.c_str()));
        ASSERT_EQ(valid, true);

        auto candidatesArray = NSVulnerabilityScanner::GetScanVulnerabilityCandidateArray(
            reinterpret_cast<const uint8_t*>(fbParser.builder_.GetBufferPointer()));

        if (candidatesArray)
        {
            for (const auto& candidate : *candidatesArray->candidates())
            {
                if (callback(cnaName, package, *candidate))
                {
                    // If the candidate is vulnerable, we stop looking for.
                    break;
                }
            }
        }
    };

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("cnaName"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates(_, _, _))
        .WillOnce(testing::Invoke(mockGetVulnerabilitiesCandidates));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));
    EXPECT_CALL(*spDatabaseFeedManagerMock, cpeMappings()).WillOnce(testing::ReturnRef(CPE_MAPS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));

    ASSERT_TRUE(scanContext != nullptr);

    EXPECT_EQ(scanContext->m_elements.size(), 1);
    EXPECT_NE(scanContext->m_elements.find(CVEID), scanContext->m_elements.end());

    EXPECT_EQ(scanContext->m_matchConditions.size(), 1);
    EXPECT_NE(scanContext->m_matchConditions.find(CVEID), scanContext->m_matchConditions.end());

    auto& matchCondition = scanContext->m_matchConditions[CVEID];
    EXPECT_EQ(matchCondition.condition, MatchRuleCondition::DefaultStatus);
}

TEST_F(PackageScannerTest, TestPackageDefaultStatusUnaffected)
{
    auto mockGetVulnerabilitiesCandidates =
        [&](const std::string& cnaName,
            const PackageData& package,
            const std::function<bool(const std::string& cnaName,
                                     const PackageData& package,
                                     const NSVulnerabilityScanner::ScanVulnerabilityCandidate&)>& callback)
    {
        std::string candidatesFlatbufferSchemaStr;

        // Read schemas from filesystem.
        bool valid =
            flatbuffers::LoadFile(CANDIDATES_FLATBUFFER_SCHEMA_PATH.c_str(), false, &candidatesFlatbufferSchemaStr);
        ASSERT_EQ(valid, true);

        // Parse schemas and JSON example.
        flatbuffers::Parser fbParser;
        const char* includeDirectories[] = {INCLUDE_DIRECTORIES[0], INCLUDE_DIRECTORIES[1]};
        valid = (fbParser.Parse(candidatesFlatbufferSchemaStr.c_str(), includeDirectories)
                 && fbParser.Parse(CANDIDATES_DEFAULT_STATUS_UNAFFECTED_INPUT.c_str()));
        ASSERT_EQ(valid, true);

        auto candidatesArray = NSVulnerabilityScanner::GetScanVulnerabilityCandidateArray(
            reinterpret_cast<const uint8_t*>(fbParser.builder_.GetBufferPointer()));

        if (candidatesArray)
        {
            for (const auto& candidate : *candidatesArray->candidates())
            {
                if (callback(cnaName, package, *candidate))
                {
                    // If the candidate is vulnerable, we stop looking for.
                    break;
                }
            }
        }
    };

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("cnaName"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates(_, _, _))
        .WillOnce(testing::Invoke(mockGetVulnerabilitiesCandidates));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));
    EXPECT_CALL(*spDatabaseFeedManagerMock, cpeMappings()).WillOnce(testing::ReturnRef(CPE_MAPS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));

    EXPECT_TRUE(scanContext->m_elements.empty());
}

TEST_F(PackageScannerTest, TestPackageGetVulnerabilitiesCandidatesGeneratesException)
{
    auto mockGetVulnerabilitiesCandidates =
        [&](const std::string& cnaName,
            const PackageData& package,
            const std::function<bool(const std::string& cnaName,
                                     const PackageData& package,
                                     const NSVulnerabilityScanner::ScanVulnerabilityCandidate&)>& callback)
    {
        throw std::runtime_error("Invalid package/cna name.");
    };

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("cnaName"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates(_, _, _))
        .WillOnce(testing::Invoke(mockGetVulnerabilitiesCandidates));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));

    EXPECT_TRUE(scanContext->m_elements.empty());
}

TEST_F(PackageScannerTest, TestPackageAffectedEqualToAlma8)
{
    const auto LOCAL_OS_MSG =
        R"({
            "hostname":"osdata_hostname",
            "architecture":"osdata_architecture",
            "name":"osdata_name",
            "codename":"upstream",
            "major_version":"8",
            "minor_version":"osdata_minorVersion",
            "patch":"osdata_patch",
            "build":"osdata_build",
            "platform":"alma",
            "version":"osdata_version",
            "release":"osdata_release",
            "display_version":"osdata_displayVersion",
            "sysname":"osdata_sysName",
            "kernel_version":"osdata_kernelVersion",
            "kernel_release":"osdata_kernelRelease"
    })"_json;

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("alma"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates("alma_8", _, _));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, LOCAL_OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));
}

TEST_F(PackageScannerTest, TestPackageAffectedEqualToAlas1)
{
    const auto LOCAL_OS_MSG =
        R"({
            "hostname":"osdata_hostname",
            "architecture":"osdata_architecture",
            "name":"osdata_name",
            "codename":"upstream",
            "major_version":"2018",
            "minor_version":"osdata_minorVersion",
            "patch":"osdata_patch",
            "build":"osdata_build",
            "platform":"amzn",
            "version":"osdata_version",
            "release":"osdata_release",
            "display_version":"osdata_displayVersion",
            "sysname":"osdata_sysName",
            "kernel_version":"osdata_kernelVersion",
            "kernel_release":"osdata_kernelRelease"
    })"_json;

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("alas"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates("alas_1", _, _));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, LOCAL_OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));
}

TEST_F(PackageScannerTest, TestPackageAffectedEqualToAlas2)
{
    const auto LOCAL_OS_MSG =
        R"({
            "hostname":"osdata_hostname",
            "architecture":"osdata_architecture",
            "name":"osdata_name",
            "codename":"upstream",
            "major_version":"2",
            "minor_version":"osdata_minorVersion",
            "patch":"osdata_patch",
            "build":"osdata_build",
            "platform":"amzn",
            "version":"osdata_version",
            "release":"osdata_release",
            "display_version":"osdata_displayVersion",
            "sysname":"osdata_sysName",
            "kernel_version":"osdata_kernelVersion",
            "kernel_release":"osdata_kernelRelease"
    })"_json;

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("alas"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates("alas_2", _, _));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, LOCAL_OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));
}

TEST_F(PackageScannerTest, TestPackageAffectedEqualToAlas2022)
{
    const auto LOCAL_OS_MSG =
        R"({
            "hostname":"osdata_hostname",
            "architecture":"osdata_architecture",
            "name":"osdata_name",
            "codename":"upstream",
            "major_version":"2022",
            "minor_version":"osdata_minorVersion",
            "patch":"osdata_patch",
            "build":"osdata_build",
            "platform":"amzn",
            "version":"osdata_version",
            "release":"osdata_release",
            "display_version":"osdata_displayVersion",
            "sysname":"osdata_sysName",
            "kernel_version":"osdata_kernelVersion",
            "kernel_release":"osdata_kernelRelease"
    })"_json;

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("alas"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates("alas_2022", _, _));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, LOCAL_OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));
}

TEST_F(PackageScannerTest, TestPackageAffectedEqualToRedHat7)
{
    const auto LOCAL_OS_MSG =
        R"({
            "hostname":"osdata_hostname",
            "architecture":"osdata_architecture",
            "name":"osdata_name",
            "codename":"upstream",
            "major_version":"7",
            "minor_version":"osdata_minorVersion",
            "patch":"osdata_patch",
            "build":"osdata_build",
            "platform":"redhat",
            "version":"osdata_version",
            "release":"osdata_release",
            "display_version":"osdata_displayVersion",
            "sysname":"osdata_sysName",
            "kernel_version":"osdata_kernelVersion",
            "kernel_release":"osdata_kernelRelease"
    })"_json;

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("redhat"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates("redhat_7", _, _));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, LOCAL_OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));
}

TEST_F(PackageScannerTest, TestPackageAffectedEqualToSLED)
{
    const auto LOCAL_OS_MSG =
        R"({
            "hostname":"osdata_hostname",
            "architecture":"osdata_architecture",
            "name":"osdata_name",
            "codename":"upstream",
            "major_version":"15",
            "minor_version":"osdata_minorVersion",
            "patch":"osdata_patch",
            "build":"osdata_build",
            "platform":"sled",
            "version":"osdata_version",
            "release":"osdata_release",
            "display_version":"osdata_displayVersion",
            "sysname":"osdata_sysName",
            "kernel_version":"osdata_kernelVersion",
            "kernel_release":"osdata_kernelRelease"
    })"_json;

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("suse"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates("suse_desktop_15", _, _));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, LOCAL_OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));
}

TEST_F(PackageScannerTest, TestPackageAffectedEqualToSLES)
{
    const auto LOCAL_OS_MSG =
        R"({
            "hostname":"osdata_hostname",
            "architecture":"osdata_architecture",
            "name":"osdata_name",
            "codename":"upstream",
            "major_version":"15",
            "minor_version":"osdata_minorVersion",
            "patch":"osdata_patch",
            "build":"osdata_build",
            "platform":"sles",
            "version":"osdata_version",
            "release":"osdata_release",
            "display_version":"osdata_displayVersion",
            "sysname":"osdata_sysName",
            "kernel_version":"osdata_kernelVersion",
            "kernel_release":"osdata_kernelRelease"
    })"_json;

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("suse"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates("suse_server_15", _, _));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, LOCAL_OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));
}

TEST_F(PackageScannerTest, TestcheckAndTranslatePackage)
{
    auto mockGetVulnerabilitiesCandidates =
        [&](const std::string& cnaName,
            const PackageData& package,
            const std::function<bool(const std::string& cnaName,
                                     const PackageData& package,
                                     const NSVulnerabilityScanner::ScanVulnerabilityCandidate&)>& callback)
    {
        std::string candidatesFlatbufferSchemaStr;

        // Read schemas from filesystem.
        bool valid =
            flatbuffers::LoadFile(CANDIDATES_FLATBUFFER_SCHEMA_PATH.c_str(), false, &candidatesFlatbufferSchemaStr);
        ASSERT_EQ(valid, true);

        // Parse schemas and JSON example.
        flatbuffers::Parser fbParser;
        std::array<const char*, 2> includeDirectories = {INCLUDE_DIRECTORIES[0], INCLUDE_DIRECTORIES[1]};
        valid = (fbParser.Parse(candidatesFlatbufferSchemaStr.c_str(), includeDirectories.data())
                 && fbParser.Parse(CANDIDATES_AFFECTED_EQUAL_TO_INPUT.c_str()));
        ASSERT_EQ(valid, true);

        auto candidatesArray = NSVulnerabilityScanner::GetScanVulnerabilityCandidateArray(
            reinterpret_cast<const uint8_t*>(fbParser.builder_.GetBufferPointer()));

        if (candidatesArray)
        {
            for (const auto& candidate : *candidatesArray->candidates())
            {
                if (callback(cnaName, package, *candidate))
                {
                    // If the candidate is vulnerable, we stop looking for.
                    break;
                }
            }
        }
    };

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("cnaName"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates(_, _, _))
        .WillOnce(testing::Invoke(mockGetVulnerabilitiesCandidates));
    std::vector<PackageData> mockPackageData = {
        PackageData {.name = "translatedProduct", .vendor = "translatedVendor"}};
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));
    EXPECT_CALL(*spDatabaseFeedManagerMock, cpeMappings()).WillOnce(testing::ReturnRef(CPE_MAPS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));

    ASSERT_TRUE(scanContext != nullptr);

    EXPECT_EQ(scanContext->m_elements.size(), 1);
    EXPECT_NE(scanContext->m_elements.find(CVEID), scanContext->m_elements.end());

    EXPECT_EQ(scanContext->m_matchConditions.size(), 1);
    EXPECT_NE(scanContext->m_matchConditions.find(CVEID), scanContext->m_matchConditions.end());

    const auto& matchCondition = scanContext->m_matchConditions[CVEID];
    EXPECT_EQ(matchCondition.condition, MatchRuleCondition::Equal);
    EXPECT_STREQ(matchCondition.version.c_str(), "5.1.9");
}

TEST_F(PackageScannerTest, TestVersionTranslation)
{
    auto mockGetVulnerabilitiesCandidates =
        [&](const std::string& cnaName,
            const PackageData& package,
            const std::function<bool(const std::string& cnaName,
                                     const PackageData& package,
                                     const NSVulnerabilityScanner::ScanVulnerabilityCandidate&)>& callback)
    {
        std::string candidatesFlatbufferSchemaStr;

        // Read schemas from filesystem.
        bool valid =
            flatbuffers::LoadFile(CANDIDATES_FLATBUFFER_SCHEMA_PATH.c_str(), false, &candidatesFlatbufferSchemaStr);
        ASSERT_EQ(valid, true);

        // Parse schemas and JSON example.
        flatbuffers::Parser fbParser;
        std::array<const char*, 2> includeDirectories = {INCLUDE_DIRECTORIES[0], INCLUDE_DIRECTORIES[1]};
        valid = (fbParser.Parse(candidatesFlatbufferSchemaStr.c_str(), includeDirectories.data())
                 && fbParser.Parse(CANDIDATES_AFFECTED_EQUAL_TO_INPUT.c_str()));
        ASSERT_EQ(valid, true);

        auto candidatesArray = NSVulnerabilityScanner::GetScanVulnerabilityCandidateArray(
            reinterpret_cast<const uint8_t*>(fbParser.builder_.GetBufferPointer()));

        if (candidatesArray)
        {
            for (const auto& candidate : *candidatesArray->candidates())
            {
                if (callback(cnaName, package, *candidate))
                {
                    // If the candidate is vulnerable, we stop looking for.
                    break;
                }
            }
        }
    };

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("cnaName"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates(_, _, _))
        .WillOnce(testing::Invoke(mockGetVulnerabilitiesCandidates));
    std::vector<PackageData> mockPackageData = {
        PackageData {.name = "translatedProduct", .vendor = "translatedVendor", .version = "5.1.9"}};
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _)).WillOnce(testing::Return(mockPackageData));

    nlohmann::json response;
    auto scanContext = std::make_shared<ScanContext>(
        ScannerType::Package, AGENT_MSG, OS_MSG, PACKAGES_WRONG_VERSION_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));
    EXPECT_CALL(*spDatabaseFeedManagerMock, cpeMappings()).WillOnce(testing::ReturnRef(CPE_MAPS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));

    ASSERT_TRUE(scanContext != nullptr);

    EXPECT_EQ(scanContext->m_elements.size(), 1);
    EXPECT_NE(scanContext->m_elements.find(CVEID), scanContext->m_elements.end());

    EXPECT_EQ(scanContext->m_matchConditions.size(), 1);
    EXPECT_NE(scanContext->m_matchConditions.find(CVEID), scanContext->m_matchConditions.end());

    const auto& matchCondition = scanContext->m_matchConditions[CVEID];
    EXPECT_EQ(matchCondition.condition, MatchRuleCondition::Equal);
    EXPECT_STREQ(matchCondition.version.c_str(), "5.1.9");
}

TEST_F(PackageScannerTest, TestVendorAndVersionTranslation)
{
    auto mockGetVulnerabilitiesCandidates =
        [&](const std::string& cnaName,
            const PackageData& package,
            const std::function<bool(const std::string& cnaName,
                                     const PackageData& package,
                                     const NSVulnerabilityScanner::ScanVulnerabilityCandidate&)>& callback)
    {
        std::string candidatesFlatbufferSchemaStr;

        // Read schemas from filesystem.
        bool valid =
            flatbuffers::LoadFile(CANDIDATES_FLATBUFFER_SCHEMA_PATH.c_str(), false, &candidatesFlatbufferSchemaStr);
        ASSERT_EQ(valid, true);

        // Parse schemas and JSON example.
        flatbuffers::Parser fbParser;
        std::array<const char*, 2> includeDirectories = {INCLUDE_DIRECTORIES[0], INCLUDE_DIRECTORIES[1]};
        valid = (fbParser.Parse(candidatesFlatbufferSchemaStr.c_str(), includeDirectories.data())
                 && fbParser.Parse(CANDIDATES_AFFECTED_LESS_THAN_INPUT_WITH_GENERIC_VENDOR.c_str()));
        ASSERT_EQ(valid, true);

        auto candidatesArray = NSVulnerabilityScanner::GetScanVulnerabilityCandidateArray(
            reinterpret_cast<const uint8_t*>(fbParser.builder_.GetBufferPointer()));

        if (candidatesArray)
        {
            for (const auto& candidate : *candidatesArray->candidates())
            {
                if (callback(cnaName, package, *candidate))
                {
                    // If the candidate is vulnerable, we stop looking for.
                    break;
                }
            }
        }
    };

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return("cnaName"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates(_, _, _))
        .WillOnce(testing::Invoke(mockGetVulnerabilitiesCandidates));
    std::vector<PackageData> mockPackageData = {
        PackageData {.name = "translatedProduct", .vendor = "testVendor", .version = "5.1.9"}};
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _)).WillOnce(testing::Return(mockPackageData));

    nlohmann::json response;
    auto scanContext = std::make_shared<ScanContext>(
        ScannerType::Package, AGENT_MSG, OS_MSG, PACKAGES_WRONG_VERSION_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));
    EXPECT_CALL(*spDatabaseFeedManagerMock, cpeMappings()).WillOnce(testing::ReturnRef(CPE_MAPS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));

    ASSERT_TRUE(scanContext != nullptr);

    EXPECT_EQ(scanContext->m_elements.size(), 1);
    EXPECT_NE(scanContext->m_elements.find(CVEID), scanContext->m_elements.end());

    EXPECT_EQ(scanContext->m_matchConditions.size(), 1);
    EXPECT_NE(scanContext->m_matchConditions.find(CVEID), scanContext->m_matchConditions.end());

    const auto& matchCondition = scanContext->m_matchConditions[CVEID];
    EXPECT_EQ(matchCondition.condition, MatchRuleCondition::LessThan);
    EXPECT_STREQ(matchCondition.version.c_str(), "5.2.0");
}

TEST_F(PackageScannerTest, TestGetCnaNameByPrefix)
{
    const auto LOCAL_OS_MSG =
        R"({
            "hostname":"osdata_hostname",
            "architecture":"osdata_architecture",
            "name":"osdata_name",
            "codename":"upstream",
            "major_version":"15",
            "minor_version":"osdata_minorVersion",
            "patch":"osdata_patch",
            "build":"osdata_build",
            "platform":"sles",
            "version":"osdata_version",
            "release":"osdata_release",
            "display_version":"osdata_displayVersion",
            "sysname":"osdata_sysName",
            "kernel_version":"osdata_kernelVersion",
            "kernel_release":"osdata_kernelRelease"
    })"_json;

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return(""));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameBySource(_)).WillOnce(testing::Return(""));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByPrefix(_, _)).WillOnce(testing::Return("suse"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates("suse_server_15", _, _));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, LOCAL_OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));
}

TEST_F(PackageScannerTest, TestGetCnaNameByContains)
{
    const auto LOCAL_OS_MSG =
        R"({
            "hostname":"osdata_hostname",
            "architecture":"osdata_architecture",
            "name":"osdata_name",
            "codename":"upstream",
            "major_version":"15",
            "minor_version":"osdata_minorVersion",
            "patch":"osdata_patch",
            "build":"osdata_build",
            "platform":"sles",
            "version":"osdata_version",
            "release":"osdata_release",
            "display_version":"osdata_displayVersion",
            "sysname":"osdata_sysName",
            "kernel_version":"osdata_kernelVersion",
            "kernel_release":"osdata_kernelRelease"
    })"_json;

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return(""));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameBySource(_)).WillOnce(testing::Return(""));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByPrefix(_, _)).WillOnce(testing::Return(""));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByContains(_, _)).WillOnce(testing::Return("suse"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates("suse_server_15", _, _));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, LOCAL_OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));
}

TEST_F(PackageScannerTest, TestGetCnaNameBySource)
{
    const auto LOCAL_OS_MSG =
        R"({
            "hostname":"osdata_hostname",
            "architecture":"osdata_architecture",
            "name":"osdata_name",
            "codename":"upstream",
            "major_version":"15",
            "minor_version":"osdata_minorVersion",
            "patch":"osdata_patch",
            "build":"osdata_build",
            "platform":"sles",
            "version":"osdata_version",
            "release":"osdata_release",
            "display_version":"osdata_displayVersion",
            "sysname":"osdata_sysName",
            "kernel_version":"osdata_kernelVersion",
            "kernel_release":"osdata_kernelRelease"
    })"_json;

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return(""));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameBySource(_)).WillOnce(testing::Return("cnaName"));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByPrefix(_, _)).Times(0);
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByContains(_, _)).Times(0);
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates("cnaName", _, _));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, LOCAL_OS_MSG, PACKAGES_MSG, "{}"_json, response);

    EXPECT_CALL(*spDatabaseFeedManagerMock, cnaMappings()).WillOnce(testing::ReturnRef(CNA_MAPPINGS));

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));
}

TEST_F(PackageScannerTest, TestGetDefaultCna)
{
    const auto LOCAL_OS_MSG =
        R"({
            "hostname":"osdata_hostname",
            "architecture":"osdata_architecture",
            "name":"osdata_name",
            "codename":"upstream",
            "major_version":"15",
            "minor_version":"osdata_minorVersion",
            "patch":"osdata_patch",
            "build":"osdata_build",
            "platform":"sles",
            "version":"osdata_version",
            "release":"osdata_release",
            "display_version":"osdata_displayVersion",
            "sysname":"osdata_sysName",
            "kernel_version":"osdata_kernelVersion",
            "kernel_release":"osdata_kernelRelease"
    })"_json;

    auto spDatabaseFeedManagerMock = std::make_shared<MockDatabaseFeedManager>();
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByFormat(_)).WillOnce(testing::Return(""));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameBySource(_)).WillOnce(testing::Return(""));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByPrefix(_, _)).WillOnce(testing::Return(""));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getCnaNameByContains(_, _)).WillOnce(testing::Return(""));
    EXPECT_CALL(*spDatabaseFeedManagerMock, getVulnerabilitiesCandidates(DEFAULT_CNA, _, _));
    EXPECT_CALL(*spDatabaseFeedManagerMock, checkAndTranslatePackage(_, _));

    nlohmann::json response;
    auto scanContext =
        std::make_shared<ScanContext>(ScannerType::Package, AGENT_MSG, LOCAL_OS_MSG, PACKAGES_MSG, "{}"_json, response);

    TPackageScanner<MockDatabaseFeedManager, ScanContext> packageScanner(spDatabaseFeedManagerMock);

    EXPECT_NO_THROW(packageScanner.handleRequest(scanContext));
}