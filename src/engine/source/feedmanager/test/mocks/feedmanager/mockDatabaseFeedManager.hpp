/*
 * Wazuh databaseFeedManager
 * Copyright (C) 2015, Wazuh Inc.
 * January 3, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _MOCK_DATABASEFEEDMANAGER_HPP
#define _MOCK_DATABASEFEEDMANAGER_HPP

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <databaseFeedManager.hpp>
#include <nlohmann/json.hpp>

/**
 * @class MockDatabaseFeedManager
 *
 * @brief Mock class for simulating a database feed manager object.
 *
 * The `MockDatabaseFeedManager` class is designed to simulate the behavior of a
 * database feed manager for testing purposes. It provides mock implementations of methods and
 * allows you to set expectations on method calls and their return values for testing.
 *
 * This class is used in unit tests only to verify interactions with a content
 * register without actually performing real operations on it.
 */
class MockDatabaseFeedManager
{
public:
    MockDatabaseFeedManager() = default;

    virtual ~MockDatabaseFeedManager() = default;

    /**
     * @brief Mock method for getVulnerabilityRemediation.
     *
     * @note This method is intended for testing purposes and does not perform any real action.
     */
    MOCK_METHOD(void,
                getVulnerabilityRemediation,
                (const std::string& cveId,
                 FlatbufferDataPair<NSVulnerabilityScanner::RemediationInfo>& dtoVulnRemediation),
                ());

    /**
     * @brief Mock method for fillL2CacheTranslations.
     *
     * @note This method is intended for testing purposes and does not perform any real action.
     */
    MOCK_METHOD(void, fillL2CacheTranslations, (const std::string_view& packageName), ());

    /**
     * @brief Mock method for getTranslationFromL2.
     *
     * @note This method is intended for testing purposes and does not perform any real action.
     */
    MOCK_METHOD(std::vector<PackageData>,
                getTranslationFromL2,
                (const PackageData& package, const std::string& osPlatform),
                ());

    /**
     * @brief Mock method for getVulnerabilitiesCandidates.
     *
     * @note This method is intended for testing purposes and does not perform any real action.
     */
    MOCK_METHOD(void,
                getVulnerabilitiesCandidates,
                (const std::string& cnaName,
                 const PackageData& package,
                 const std::function<bool(const std::string& cnaName,
                                          const PackageData& package,
                                          const NSVulnerabilityScanner::ScanVulnerabilityCandidate&)>& callback),
                ());

    /**
     * @brief Mock method for update.
     *
     * @note This method is intended for testing purposes and does not perform any real action.
     */
    MOCK_METHOD(void, update, (nlohmann::json & data), ());

    /**
     * @brief Mock method for checkAndTranslatePackage
     *
     * @note This method is intended for testing purposes and does not perform any real action.
     */
    MOCK_METHOD(std::vector<PackageData>,
                checkAndTranslatePackage,
                (const PackageData& package, const std::string& osPlatform),
                ());

    /**
     * @brief Mock method for getVulnerabilityDescriptiveInformation.
     *
     * @note This method is intended for testing purposes and does not perform any real action.
     */
    MOCK_METHOD(bool,
                getVulnerabilityDescriptiveInformation,
                (const std::string& cveId,
                 const std::string& subShortName,
                 FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer),
                ());

    /**
     * @brief Mock method for getCnaNameByFormat.
     */
    MOCK_METHOD(std::string, getCnaNameByFormat, (std::string_view format), ());

    /**
     * @brief Mock method for getCnaNameByContains.
     *
     */
    MOCK_METHOD(std::string, getCnaNameByContains, (std::string_view vendor, std::string_view platform), ());

    /**
     * @brief Mock method for getCnaNameByPrefix.
     *
     */
    MOCK_METHOD(std::string, getCnaNameByPrefix, (std::string_view vendor, std::string_view platform), ());

    /**
     * @brief Mock method for getCnaNameBySource
     *
     */
    MOCK_METHOD(std::string, getCnaNameBySource, (std::string_view source), ());

    /**
     * @brief Mock method for cpeMappings.
     *
     */
    MOCK_METHOD(const nlohmann::json&, cpeMappings, (), ());

    /**
     * @brief Mock method for cnaMappings.
     *
     */
    MOCK_METHOD(const nlohmann::json&, cnaMappings, (), ());

    /**
     * @brief Mock method for vendorsMap.
     *
     */
    MOCK_METHOD(const nlohmann::json&, vendorsMap, (), ());
};

#endif // _MOCK_DATABASEFEEDMANAGER_HPP
