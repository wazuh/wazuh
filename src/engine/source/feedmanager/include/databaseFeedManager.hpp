/*
 * Wazuh Vulnerability scanner
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DATABASE_FEED_MANAGER_HPP
#define _DATABASE_FEED_MANAGER_HPP

#include <functional>
#include <memory>
#include <regex>
#include <shared_mutex>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <base/lruCache.hpp>
#include <base/utils/rocksDBWrapper.hpp>

#include "packageTranslation_generated.h"
#include "vulnerabilityCandidate_generated.h"
#include "vulnerabilityDescription_generated.h"
#include "vulnerabilityRemediations_generated.h"

constexpr auto DEFAULT_ADP {"nvd"};
constexpr auto ADP_CVSS_KEY {"cvss"};
constexpr auto ADP_DESCRIPTION_KEY {"description"};
constexpr auto ADP_DESCRIPTIONS_MAP_KEY {"adp_descriptions"};

/**
 * @brief Scanning package data struct.
 */
struct PackageData final
{
    std::string name;    ///< Package name.
    std::string vendor;  ///< Package vendor.
    std::string format;  ///< Package format.
    std::string version; ///< Package version.
};

/**
 * @brief A struct for storing a pair of FlatBuffers data.
 *
 * The `FlatbufferDataPair` struct is designed to store a pair of related FlatBuffers data:
 * a `rocksdb::PinnableSlice` containing the serialized data and a pointer to the deserialized
 * data of type `FlatbufferType`. This allows for efficient storage and access to both the raw
 * serialized data and its parsed form.
 *
 * @tparam FlatbufferType The type of the FlatBuffers object that this struct represents.
 */
template<typename FlatbufferType>
struct FlatbufferDataPair final
{
    /**
     * @brief A slice to the serialized FlatBuffers data.
     *
     * The `slice` member stores a `rocksdb::PinnableSlice` that contains the serialized
     * FlatBuffers data.
     */
    rocksdb::PinnableSlice slice;

    /**
     * @brief A pointer to the deserialized FlatBuffers data.
     *
     * The `data` member is a pointer to the deserialized FlatBuffers data of type `FlatbufferType`.
     * It provides direct access to the parsed information.
     */
    const FlatbufferType* data = nullptr;
};

/**
 * @brief Represents a translation entry containing regular expressions for product and vendor identification,
 *        along with a vector of translated data.
 */
struct Translation final
{
    std::optional<std::regex> productRegex; ///< Regular expression for product identification.
    std::optional<std::regex> vendorRegex;  ///< Regular expression for vendor identification.
    std::optional<std::regex> versionRegex; ///< Regular expression for version identification.
    std::vector<PackageData> translation;   ///< Vector of translated data.
    std::vector<std::string> target;        ///< Vector of valid targets.
};

/**
 * @brief Translations cache.
 * @details Key: Translation ID, Value: Translation information.
 */
using TranslationLRUCache = LRUCache<std::string, Translation>;

/**
 * @brief DatabaseFeedManager class.
 */
class DatabaseFeedManager final
{
public:
    /**
     * @brief Class constructor.
     *
     * @param mutex Mutex to protect the access to the internal databases.
     */
    // LCOV_EXCL_START
    explicit DatabaseFeedManager(std::shared_mutex& mutex);
    /**
     * @brief Retrieves vulnerability remediation information from the database, for a given CVE ID.
     *
     * This function retrieves remediation information associated with a given CVE ID
     * from the underlying database and stores it in the provided `dtoVulnRemediation`
     * object.
     *
     * @param cveId The CVE ID for which remediation information is requested.
     * @param dtoVulnRemediation A reference to a `FlatbufferDataPair` object
     *        where the retrieved remediation information will be stored.
     *
     * @throws std::runtime_error if the retrieved data from the database is invalid or
     *         not in the expected FlatBuffers format.
     */
    void getVulnerabilityRemediation(const std::string& cveId,
                                     FlatbufferDataPair<NSVulnerabilityScanner::RemediationInfo>& dtoVulnRemediation);
    ;

    /**
     * @brief Retrieves the vulnerabilities information from the database, for a given hotfix ID.
     *
     * This function retrieves remediation information associated with a given hotfix from the underlying database and
     * stores it in the 'remediationInfo' object.
     *
     * @param hotfix hotfix id for which remediation information is requested.
     *
     * @return An unordered set containing the CVEs associated with the provided hotfix.
     *
     * @throws std::runtime_error if the retrieved data from the database is invalid or not in the expected FlatBuffers
     * format.
     */
    std::unordered_set<std::string> getHotfixVulnerabilities(const std::string& hotfix);

    /**
     * @brief Fills the Level 2 cache with translations from the feed database.
     *
     * This function iterates over translations in the feed database, verifies the integrity of FlatBuffers
     * translation data, and inserts valid translations into the Level 2 cache.
     *
     * @throws std::runtime_error If invalid FlatBuffers translation data is encountered in the database.
     */
    void fillL2CacheTranslations();

    /**
     * @brief Retrieves translations from the Level 2 cache based on the provided package data and operating system
     * platform.
     *
     * This function searches the Level 2 cache for translations that match the provided package name, vendor and
     * operating system platform. If a translation matches the regex expressions, it is appended to the result vector.
     *
     * @param package A structure containing all the data for the package.
     * @param osPlatform The operating system platform for which translations are requested.
     * @return A vector containing the matching translations for the specified package and platform.
     */
    std::vector<PackageData> getTranslationFromL2(const PackageData& package, const std::string& osPlatform);

    /**
     * @brief Get the Vulnerabilities Candidates information.
     *
     * @param cnaName RocksDB table identifier.
     * @param package Struct with package data.
     * @param callback Store vulnerability data.
     */
    void getVulnerabilitiesCandidates(
        const std::string& cnaName,
        const PackageData& package,
        const std::function<bool(const std::string& cnaName,
                                 const PackageData& package,
                                 const NSVulnerabilityScanner::ScanVulnerabilityCandidate&)>& callback);

    /**
     * @brief Checks and translates package information.
     *
     * This function searches for translation data in the Level 1 and Level 2 caches for a given package.
     * If translation data is found, it populates the translations and returns them. If no translation data
     * is found, it logs a debug message and returns an empty vector.
     *
     * @param package The package data to be checked and translated.
     * @param osPlatform The operating system platform for which the package translation is required.
     * @return A vector containing the translated package data.
     */
    std::vector<PackageData> checkAndTranslatePackage(const PackageData& package, const std::string& osPlatform);

    /**
     * @brief Retrieves a reference to the CVE (Common Vulnerabilities and Exposures) database.
     *
     * This function provides access to the Common Vulnerabilities and Exposures (CVE) database
     * represented by a reference to a RocksDBWrapper object.
     *
     * @return A reference to the CVE database represented by utils::rocksdb::RocksDBWrapper.
     */
    utils::rocksdb::RocksDBWrapper& getCVEDatabase();

    // LCOV_EXCL_STOP

    /**
     * @brief Gets descriptive information for a given CVE ID and CNA/ADP.
     *
     * @param cveId CVE ID to get the information.
     * @param subShortName Expanded CNA/ADP name (Ex. nvd, suse_server_15, redhat_8)
     * @param resultContainer container struct to store the result.
     *
     * @return true if the information was successfully retrieved, false otherwise.
     */
    bool getVulnerabilityDescriptiveInformation(
        const std::string& cveId,
        const std::string& subShortName,
        FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer);

    /**
     * @brief Get CNA/ADP name based on the package source.
     *
     * @param source Package source.
     * @return std::string CNA/ADP name. Empty string otherwise.
     */
    std::string getCnaNameBySource(std::string_view source) const;

    /**
     * @brief Get CNA/ADP name based on the package format.
     * @param format Package format.
     * @return CNA/ADP name. Empty string otherwise.
     */
    std::string getCnaNameByFormat(std::string_view format) const;

    /**
     * @brief Get CNA/ADP name based on the package vendor when it contains a specific word.
     * @param vendor Package vendor.
     * @param platform Os platform.
     * @return CNA/ADP name. Empty string otherwise.
     */
    std::string getCnaNameByContains(std::string_view vendor, std::string_view platform) const;

    /**
     * @brief Get CNA/ADP name based on the package vendor when it starts with a specific word.
     * @param vendor Package vendor.
     * @param platform Os platform.
     *
     * @return CNA/ADP name. Empty string otherwise.
     */
    std::string getCnaNameByPrefix(std::string_view vendor, std::string_view platform) const;

    /**
     * @brief Get cache size from configuration.
     *
     * This function retrieves the cache size for translation cache from the configuration settings.
     * It accesses the instance of TPolicyManager to fetch the translation LRU size specified in the configuration.
     *
     * @return The size of the translation cache as specified in the configuration settings.
     */
    uint32_t getCacheSizeFromConfig() const;

    /**
     * @brief Get CNA mappings.
     *
     * This function retrieves the CNA mappings from the database and returns them as a JSON object.
     *
     * @return const nlohmann::json& CNA mappings.
     */
    auto cnaMappings() const -> const nlohmann::json&;

    /**
     * @brief Get CPE mappings.
     *
     * This function retrieves the CPE mappings from the database and returns them as a JSON object.
     *
     * @return const nlohmann::json& Vendors map.
     */
    auto cpeMappings() const -> const nlohmann::json&;

    /**
     * @brief Get vendors map.
     *
     * This function retrieves the vendors map from the database and returns them as a JSON object.
     *
     * @return const nlohmann::json& Vendors map.
     */
    auto vendorsMap() const -> const nlohmann::json&;

private:
    /**
     * Do not change the order of definition of these variables.
     * Since it is important at the object destruction time.
     */
    std::shared_mutex& m_mutex;
    std::unique_ptr<utils::rocksdb::RocksDBWrapper> m_feedDatabase;
    // TODO: Get size from the config
    std::unique_ptr<TranslationLRUCache> m_translationL2Cache = std::make_unique<TranslationLRUCache>(1024);

    std::unique_ptr<std::unordered_set<std::string>> m_translationFilter =
        std::make_unique<std::unordered_set<std::string>>();

    // TODO: Get size from the config
    std::unique_ptr<LRUCache<std::string, std::vector<PackageData>>> m_translationL1Cache =
        std::make_unique<LRUCache<std::string, std::vector<PackageData>>>(1024);

    /**
     * @brief Reads the vendor and os cpe maps from the database and loads the data into memory.
     *
     * @throws std::runtime_error if the vendor and os cpe maps aren't available or are invalid.
     * @note This methods locks the mutex.
     */
    void reloadGlobalMaps();

    nlohmann::json m_cnaMappings;
    nlohmann::json m_vendorsMap;
    nlohmann::json m_cpeMappings;
};

#endif // _DATABASE_FEED_MANAGER_HPP
