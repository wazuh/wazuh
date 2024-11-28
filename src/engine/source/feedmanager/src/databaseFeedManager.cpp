/*
 * Wazuh Vulnerability scanner - Database Feed Manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <filesystem>

#include <base/logging.hpp>
#include <fs/archiveHelper.hpp>
#include <fs/xzHelper.hpp>

#include "databaseFeedManager.hpp"
#include "eventDecoder.hpp"
#include "storeModel.hpp"

const std::string CONTENT_NAME {"vd_1.0.0_vd_4.10.0"};                            // Content name.
const std::filesystem::path WAZUH_LIB_PATH {"/var/lib/wazuh-server/"};            //< Path to the lib server files.
const std::filesystem::path TMP_PATH {"/tmp/wazuh-server"};                       //< Path to the tmp files.
const std::filesystem::path WAZUH_LIB_TMP_PATH {WAZUH_LIB_PATH / "tmp/"};         //< Path to the lib server tmp files.
const std::filesystem::path XZ_FILE_PATH {TMP_PATH / (CONTENT_NAME + ".tar.xz")}; //< Path of the compressed db
const std::filesystem::path TAR_FILE_PATH {WAZUH_LIB_TMP_PATH / (CONTENT_NAME + ".tar")}; //< Path to the tar db.
const std::filesystem::path LEGACY_DB_PATH {WAZUH_LIB_TMP_PATH / "queue/"};           //< Path to the legacy database.
const std::filesystem::path VD_FEED_DB_BASE_PATH {WAZUH_LIB_PATH / "vd/"};            //< Path to the current database.
const std::filesystem::path VD_UPDATER_DB_BASE_PATH {WAZUH_LIB_PATH / "vd_updater/"}; //< Path to the updater database.

constexpr auto OFFSET_TRANSACTION_SIZE {1000};
constexpr auto EMPTY_KEY {""};
constexpr auto TRANSLATIONS_COLUMN {"translation"};
constexpr auto VENDOR_MAP_COLUMN {"vendor_map"};
constexpr auto OS_CPE_RULES_COLUMN {"oscpe_rules"};
constexpr auto CNA_MAPPING_COLUMN {"cna_mapping"};

DatabaseFeedManager::DatabaseFeedManager(std::shared_mutex& mutex)
    : m_mutex(mutex)
{
    try
    {
        if (std::filesystem::exists(XZ_FILE_PATH))
        {
            LOG_INFO("Starting database file decompression.");

            if (std::filesystem::remove(TAR_FILE_PATH))
            {
                LOG_DEBUG("Removing {} file before decompression.", TAR_FILE_PATH.c_str());
            }
            if (std::filesystem::remove_all(LEGACY_DB_PATH))
            {
                LOG_DEBUG("Removing existent {} folder.", LEGACY_DB_PATH.c_str());
            }
            if (std::filesystem::remove_all(VD_FEED_DB_BASE_PATH))
            {
                LOG_DEBUG("Removing existent {} folder.", VD_FEED_DB_BASE_PATH.c_str());
            }
            if (std::filesystem::remove_all(VD_UPDATER_DB_BASE_PATH))
            {
                LOG_DEBUG("Removing existent {} folder.", VD_UPDATER_DB_BASE_PATH.c_str());
            }
            if (!std::filesystem::exists(WAZUH_LIB_TMP_PATH))
            {
                std::filesystem::create_directories(WAZUH_LIB_TMP_PATH);
            }

            LOG_DEBUG("Starting XZ file decompression");
            fs::XzHelper(std::filesystem::path(XZ_FILE_PATH), std::filesystem::path(TAR_FILE_PATH)).decompress();

            LOG_DEBUG("Finishing XZ file decompression. Removing {}.", XZ_FILE_PATH.c_str());
            std::filesystem::remove(XZ_FILE_PATH);

            // Define folders to extract
            std::vector<std::string> extractOnly;
            extractOnly.emplace_back(LEGACY_DB_PATH / "vd");
            extractOnly.emplace_back(LEGACY_DB_PATH / "vd_updater");

            LOG_DEBUG("Starting TAR file decompression.");
            fs::ArchiveHelper::decompress(TAR_FILE_PATH, WAZUH_LIB_TMP_PATH, extractOnly);

            LOG_DEBUG("Finishing TAR file decompression. Removing {}.", TAR_FILE_PATH.c_str());
            std::filesystem::remove(TAR_FILE_PATH);

            // Move the extracted folder to the current database path
            std::filesystem::rename(LEGACY_DB_PATH / "vd", WAZUH_LIB_PATH / "vd");
            std::filesystem::rename(LEGACY_DB_PATH / "vd_updater", WAZUH_LIB_PATH / "vd_updater");

            // Remove temporary folder
            std::filesystem::remove_all(LEGACY_DB_PATH);
        }

        m_feedDatabase = std::make_unique<utils::rocksdb::RocksDBWrapper>(VD_FEED_DB_BASE_PATH / "feed", false);

        // Try to load global maps from the database, if it fails we throw an exception to force the download of
        // the complete feed.
        reloadGlobalMaps();
    }
    catch (const std::exception& ex)
    {
        // Create the database if it doesn't exist. We must remove any existing directory, as it may be corrupted.
        if (!m_feedDatabase)
        {
            std::filesystem::remove_all(VD_FEED_DB_BASE_PATH);
            std::filesystem::remove_all(VD_UPDATER_DB_BASE_PATH);
            m_feedDatabase = std::make_unique<utils::rocksdb::RocksDBWrapper>(VD_FEED_DB_BASE_PATH / "feed", false);
        }

        LOG_ERROR("Error opening the database: {}, trying to re-download the feed.", ex.what());
    }

    // TODO Check if the last sync is the last, if not get all CVEs with updates.
    auto eventDecoder = std::make_shared<EventDecoder>();
    eventDecoder->setLast(std::make_shared<StoreModel>());

    /*
    try
    {
        // logInfo(WM_VULNSCAN_LOGTAG, "Initiating update feed process.");
        processMessage(message, topicName, orchestrationLambda);
        auto eventContext =
            std::make_shared<EventContext>(EventContext {.message = message,
                                                         .resource = resource,
                                                         .feedDatabase = feedDatabaseArg,
                                                         .resourceType = ResourceType::UNKNOWN});
        eventDecoder->handleRequest(std::move(eventContext));

        // Verify vendor-map and oscpe-map values and update the maps in memory
        reloadGlobalMaps();

        // TODO: Make response
        LOG_INFO("Feed update process completed.");
    }
    catch (const DatabaseFeedManagerException& e)
    {
        LOG_INFO("Feed update interrupted: {}.", e.what());
    }
    catch (const std::exception& e)
    {
        logError(WM_VULNSCAN_LOGTAG, "Feed update failed: %s.", e.what());
    } */
}

void DatabaseFeedManager::getVulnerabilityRemediation(
    const std::string& cveId, FlatbufferDataPair<NSVulnerabilityScanner::RemediationInfo>& dtoVulnRemediation)
{
    // If the remediation information is not found in the database, we return because there is no remediation.
    if (auto result = m_feedDatabase->get(cveId, dtoVulnRemediation.slice, REMEDIATIONS_COLUMN); !result)
    {
        return;
    }

    if (flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(dtoVulnRemediation.slice.data()),
                                       dtoVulnRemediation.slice.size());
        !NSVulnerabilityScanner::VerifyRemediationInfoBuffer(verifier))
    {
        throw std::runtime_error("Error: Invalid FlatBuffers data in RocksDB.");
    }

    dtoVulnRemediation.data =
        NSVulnerabilityScanner::GetRemediationInfo(reinterpret_cast<const uint8_t*>(dtoVulnRemediation.slice.data()));
}

std::unordered_set<std::string> DatabaseFeedManager::getHotfixVulnerabilities(const std::string& hotfix)
{
    std::unordered_set<std::string> hotfixVulnerabilities;
    if (m_feedDatabase->columnExists(HOTFIXES_APPLICATIONS_COLUMN))
    {
        for (const auto& [key, value] : m_feedDatabase->seek(hotfix, HOTFIXES_APPLICATIONS_COLUMN))
        {
            hotfixVulnerabilities.insert(key);
        }
    }
    return hotfixVulnerabilities;
}

void DatabaseFeedManager::fillL2CacheTranslations()
{
    // Clear the Level 1 and Level 2 cache before filling the Level 2 cache
    m_translationL1Cache->clear();

    m_translationL2Cache->clear();

    // Clear the translation filter before filling any cache
    m_translationFilter->clear();

    // Iterate over translations in the feed database
    for (const auto& [key, value] : m_feedDatabase->begin(TRANSLATIONS_COLUMN))
    {
        // Check if the cache is full
        if (m_translationL2Cache->isFull())
        {
            break; // Exit the loop if cache is full
        }

        // Verify the integrity of FlatBuffers translation data
        if (flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(value.data()), value.size());
            !NSVulnerabilityScanner::VerifyTranslationEntryBuffer(verifier))
        {
            throw std::runtime_error("Error: Invalid FlatBuffers translation data in RocksDB.");
        }

        // Parse translation data
        auto queryData = NSVulnerabilityScanner::GetTranslationEntry(reinterpret_cast<const uint8_t*>(value.data()));

        // Prepare regular expressions for product, vendor and version matching
        auto createRegex = [](const auto regex) -> std::optional<std::regex>
        {
            return regex && !regex->str().empty() ? std::optional<std::regex>(regex->str()) : std::nullopt;
        };

        // Initialize Translation object to store translation data
        Translation translationQuery = {.productRegex = createRegex(queryData->source()->product()),
                                        .vendorRegex = createRegex(queryData->source()->vendor()),
                                        .versionRegex = createRegex(queryData->source()->version())};

        // Load target platforms into the Translation object
        for (const auto& target : *queryData->target())
        {
            translationQuery.target.push_back(target->str());
        }

        // Load translation data into the Translation object
        for (const auto& translationData : *queryData->translation())
        {
            translationQuery.translation.emplace_back(
                PackageData {.name = translationData->product() ? translationData->product()->str() : "",
                             .vendor = translationData->vendor() ? translationData->vendor()->str() : "",
                             .version = translationData->version() ? translationData->version()->str() : ""});
        }

        // Insert translation into cache
        m_translationL2Cache->insertKey(key, translationQuery);
    }
}

std::vector<PackageData> DatabaseFeedManager::getTranslationFromL2(const PackageData& package,
                                                                   const std::string& osPlatform)
{
    // Vector to store the resulting translations
    std::vector<PackageData> translationResult;

    // Iterate over the Level 2 cache data
    m_translationL2Cache->forEach(
        [&]([[maybe_unused]] const auto& key, const auto& cacheData)
        {
            /* Check conditions, return true to continue the loop, false to break it */
            // - The target platform matches the provided OS platform
            if (std::find(cacheData.target.begin(), cacheData.target.end(), osPlatform) == cacheData.target.end())
            {
                return true;
            }
            // - The package name matches the product regex if present
            if (cacheData.productRegex.has_value() && !std::regex_search(package.name, cacheData.productRegex.value()))
            {
                return true;
            }
            // - The vendor matches the vendor regex if present
            if (cacheData.vendorRegex.has_value() && !std::regex_search(package.vendor, cacheData.vendorRegex.value()))
            {
                return true;
            }

            // Append the matching translation to the result vector
            for (const auto& translatedPackage : cacheData.translation)
            {
                PackageData translatedResult {.name = translatedPackage.name, .vendor = translatedPackage.vendor};
                // Search for version regex or use translated version
                if (std::smatch stringFound;
                    cacheData.versionRegex.has_value()
                    && std::regex_search(package.name, stringFound, cacheData.versionRegex.value())
                    && !stringFound.empty())
                {
                    // We only consider the first capture group
                    translatedResult.version = stringFound.str(1);
                }
                else
                {
                    translatedResult.version = translatedPackage.version;
                }
                translationResult.push_back(std::move(translatedResult));
            }

            // Break the loop after finding the first matching translation
            return false;
        });

    // Return the vector containing the matching translations
    return translationResult;
}

void DatabaseFeedManager::getVulnerabilitiesCandidates(
    const std::string& cnaName,
    const PackageData& package,
    const std::function<bool(const std::string& cnaName,
                             const PackageData& package,
                             const NSVulnerabilityScanner::ScanVulnerabilityCandidate&)>& callback)
{
    if (package.name.empty() || cnaName.empty())
    {
        throw std::runtime_error("Invalid package/cna name.");
    }

    std::string packageNameWithSeparator;
    packageNameWithSeparator.append(package.name);
    packageNameWithSeparator.append("_CVE");

    for (const auto& [key, value] : m_feedDatabase->seek(packageNameWithSeparator, cnaName))
    {
        if (flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(value.data()), value.size());
            !NSVulnerabilityScanner::VerifyScanVulnerabilityCandidateArrayBuffer(verifier))
        {
            throw std::runtime_error(
                "Error getting ScanVulnerabilityCandidateArray object from rocksdb. FlatBuffers verifier failed");
        }

        auto candidatesArray =
            NSVulnerabilityScanner::GetScanVulnerabilityCandidateArray(reinterpret_cast<const uint8_t*>(value.data()));

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
    }
}

std::vector<PackageData> DatabaseFeedManager::checkAndTranslatePackage(const PackageData& package,
                                                                       const std::string& osPlatform)
{
    std::vector<PackageData> vulnerabilityTranslations;
    const auto cacheKey = osPlatform + "_" + package.vendor + "_" + package.name;

    auto translatePackage = [&](const auto& translations)
    {
        for (const auto& translation : translations)
        {
            PackageData translatedPackage = package;
            if (!translation.name.empty())
            {
                translatedPackage.name = translation.name;
            }
            if (!translation.vendor.empty())
            {
                translatedPackage.vendor = translation.vendor;
            }
            if (!translation.version.empty())
            {
                translatedPackage.version = translation.version;
            }
            vulnerabilityTranslations.push_back(translatedPackage);
        }
    };

    // Check first the filter
    if (m_translationFilter->count(cacheKey) > 0)
    {
        LOG_DEBUG("No translation exists for package '{}' on platform '{}'. Using provided package data.",
                  package.name,
                  osPlatform);
        return vulnerabilityTranslations;
    }

    // Check Level 1 cache
    if (m_translationL1Cache->isHit(cacheKey))
    {
        LOG_DEBUG("Translation for package '{}' on platform '{}' found in Level 1 cache.", package.name, osPlatform);

        const auto L1Translations = m_translationL1Cache->getValue(cacheKey).value();
        translatePackage(L1Translations);
        return vulnerabilityTranslations;
    }

    // Check Level 2 cache
    const auto L2Translations = getTranslationFromL2(package, osPlatform);
    if (!L2Translations.empty())
    {
        LOG_DEBUG("Translation for package '{}' on platform '{}' found in Level 2 cache.", package.name, osPlatform);

        translatePackage(L2Translations);

        // Store translations in Level 1 cache
        m_translationL1Cache->insertKey(cacheKey, L2Translations);
        return vulnerabilityTranslations;
    }

    // Insert the key in the filter to avoid searching for it again
    m_translationFilter->insert(cacheKey);
    LOG_DEBUG("No translation exists for package '{}' on platform '{}'. Using provided package data.",
              package.name,
              osPlatform);

    return vulnerabilityTranslations;
}

utils::rocksdb::RocksDBWrapper& DatabaseFeedManager::getCVEDatabase()
{
    return *m_feedDatabase;
}

// LCOV_EXCL_STOP

bool DatabaseFeedManager::getVulnerabilityDescriptiveInformation(
    const std::string& cveId,
    const std::string& subShortName,
    FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription>& resultContainer)
{
    if (const auto descriptionColumn = std::string(DESCRIPTIONS_COLUMN) + "_" + subShortName;
        m_feedDatabase->get(cveId, resultContainer.slice, descriptionColumn) == false)
    {
        LOG_DEBUG("Vulnerability description not found for {} in {}.", cveId.c_str(), descriptionColumn.c_str());
        resultContainer.data = nullptr;
        return false;
    }

    resultContainer.data = const_cast<NSVulnerabilityScanner::VulnerabilityDescription*>(
        NSVulnerabilityScanner::GetVulnerabilityDescription(resultContainer.slice.data()));

    return true;
}

std::string DatabaseFeedManager::getCnaNameBySource(std::string_view source) const
{
    if (const auto& vendorMap = vendorsMap(); vendorMap.contains("source"))
    {
        for (const auto& item : vendorMap.at("source"))
        {
            if (source == item.begin().key())
            {
                return item.begin().value();
            }
        }
    }

    return {};
}

std::string DatabaseFeedManager::getCnaNameByFormat(std::string_view format) const
{
    if (const auto& vendorMap = vendorsMap(); vendorMap.contains("format"))
    {
        for (const auto& item : vendorMap.at("format"))
        {
            if (format == item.begin().key())
            {
                return item.begin().value();
            }
        }
    }

    return {};
}

std::string DatabaseFeedManager::getCnaNameByContains(std::string_view vendor, std::string_view platform) const
{
    if (const auto& vendorMap = vendorsMap(); vendorMap.contains("contains"))
    {
        for (const auto& item : vendorMap.at("contains"))
        {
            if (const auto& platforms = item.begin().value().at("platforms");
                vendor.find(item.begin().key()) != std::string::npos
                && std::find(platforms.begin(), platforms.end(), platform) != platforms.end())
            {
                return item.begin().value().at("cna");
            }
        }
    }

    return {};
}

std::string DatabaseFeedManager::getCnaNameByPrefix(std::string_view vendor, std::string_view platform) const
{
    if (const auto& vendorMap = vendorsMap(); vendorMap.contains("prefix"))
    {
        for (const auto& item : vendorMap.at("prefix"))
        {
            if (const auto& platforms = item.begin().value().at("platforms");
                base::utils::string::startsWith(vendor.data(), item.begin().key())
                && std::find(platforms.begin(), platforms.end(), platform) != platforms.end())
            {
                return item.begin().value().at("cna");
            }
        }
    }
    return {};
}

uint32_t DatabaseFeedManager::getCacheSizeFromConfig() const
{
    // TODO: Get size from the config
    // return TPolicyManager::instance().getTranslationLRUSize();
    return 1024;
}

void DatabaseFeedManager::reloadGlobalMaps()
{
    std::scoped_lock<std::shared_mutex> lock(m_mutex);

    std::string result;
    if (!m_feedDatabase->get("FEED-GLOBAL", result, VENDOR_MAP_COLUMN))
    {
        throw std::runtime_error("Vendor map can not be found in DB.");
    }
    else if (result.empty())
    {
        throw std::runtime_error("Vendor map is empty.");
    }

    m_vendorsMap = nlohmann::json::parse(result);

    rocksdb::PinnableSlice queryResult;
    if (!m_feedDatabase->get("OSCPE-GLOBAL", queryResult, OS_CPE_RULES_COLUMN))
    {
        throw std::runtime_error("Error getting OS CPE rules content from rocksdb.");
    }

    m_cpeMappings = nlohmann::json::parse(queryResult.ToString());

    // Load CNA mappings
    if (!m_feedDatabase->get("CNA-MAPPING-GLOBAL", queryResult, CNA_MAPPING_COLUMN))
    {
        throw std::runtime_error("Error getting CNA Mapping content from rocksdb.");
    }
    m_cnaMappings = nlohmann::json::parse(queryResult.ToString());

    // Load translations into the Level 2 cache
    fillL2CacheTranslations();
}

auto DatabaseFeedManager::cnaMappings() const -> const nlohmann::json&
{
    return m_cnaMappings;
}

auto DatabaseFeedManager::cpeMappings() const -> const nlohmann::json&
{
    return m_cpeMappings;
}

auto DatabaseFeedManager::vendorsMap() const -> const nlohmann::json&
{
    return m_vendorsMap;
}
