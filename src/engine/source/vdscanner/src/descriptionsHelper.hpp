/*
 * Wazuh Vulnerability scanner
 * Copyright (C) 2015, Wazuh Inc.
 * September 22, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _DESCRIPTIONS_HELPER_HPP
#define _DESCRIPTIONS_HELPER_HPP

#include <base/json.hpp>
#include <base/logging.hpp>
#include <databaseFeedManager.hpp>
#include <string>

/**
 * @brief Holds information about a vulnerability's CVSS metrics and related data.
 */
struct CveDescription final
{
    static constexpr const char* DEFAULT_STR_VALUE = "";                     ///< Default value for strings.
    static constexpr float DEFAULT_FLOAT_VALUE = 0.0f;                       ///< Default value for floats.
    static constexpr const char* DEFAULT_TIMESTAMP = "0000-01-01T00:00:00Z"; ///< Default value for timestamps.

    /**
     * @brief Complexity of access required to exploit the vulnerability (CVSS metric).
     */
    std::string_view accessComplexity = DEFAULT_STR_VALUE;

    /**
     * @brief Short name of the entity that assigned the CVE.
     */
    std::string_view assignerShortName = DEFAULT_STR_VALUE;

    /**
     * @brief The context by which vulnerability exploitation is possible (CVSS metric).
     */
    std::string_view attackVector = DEFAULT_STR_VALUE;

    /**
     * @brief Level of authentication needed to exploit the vulnerability (CVSS metric).
     */
    std::string_view authentication = DEFAULT_STR_VALUE;

    /**
     * @brief Impact on the availability of the target system (CVSS metric).
     */
    std::string_view availabilityImpact = DEFAULT_STR_VALUE;

    /**
     * @brief The classification or category of the vulnerability.
     */
    std::string_view classification = DEFAULT_STR_VALUE;

    /**
     * @brief Impact on the confidentiality of the target system (CVSS metric).
     */
    std::string_view confidentialityImpact = DEFAULT_STR_VALUE;

    /**
     * @brief Common Weakness Enumeration (CWE) identifier for the vulnerability.
     */
    std::string_view cweId = DEFAULT_STR_VALUE;

    /**
     * @brief Date when the vulnerability was first published.
     */
    std::string_view datePublished = DEFAULT_TIMESTAMP;

    /**
     * @brief Date when the vulnerability was last updated.
     */
    std::string_view dateUpdated = DEFAULT_TIMESTAMP;

    /**
     * @brief Detailed description of the vulnerability.
     */
    std::string_view description = DEFAULT_STR_VALUE;

    /**
     * @brief Impact on the integrity of the target system (CVSS metric).
     */
    std::string_view integrityImpact = DEFAULT_STR_VALUE;

    /**
     * @brief Level of privileges required to exploit the vulnerability (CVSS metric).
     */
    std::string_view privilegesRequired = DEFAULT_STR_VALUE;

    /**
     * @brief Reference URL or document related to the vulnerability.
     */
    std::string_view reference = DEFAULT_STR_VALUE;

    /**
     * @brief Scope of impact once the vulnerability is exploited (CVSS metric).
     */
    std::string_view scope = DEFAULT_STR_VALUE;

    /**
     * @brief Base CVSS score indicating the severity of the vulnerability.
     * @details Initialized to 0.0 by default.
     */
    float scoreBase = DEFAULT_FLOAT_VALUE;

    /**
     * @brief The version of the CVSS scoring system used.
     */
    std::string_view scoreVersion = DEFAULT_STR_VALUE;

    /**
     * @brief Severity level of the vulnerability (e.g., Low, Medium, High).
     */
    std::string_view severity = DEFAULT_STR_VALUE;

    /**
     * @brief Indicates if user interaction is required to exploit the vulnerability (CVSS metric).
     */
    std::string_view userInteraction = DEFAULT_STR_VALUE;
};

/**
 * @brief Descriptions helper class.
 */
class DescriptionsHelper final
{
private:
    template<typename TDatabaseFeedManager = DatabaseFeedManager>
    static std::pair<const std::string, const std::string>
    cvssAndDescriptionSources(const std::pair<std::string, std::string>& sources,
                              std::shared_ptr<TDatabaseFeedManager>& databaseFeedManager)
    {
        // Ex. sources = {"redhat", "redhat_8"}
        const auto& [adp, expandedAdp] = sources;
        const auto& vendorsMap = databaseFeedManager->vendorsMap();

        nlohmann::json vendorConfig;
        if (vendorsMap.at(ADP_DESCRIPTIONS_MAP_KEY).contains(adp))
        {
            vendorConfig = vendorsMap.at(ADP_DESCRIPTIONS_MAP_KEY).at(adp);
        }
        else
        {
            // Fallback to default ADP
            vendorConfig = vendorsMap.at(ADP_DESCRIPTIONS_MAP_KEY).at(DEFAULT_ADP);
        }

        const auto& cvssSource = vendorConfig.at(ADP_CVSS_KEY).get_ref<const std::string&>();
        const auto& descriptionSource = vendorConfig.at(ADP_DESCRIPTION_KEY).get_ref<const std::string&>();

        return {cvssSource == adp ? expandedAdp : cvssSource,
                descriptionSource == adp ? expandedAdp : descriptionSource};
    }

public:
    /**
     * @brief Get the vulnerability description and CVSS metrics for a given CVE.
     *
     * @note Attempt to retrieve the information from the specified sources. If the information is not available (or it
     * is not reliable), it uses the default ADP information instead.
     *
     * @tparam TDatabaseFeedManager Database feed manager type.
     *
     * @param cve CVE identifier.
     * @param sources Pair of sources (ADP and expanded ADP).
     * @param databaseFeedManager Database feed manager instance.
     * @param callback Callback function to call with the retrieved CveDescription object.
     *
     */
    template<typename TDatabaseFeedManager = DatabaseFeedManager>
    static void vulnerabilityDescription(const std::string& cve,
                                         const std::pair<std::string, std::string>& sources,
                                         std::shared_ptr<TDatabaseFeedManager>& databaseFeedManager,
                                         const std::function<void(const CveDescription&)>& callback)
    {
        FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription> descriptionData;
        FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription> cvssData;

        const auto [cvssSource, descriptionSource] =
            DescriptionsHelper::cvssAndDescriptionSources(sources, databaseFeedManager);

        bool defaultADPRetrievalFailed = false;

        // Get description data
        // Check if the description information is reliable
        // The description information is considered unreliable if the description is empty or "not defined"
        const auto descriptionIsReliable = [&descriptionData, &descriptionSource, &cve]()
        {
            if (!descriptionData.data || descriptionData.data->description()->str() == "not defined")
            {
                LOG_DEBUG("Unreliable description information for '{}' from '{}' source.",
                          cve.c_str(),
                          descriptionSource.c_str());
                return false;
            }

            return true;
        };

        // Get vulnerability descriptive information using the description source specified for the feed vendor.
        if (!databaseFeedManager->getVulnerabilityDescriptiveInformation(cve, descriptionSource, descriptionData))
        {
            LOG_DEBUG("Description information could not be obtained for '{}' from '{}' source.",
                      cve.c_str(),
                      descriptionSource.c_str());
        }

        // Only attempt to retrieve the descriptive information if the source differs from the DEFAULT_ADP
        if (!descriptionIsReliable() && descriptionSource != DEFAULT_ADP)
        {
            if (!databaseFeedManager->getVulnerabilityDescriptiveInformation(cve, DEFAULT_ADP, descriptionData))
            {
                LOG_DEBUG("Description information could not be obtained for '{}' from '{}' source.",
                          cve.c_str(),
                          DEFAULT_ADP);
                defaultADPRetrievalFailed = true;
            }
        }

        // Get CVSS data
        // Check if the CVSS information is reliable
        // The CVSS information is considered unreliable if the score is near 0 or the severity is empty
        const auto cvssIsReliable = [&cvssData, &cvssSource, &cve]()
        {
            if (!cvssData.data || cvssData.data->scoreBase() < 0.01f || cvssData.data->severity()->str().empty())
            {
                LOG_DEBUG("Unreliable information for '{}' from {} source.", cve.c_str(), cvssSource.c_str());
                return false;
            }

            return true;
        };

        // Only if cvssSource is not the same as the previous one.
        if (cvssSource != descriptionSource)
        {
            if (!databaseFeedManager->getVulnerabilityDescriptiveInformation(cve, cvssSource, cvssData))
            {
                LOG_DEBUG("CVSS information could not be obtained for '{}' from '{}' source.",
                          cve.c_str(),
                          cvssSource.c_str());
            }
        }
        else
        {
            // If the sources are the same, cvssData will be the same as descriptionData
            cvssData.data = descriptionData.data;
        }

        // Attempt with default ADP if the information is not reliable.
        if (!cvssIsReliable() && cvssSource != DEFAULT_ADP)
        {
            if (!defaultADPRetrievalFailed)
            {
                if (!databaseFeedManager->getVulnerabilityDescriptiveInformation(cve, DEFAULT_ADP, cvssData))
                {
                    LOG_DEBUG(
                        "CVSS information could not be obtained for '{}' from '{}' source.", cve.c_str(), DEFAULT_ADP);
                }
            }
        }

        // Assign a value to the target variable if the value is not empty
        const auto assignValue = [](std::string_view& target, const flatbuffers::string_view& value)
        {
            if (!value.empty())
            {
                target = value;
            }
        };

        // Creating struct with default values.
        CveDescription cveDescription {};

        if (cvssData.data)
        {
            assignValue(cveDescription.accessComplexity, cvssData.data->accessComplexity()->string_view());
            assignValue(cveDescription.attackVector, cvssData.data->attackVector()->string_view());
            assignValue(cveDescription.authentication, cvssData.data->authentication()->string_view());
            assignValue(cveDescription.availabilityImpact, cvssData.data->availabilityImpact()->string_view());
            assignValue(cveDescription.classification, cvssData.data->classification()->string_view());
            assignValue(cveDescription.confidentialityImpact, cvssData.data->confidentialityImpact()->string_view());
            assignValue(cveDescription.integrityImpact, cvssData.data->integrityImpact()->string_view());
            assignValue(cveDescription.privilegesRequired, cvssData.data->privilegesRequired()->string_view());
            assignValue(cveDescription.scope, cvssData.data->scope()->string_view());
            assignValue(cveDescription.scoreVersion, cvssData.data->scoreVersion()->string_view());
            assignValue(cveDescription.severity, cvssData.data->severity()->string_view());
            assignValue(cveDescription.userInteraction, cvssData.data->userInteraction()->string_view());
            cveDescription.scoreBase = cvssData.data->scoreBase();
        }

        if (descriptionData.data)
        {
            assignValue(cveDescription.assignerShortName, descriptionData.data->assignerShortName()->string_view());
            assignValue(cveDescription.cweId, descriptionData.data->cweId()->string_view());
            assignValue(cveDescription.datePublished, descriptionData.data->datePublished()->string_view());
            assignValue(cveDescription.dateUpdated, descriptionData.data->dateUpdated()->string_view());
            assignValue(cveDescription.description, descriptionData.data->description()->string_view());
            assignValue(cveDescription.reference, descriptionData.data->reference()->string_view());
        }

        // Call the callback function with the CveDescription object
        callback(cveDescription);
    }
};

#endif // _DESCRIPTIONS_HELPER_HPP
