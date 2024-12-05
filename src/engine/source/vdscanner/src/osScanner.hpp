/*
 * Wazuh Vulnerability scanner - Scan Orchestrator
 * Copyright (C) 2015, Wazuh Inc.
 * May 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OS_SCANNER_HPP
#define _OS_SCANNER_HPP

#include "base/utils/chainOfResponsability.hpp"
#include "databaseFeedManager.hpp"
#include "scanContext.hpp"
#include "scannerHelper.hpp"
#include "versionMatcher/versionMatcher.hpp"

auto constexpr OS_SCANNER_CNA {"nvd"};

/**
 * @brief OsScanner class.
 * This class is in charge of scanning the OS for vulnerabilities.
 * It receives the scan context and the database feed manager and returns the scan context with the vulnerabilities
 * found. The OS scanner is in charge of scanning the OS for vulnerabilities and updating the scan context with the
 * vulnerabilities found. The OS scanner is also in charge of updating the scan context with the match conditions for
 * the vulnerabilities found.
 *
 */
template<typename TDatabaseFeedManager = DatabaseFeedManager, typename TScanContext = ScanContext>
class TOsScanner final : public utils::patterns::AbstractHandler<std::shared_ptr<TScanContext>>
{
private:
    std::shared_ptr<TDatabaseFeedManager> m_databaseFeedManager;

public:
    /**
     * @brief OsScanner constructor.
     *
     * @param databaseFeedManager Database feed manager.
     */
    explicit TOsScanner(std::shared_ptr<TDatabaseFeedManager> databaseFeedManager)
        : m_databaseFeedManager(std::move(databaseFeedManager))
    {
    }
    /**
     * @brief Handles request and passes control to the next step of the chain.
     *
     * @param data Scan context.
     * @return std::shared_ptr<ScanContext> Abstract handler.
     */
    // LCOV_EXCL_START
    std::shared_ptr<ScanContext> handleRequest(std::shared_ptr<TScanContext> data) override
    {
        const auto hotfixes = data->hotfixes();

        const auto osCPE = ScannerHelper::parseCPE(data->osCPEName(m_databaseFeedManager->cpeMappings()).data());

        auto vulnerabilityScan = [&, functionName = logging::getLambdaName(__FUNCTION__, "vulnerabilityScan")](
                                     const std::string& cnaName,
                                     const PackageData& package,
                                     const NSVulnerabilityScanner::ScanVulnerabilityCandidate& callbackData)
        {
            try
            {
                VersionObjectType objectType = VersionObjectType::DPKG;
                for (const auto& version : *callbackData.versions())
                {
                    const std::string osVersion {data->osVersion()};
                    std::string versionString {version->version() ? version->version()->str() : ""};
                    std::string versionStringLessThan {version->lessThan() ? version->lessThan()->str() : ""};
                    std::string versionStringLessThanOrEqual {
                        version->lessThanOrEqual() ? version->lessThanOrEqual()->str() : ""};
                    LOG_DEBUG_L(
                        functionName.c_str(),
                        "Scanning OS - '{}' (Installed Version: {}, Security Vulnerability: {}). Identified "
                        "vulnerability: "
                        "Version: {}. Required Version Threshold: {}. Required Version Threshold (or Equal): {}.",
                        osCPE.product,
                        osVersion,
                        callbackData.cveId()->str(),
                        versionString,
                        versionStringLessThan,
                        versionStringLessThanOrEqual);

                    // No version range specified, check if the installed version is equal to the required version.
                    if (versionStringLessThan.empty() && versionStringLessThanOrEqual.empty())
                    {
                        if (VersionMatcher::compare(osVersion, versionString, objectType)
                            == VersionComparisonResult::A_EQUAL_B)
                        {
                            // Version match found, the package status is defined by the vulnerability status.
                            if (version->status() == NSVulnerabilityScanner::Status::Status_affected)
                            {
                                LOG_DEBUG_L(functionName.c_str(),
                                            "Match found, the OS '{}', is vulnerable to '{}'. Current version: '{}' is "
                                            "equal to '{}'. - Agent '{}' (ID: '{}', Version: '{}').",
                                            osCPE.product,
                                            callbackData.cveId()->str(),
                                            osVersion,
                                            versionString,
                                            data->agentName(),
                                            data->agentId(),
                                            data->agentVersion());

                                data->m_elements[callbackData.cveId()->str()] = nlohmann::json::object();
                                data->m_matchConditions[callbackData.cveId()->str()] = {std::move(versionString),
                                                                                        MatchRuleCondition::Equal};
                                return true;
                            }

                            return false;
                        }
                    }
                    else
                    {
                        // Version range specified
                        // Check if the installed version satisfies the lower bound of the version range.
                        auto lowerBoundMatch = false;
                        if (versionString.compare("0") == 0)
                        {
                            lowerBoundMatch = true;
                        }
                        else
                        {
                            const auto matchResult = VersionMatcher::compare(osVersion, versionString, objectType);
                            lowerBoundMatch = matchResult == VersionComparisonResult::A_GREATER_THAN_B
                                              || matchResult == VersionComparisonResult::A_EQUAL_B;
                        }

                        if (lowerBoundMatch)
                        {
                            // Check if the installed version satisfies the upper bound of the version range.
                            auto upperBoundMatch = false;
                            if (!versionStringLessThan.empty() && versionStringLessThan.compare("*") != 0)
                            {
                                const auto matchResult =
                                    VersionMatcher::compare(osVersion, versionStringLessThan, objectType);
                                upperBoundMatch = matchResult == VersionComparisonResult::A_LESS_THAN_B;
                            }
                            else if (!versionStringLessThanOrEqual.empty())
                            {
                                const auto matchResult =
                                    VersionMatcher::compare(osVersion, versionStringLessThanOrEqual, objectType);
                                upperBoundMatch = matchResult == VersionComparisonResult::A_LESS_THAN_B
                                                  || matchResult == VersionComparisonResult::A_EQUAL_B;
                            }
                            else
                            {
                                upperBoundMatch = false;
                            }

                            if (upperBoundMatch)
                            {
                                // Version match found, the package status is defined by the vulnerability status.
                                if (version->status() == NSVulnerabilityScanner::Status::Status_affected)
                                {
                                    LOG_DEBUG_L(
                                        functionName.c_str(),
                                        "Match found, the OS '{}', is vulnerable to '{}'. Current version: "
                                        "'{}' ("
                                        "less than '{}' or equal to '{}'). - Agent '{}' (ID: '{}', Version: '{}').",
                                        osCPE.product,
                                        callbackData.cveId()->str(),
                                        osVersion,
                                        versionStringLessThan,
                                        versionStringLessThanOrEqual,
                                        data->agentName(),
                                        data->agentId(),
                                        data->agentVersion());

                                    data->m_elements[callbackData.cveId()->str()] = nlohmann::json::object();

                                    if (!versionStringLessThanOrEqual.empty())
                                    {
                                        data->m_matchConditions[callbackData.cveId()->str()] = {
                                            std::move(versionStringLessThanOrEqual),
                                            MatchRuleCondition::LessThanOrEqual};
                                    }
                                    else
                                    {
                                        data->m_matchConditions[callbackData.cveId()->str()] = {
                                            std::move(versionStringLessThan), MatchRuleCondition::LessThan};
                                    }
                                    return true;
                                }
                                else
                                {
                                    LOG_DEBUG_L(
                                        functionName.c_str(),
                                        "No match due to default status for OS: {}, Version: {} while scanning "
                                        "for Vulnerability: {}, "
                                        "Installed Version: {}, Required Version Threshold: {}, Required Version "
                                        "Threshold (or Equal): {}",
                                        osCPE.product,
                                        osVersion,
                                        callbackData.cveId()->str(),
                                        versionString,
                                        versionStringLessThan,
                                        versionStringLessThanOrEqual);

                                    return false;
                                }
                            }
                        }
                    }
                }

                // No match found, the default status defines the package status.
                if (callbackData.defaultStatus() == NSVulnerabilityScanner::Status::Status_affected)
                {
                    LOG_DEBUG_L(functionName.c_str(),
                                "Match found for OS: {} for vulnerability: {} due to default status.",
                                osCPE.product,
                                callbackData.cveId()->str());

                    data->m_elements[callbackData.cveId()->str()] = nlohmann::json::object();

                    data->m_matchConditions[callbackData.cveId()->str()] = {"", MatchRuleCondition::DefaultStatus};
                    return true;
                }

                LOG_DEBUG_L(
                    functionName.c_str(),
                    "No match due to default status for OS: {}, Version: {} while scanning for Vulnerability: {}",
                    osCPE.product,
                    data->osVersion(),
                    callbackData.cveId()->str());

                return false;
            }
            catch (const std::exception& e)
            {
                // Log the warning and continue with the next vulnerability.
                LOG_DEBUG_L(functionName.c_str(),
                            "Failed to scan OS: '{}', CVE Numbering Authorities (CNA): '{}', Error: '{}'",
                            osCPE.product,
                            cnaName,
                            e.what());

                return false;
            }
        };

        try
        {
            if (data->osPlatform() == "windows" || data->osPlatform() == "darwin")
            {
                if (osCPE.product.empty())
                {
                    LOG_DEBUG("No CPE product found for OS '{}' on Agent '{}'.", data->osName(), data->agentId());
                }
                else
                {
                    PackageData package = {.name = osCPE.product};

                    data->m_vulnerabilitySource = std::make_pair(OS_SCANNER_CNA, OS_SCANNER_CNA);

                    m_databaseFeedManager->getVulnerabilitiesCandidates(OS_SCANNER_CNA, package, vulnerabilityScan);

                    if (data->osPlatform() == "windows")
                    {
                        std::vector<std::string> cvesRemediated;

                        auto it = data->m_elements.begin();
                        while (it != data->m_elements.end())
                        {
                            const auto& cve = it->first;
                            FlatbufferDataPair<NSVulnerabilityScanner::RemediationInfo> remediations {};
                            m_databaseFeedManager->getVulnerabilityRemediation(cve, remediations);

                            if (remediations.data == nullptr || remediations.data->updates() == nullptr
                                || remediations.data->updates()->size() == 0)
                            {
                                LOG_DEBUG(
                                    "No remediation available for OS '{}' on Agent '{}' for CVE: '{}', discarding.",
                                    osCPE.product,
                                    data->agentId(),
                                    cve);
                                it = data->m_elements.erase(it);
                                continue;
                            }

                            for (const auto& remediation : *(remediations.data->updates()))
                            {
                                // Delete element if the update is already installed
                                if (std::find_if(hotfixes.begin(),
                                                 hotfixes.end(),
                                                 [&](const auto& element) {
                                                     return element.template get_ref<const std::string&>()
                                                            == remediation->str();
                                                 })
                                    != hotfixes.end())
                                {
                                    LOG_DEBUG("Remediation for OS '{}' on Agent '{}' has been found. CVE: '{}', "
                                              "Remediation: '{}'.",
                                              osCPE.product,
                                              data->agentId(),
                                              cve,
                                              remediation->str());
                                    cvesRemediated.push_back(cve);
                                    break;
                                }
                            }
                            ++it;
                        }

                        for (const auto& cve : cvesRemediated)
                        {
                            data->m_elements.erase(cve);
                        }
                    }
                }
            }
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Failed to scan OS: '{}', CVE Numbering Authorities (CNA): 'nvd', Error: '{}'.",
                        osCPE.product.empty() ? data->osName() : osCPE.product,
                        e.what());
        }

        LOG_DEBUG("Vulnerability scan for OS '{}' on Agent '{}' has completed.",
                  osCPE.product.empty() ? data->osName() : osCPE.product,
                  data->agentId());

        return utils::patterns::AbstractHandler<std::shared_ptr<ScanContext>>::handleRequest(std::move(data));
    }
    // LCOV_EXCL_STOP
};

using OsScanner = TOsScanner<>;

#endif // _OS_SCANNER_HPP
