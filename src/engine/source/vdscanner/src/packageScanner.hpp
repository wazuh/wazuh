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

#ifndef _PACKAGE_SCANNER_HPP
#define _PACKAGE_SCANNER_HPP

#include "base/logging.hpp"
#include "base/utils/chainOfResponsability.hpp"
#include "base/utils/stringUtils.hpp"
#include "databaseFeedManager.hpp"
#include "scanContext.hpp"
#include "scannerHelper.hpp"
#include "versionMatcher/versionMatcher.hpp"
#include <memory>
#include <variant>

auto constexpr L1_CACHE_SIZE {2048};

/**
 * @brief PackageScanner class.
 * This class is responsible for scanning the package and checking if it is vulnerable.
 * It receives the scan context and the database feed manager and returns the scan context with the vulnerability
 * details. The package format is used to determine the version object type or the version matcher strategy. The package
 * format can be deb, rpm, pypi, npm, pacman, snap, pkg, apk, win, macports. The vulnerability scan is performed using
 * the database feed manager.
 */
template<typename TDatabaseFeedManager = DatabaseFeedManager, typename TScanContext = ScanContext>
class TPackageScanner final : public utils::patterns::AbstractHandler<std::shared_ptr<TScanContext>>
{
private:
    /**
     * @brief Package format to VersionObjectType / VersionMatcherStrategy map.
     *
     * @note The map is used to determine the version object type or the version matcher strategy based on the package
     * format.
     */
    std::unordered_map<std::string_view, std::variant<VersionObjectType, VersionMatcherStrategy>> m_packageMap {
        {"deb", VersionObjectType::DPKG},
        {"rpm", VersionObjectType::RPM},
        {"pypi", VersionObjectType::PEP440},
        {"npm", VersionObjectType::SemVer},
        {"pacman", VersionMatcherStrategy::Pacman},
        {"snap", VersionMatcherStrategy::Snap},
        {"pkg", VersionMatcherStrategy::PKG},
        {"apk", VersionMatcherStrategy::APK},
        {"win", VersionMatcherStrategy::Windows},
        {"macports", VersionMatcherStrategy::MacOS}};

    std::shared_ptr<TDatabaseFeedManager> m_databaseFeedManager;

    /**
     * @brief Scans package translation for vulnerabilities.
     *
     * This function initiates a vulnerability scan for a given package candidate. It first attempts to translate
     * the package information based on the provided operating system platform using Level 1 and Level 2 caches.
     * If translations are found, it performs a vulnerability scan for each translated package. If no translations
     * are found, it logs a debug message and initiates a vulnerability scan using the original package information.
     *
     * @param cnaName The name of the CVE Numbering Authority (CNA) responsible for the package.
     * @param data A shared pointer to the scan context, containing information about the scanning environment.
     * @param packageCandidate The package data candidate to be checked and translated for vulnerabilities.
     * @param vulnerabilityScan A function to perform the vulnerability scan. This function takes the CNA name,
     *                          package data, and a scan vulnerability candidate as arguments and returns a boolean.
     */
    void scanPackageTranslation(
        const std::string& cnaName,
        const std::shared_ptr<TScanContext> data,
        const PackageData& packageCandidate,
        const std::function<bool(const std::string& cnaName,
                                 const PackageData& package,
                                 const NSVulnerabilityScanner::ScanVulnerabilityCandidate&)>& vulnerabilityScan)
    {
        const auto osPlatform = data->osPlatform().data();
        const auto translations = m_databaseFeedManager->checkAndTranslatePackage(packageCandidate, osPlatform);

        auto scanPackage =
            [this,
             &data,
             &cnaName,
             &vulnerabilityScan,
             functionName = logging::getLambdaName(__FUNCTION__, "scanPackage")](const PackageData& package)
        {
            LOG_DEBUG_L(
                functionName.c_str(),
                "Initiating a vulnerability scan for package '{}' ({}) ({}) with CVE Numbering Authorities (CNA)"
                " '{}' on Agent '{}' (ID: '{}', Version: '{}').",
                package.name,
                package.format,
                package.vendor,
                cnaName,
                data->agentName(),
                data->agentId(),
                data->agentVersion());

            m_databaseFeedManager->getVulnerabilitiesCandidates(cnaName, package, vulnerabilityScan);
        };

        if (!translations.empty())
        {
            for (const auto& translatedPackage : translations)
            {
                scanPackage(translatedPackage);
            }
        }
        else
        {
            PackageData package = {.name = base::utils::string::toLowerCase(data->packageName().data()),
                                   .vendor = base::utils::string::toLowerCase(data->packageVendor().data()),
                                   .format = data->packageFormat().data(),
                                   .version = data->packageVersion().data()};

            scanPackage(package);
        }
    }

    /**
     * @brief Define what CNA will be used to read the data.
     *
     * @param ctx Scan context.
     * @return std::pair<std::string, std::string> CNA pair.
     *
     */
    std::pair<std::string, std::string> getCNA(std::shared_ptr<TScanContext> ctx)
    {
        auto cnaName {m_databaseFeedManager->getCnaNameByFormat(ctx->packageFormat().data())};

        if (cnaName.empty())
        {
            cnaName = m_databaseFeedManager->getCnaNameBySource(ctx->packageSource().data());
            if (cnaName.empty())
            {
                cnaName =
                    m_databaseFeedManager->getCnaNameByPrefix(ctx->packageVendor().data(), ctx->osPlatform().data());
                if (cnaName.empty())
                {
                    cnaName = m_databaseFeedManager->getCnaNameByContains(ctx->packageVendor().data(),
                                                                          ctx->osPlatform().data());
                    if (cnaName.empty())
                    {
                        return {DEFAULT_CNA, DEFAULT_CNA};
                    }
                }
            }
        }

        const auto mapping = m_databaseFeedManager->cnaMappings();

        const auto& cnaMapping = mapping.at("cnaMapping");
        const auto platformEquivalence = [&](const std::string& platform) -> const std::string&
        {
            const auto& platformMapping = mapping.at("platformEquivalence");
            if (const auto it = platformMapping.find(platform); it == platformMapping.end())
            {
                return platform;
            }
            else
            {
                return it->template get_ref<const std::string&>();
            }
        };

        const auto majorVersionEquivalence = [&](const std::string& platform,
                                                 const std::string& majorVersion) -> const std::string&
        {
            const auto& majorVersionMapping = mapping.at("majorVersionEquivalence");
            if (const auto itPlatform = majorVersionMapping.find(platform); itPlatform == majorVersionMapping.end())
            {
                return majorVersion;
            }
            else
            {
                if (const auto itMajorVersion = itPlatform->find(majorVersion); itMajorVersion == itPlatform->end())
                {
                    return majorVersion;
                }
                else
                {
                    return itMajorVersion->template get_ref<const std::string&>();
                }
            }
        };

        if (const auto it = cnaMapping.find(cnaName); it == cnaMapping.end())
        {
            return {cnaName, cnaName};
        }
        else
        {
            std::string base = it->template get<std::string>();
            base::utils::string::replaceAll(base, "$(PLATFORM)", platformEquivalence(ctx->osPlatform().data()));
            base::utils::string::replaceAll(
                base,
                "$(MAJOR_VERSION)",
                majorVersionEquivalence(ctx->osPlatform().data(), ctx->osMajorVersion().data()));
            return {cnaName, base};
        }
    }

    bool platformVerify(const std::string& cnaName,
                        const PackageData& package,
                        const NSVulnerabilityScanner::ScanVulnerabilityCandidate& callbackData,
                        std::shared_ptr<TScanContext> contextData)
    {
        // if the platforms are not empty, we need to check if the platform is in the list.
        if (callbackData.platforms())
        {
            auto agentOsCpe = contextData->osCPEName(m_databaseFeedManager->cpeMappings());
            bool matchPlatform {false};
            for (const auto& platform : *callbackData.platforms())
            {
                const std::string platformValue {platform->str()};
                // if the platform is a CPE, we need to parse it and check if the product is the same as the os
                // cpe.
                if (ScannerHelper::isCPE(platformValue))
                {
                    const auto cpe {ScannerHelper::parseCPE(platformValue)};
                    if (cpe.part.compare("o") == 0
                        && ScannerHelper::compareCPE(cpe, ScannerHelper::parseCPE(agentOsCpe)))
                    {
                        LOG_DEBUG("The platform is in the list based on CPE comparison for "
                                  "Package: {}, Version: {}, CVE: {}, Content platform CPE: {} OS CPE: {}",
                                  package.name,
                                  package.version,
                                  callbackData.cveId()->str(),
                                  platformValue,
                                  agentOsCpe);
                        matchPlatform = true;
                        break;
                    }
                }
                // If the platform is not a CPE, it is a string, at the moment, we only support the os code
                // name. This is used mainly for debian and ubuntu platforms.
                else
                {
                    if (platformValue.compare(contextData->osCodeName()) == 0)
                    {
                        LOG_DEBUG("The platform is in the list based on OS code name comparison for "
                                  "Package: {}, Version: {}, CVE: {}, Content OS code name: {}, OS code name: {}",
                                  package.name,
                                  package.version,
                                  callbackData.cveId()->str(),
                                  platformValue,
                                  contextData->osCodeName());
                        matchPlatform = true;
                        break;
                    }
                }
            }

            if (!matchPlatform)
            {
                LOG_DEBUG("The platform is not in the list for Package: {}, Version: {}, CVE: {}, OS CPE: {}, "
                          "OS code name: {}",
                          package.name,
                          package.version,
                          callbackData.cveId()->str(),
                          agentOsCpe,
                          contextData->osCodeName());
                return false;
            }
        }

        return true;
    }

    bool vendorVerify(const std::string& cnaName,
                      const PackageData& package,
                      const NSVulnerabilityScanner::ScanVulnerabilityCandidate& callbackData,
                      std::shared_ptr<TScanContext> contextData)
    {
        if (callbackData.vendor())
        {
            if (package.vendor.empty() || " " == package.vendor)
            {
                LOG_DEBUG("The vendor information is not available for Package: {}, Version: {}, "
                          "CVE: {}, Content vendor: {}",
                          package.name,
                          package.version,
                          callbackData.cveId()->str(),
                          callbackData.vendor()->str());
                return false;
            }
            else
            {
                if (package.vendor.compare(callbackData.vendor()->str()) != 0)
                {
                    LOG_DEBUG("The vendor is not the same for Package: {}, Version: {}, "
                              "CVE: {}, Content vendor: {}, Package vendor: {}",
                              package.name,
                              package.version,
                              callbackData.cveId()->str(),
                              callbackData.vendor()->str(),
                              package.vendor);
                    return false;
                }
                else
                {
                    LOG_DEBUG("Vendor match for Package: {}, Version: {}, "
                              "CVE: {}, Vendor: {}",
                              package.name,
                              package.version,
                              callbackData.cveId()->str(),
                              package.vendor);
                }
            }
        }

        return true;
    }

    bool versionMatch(const std::string& cnaName,
                      const PackageData& package,
                      const NSVulnerabilityScanner::ScanVulnerabilityCandidate& callbackData,
                      std::shared_ptr<TScanContext> contextData)
    {
        std::variant<VersionObjectType, VersionMatcherStrategy> objectType = VersionMatcherStrategy::Unspecified;
        if (const auto it = m_packageMap.find(package.format); it != m_packageMap.end())
        {
            objectType = it->second;
        }

        for (const auto& version : *callbackData.versions())
        {
            const std::string packageVersion {package.version};
            std::string versionString {version->version() ? version->version()->str() : ""};
            std::string versionStringLessThan {version->lessThan() ? version->lessThan()->str() : ""};
            std::string versionStringLessThanOrEqual {version->lessThanOrEqual() ? version->lessThanOrEqual()->str()
                                                                                 : ""};

            LOG_DEBUG("Scanning package - '{}' (Installed Version: {}, Security Vulnerability: {}). Identified "
                      "vulnerability: "
                      "Version: {}. Required Version Threshold: {}. Required Version Threshold (or Equal): {}.",
                      package.name,
                      packageVersion,
                      callbackData.cveId()->str(),
                      versionString,
                      versionStringLessThan,
                      versionStringLessThanOrEqual);

            // No version range specified, check if the installed version is equal to the required version.
            if (versionStringLessThan.empty() && versionStringLessThanOrEqual.empty())
            {
                if (VersionMatcher::compare(packageVersion, versionString, objectType)
                    == VersionComparisonResult::A_EQUAL_B)
                {
                    // Version match found, the package status is defined by the vulnerability status.
                    if (version->status() == NSVulnerabilityScanner::Status::Status_affected)
                    {
                        LOG_DEBUG("Match found, the package '{}', is vulnerable to '{}'. Current version: '{}' is "
                                  "equal to '{}'. - Agent '{}' (ID: '{}', Version: '{}').",
                                  package.name,
                                  callbackData.cveId()->str(),
                                  packageVersion,
                                  versionString,
                                  contextData->agentName(),
                                  contextData->agentId(),
                                  contextData->agentVersion());

                        contextData->m_elements[callbackData.cveId()->str()] = nlohmann::json::object();
                        contextData->m_matchConditions[callbackData.cveId()->str()] = {std::move(versionString),
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
                    const auto matchResult = VersionMatcher::compare(packageVersion, versionString, objectType);
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
                            VersionMatcher::compare(packageVersion, versionStringLessThan, objectType);
                        upperBoundMatch = matchResult == VersionComparisonResult::A_LESS_THAN_B;
                    }
                    else if (!versionStringLessThanOrEqual.empty())
                    {
                        const auto matchResult =
                            VersionMatcher::compare(packageVersion, versionStringLessThanOrEqual, objectType);
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
                            LOG_DEBUG("Match found, the package '{}', is vulnerable to '{}'. Current version: "
                                      "'{}' ("
                                      "less than '{}' or equal to '{}'). - Agent '{}' (ID: '{}', Version: '{}').",
                                      package.name,
                                      callbackData.cveId()->str(),
                                      packageVersion,
                                      versionStringLessThan,
                                      versionStringLessThanOrEqual,
                                      contextData->agentName(),
                                      contextData->agentId(),
                                      contextData->agentVersion());

                            contextData->m_elements[callbackData.cveId()->str()] = nlohmann::json::object();

                            if (!versionStringLessThanOrEqual.empty())
                            {
                                contextData->m_matchConditions[callbackData.cveId()->str()] = {
                                    std::move(versionStringLessThanOrEqual), MatchRuleCondition::LessThanOrEqual};
                            }
                            else
                            {
                                contextData->m_matchConditions[callbackData.cveId()->str()] = {
                                    std::move(versionStringLessThan), MatchRuleCondition::LessThan};
                            }
                            return true;
                        }
                        else
                        {
                            LOG_DEBUG("No match due to default status for Package: {}, Version: {} while scanning "
                                      "for Vulnerability: {}, "
                                      "Installed Version: {}, Required Version Threshold: {}, Required Version "
                                      "Threshold (or Equal): {}",
                                      package.name,
                                      packageVersion,
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
            LOG_DEBUG("Match found, the package '{}' is vulnerable to '{}' due to default status. - Agent "
                      "'{}' (ID: '{}', Version: '{}').",
                      package.name,
                      callbackData.cveId()->str(),
                      contextData->agentName(),
                      contextData->agentId(),
                      contextData->agentVersion());

            contextData->m_elements[callbackData.cveId()->str()] = nlohmann::json::object();
            contextData->m_matchConditions[callbackData.cveId()->str()] = {"", MatchRuleCondition::DefaultStatus};
            return true;
        }

        LOG_DEBUG("No match due to default status for Package: {}, Version: {} while scanning for Vulnerability: {}",
                  package.name,
                  package.version,
                  callbackData.cveId()->str());

        return false;
    }

    bool packageHotfixSolved(const std::string& cnaName,
                             const PackageData& package,
                             const NSVulnerabilityScanner::ScanVulnerabilityCandidate& callbackData,
                             std::shared_ptr<TScanContext> contextData)
    {
        FlatbufferDataPair<NSVulnerabilityScanner::RemediationInfo> remediations {};
        m_databaseFeedManager->getVulnerabilityRemediation(callbackData.cveId()->str(), remediations);

        if (remediations.data == nullptr || remediations.data->updates() == nullptr
            || remediations.data->updates()->size() == 0)
        {
            return false;
        }

        // Check that the agent has remediation data.
        auto agentRemediations = contextData->hotfixes();
        if (agentRemediations.empty())
        {
            LOG_DEBUG("No remediations for agent '{}' have been found.", contextData->agentId());
            return false;
        }

        for (const auto& remediation : *(remediations.data->updates()))
        {
            // Check if the remediation is installed on the agent.
            for (const auto& hotfix : agentRemediations)
            {
                if (hotfix.template get_ref<const std::string&>().compare(remediation->str()) == 0)
                {
                    LOG_DEBUG("Remediation '{}' for package '{}' on agent '{}' that solves CVE '{}' has been found.",
                              remediation->str(),
                              package.name,
                              contextData->agentId(),
                              callbackData.cveId()->str());

                    contextData->m_elements.erase(callbackData.cveId()->str());
                    contextData->m_matchConditions.erase(callbackData.cveId()->str());
                    return true;
                }
            }
        }

        LOG_DEBUG("No remediation for package '{}' on agent '{}' that solves CVE '{}' has been found.",
                  package.name,
                  contextData->agentId(),
                  callbackData.cveId()->str());

        return false;
    }

public:
    // LCOV_EXCL_START
    /**
     * @brief PackageScanner constructor.
     *
     * @param databaseFeedManager Database feed manager.
     */
    explicit TPackageScanner(std::shared_ptr<TDatabaseFeedManager>& databaseFeedManager)
        : m_databaseFeedManager(databaseFeedManager)
    {
    }
    // LCOV_EXCL_STOP

    /**
     * @brief Handles request and passes control to the next step of the chain.
     *
     * @param data Scan context.
     * @return std::shared_ptr<TScanContext> Abstract handler.
     */
    std::shared_ptr<TScanContext> handleRequest(std::shared_ptr<TScanContext> data) override
    {
        auto vulnerabilityScan = [&data, this, functionName = logging::getLambdaName(__FUNCTION__, "scanPackage")](
                                     const std::string& cnaName,
                                     const PackageData& package,
                                     const NSVulnerabilityScanner::ScanVulnerabilityCandidate& callbackData)
        {
            try
            {
                /* Preliminary verifications before version matching. We return if the basic conditions are not met. */

                // If the candidate contains platforms, verify if agent OS is in the list.
                if (!platformVerify(cnaName, package, callbackData, data))
                {
                    return false;
                }

                // If the candidate contains a vendor, verify if package vendor matches.
                if (!vendorVerify(cnaName, package, callbackData, data))
                {
                    return false;
                }

                /* Real version analysis of the candidate. */
                if (versionMatch(cnaName, package, callbackData, data))
                {
                    // The candidate version matches the package. Post-match filtering.
                    if (data->osPlatform().compare("windows") == 0
                        && packageHotfixSolved(cnaName, package, callbackData, data))
                    {
                        // An installed hotfix solves the vulnerability.
                        return false;
                    }

                    return true;
                }

                /* The candidate for this CVE is discarded. */
                return false;
            }
            catch (const std::exception& e)
            {
                // Log the warning and continue with the next vulnerability.
                LOG_DEBUG_L(functionName.c_str(),
                            "Failed to scan package: '{}', CVE Numbering Authorities (CNA): '{}', Error: '{}'",
                            package.name,
                            cnaName,
                            e.what());

                return false;
            }
        };

        data->m_vulnerabilitySource = getCNA(data);
        const auto& CNAValue = data->m_vulnerabilitySource.second;

        try
        {
            PackageData package = {.name = data->packageName().data(),
                                   .vendor = data->packageVendor().data(),
                                   .format = data->packageFormat().data(),
                                   .version = data->packageVersion().data()};
            scanPackageTranslation(CNAValue, data, package, vulnerabilityScan);
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Failed to scan package: '{}', CVE Numbering Authorities (CNA): '{}', Error: '{}'.",
                        data->packageName(),
                        CNAValue,
                        e.what());
        }

        // Vulnerability scan ended for agent and package...
        LOG_DEBUG(
            "Vulnerability scan for package '{}' on Agent '{}' has completed.", data->packageName(), data->agentId());

        if (data->m_elements.empty())
        {
            return nullptr;
        }
        return utils::patterns::AbstractHandler<std::shared_ptr<TScanContext>>::handleRequest(std::move(data));
    }
};

using PackageScanner = TPackageScanner<>;

#endif // _PACKAGE_SCANNER_HPP
