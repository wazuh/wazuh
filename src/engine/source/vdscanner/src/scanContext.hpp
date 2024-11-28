/*
 * Wazuh Vulnerability scanner - Scan Orchestrator
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SCAN_CONTEXT_HPP
#define _SCAN_CONTEXT_HPP

#include "base/utils/stringUtils.hpp"
#include <nlohmann/json.hpp>
#include <string>

auto constexpr DEFAULT_CNA {"nvd"};

enum VulnerabilitySource
{
    ADP_BASE = 0,
    ADP_EXPANDED = 1
};

enum class ScannerType
{
    Unknown = 0,
    Os = 1,
    Package = 2
};

// Match rule condition.
enum class MatchRuleCondition
{
    Unknown = 0,
    Equal = 1,
    NotEqual = 2,
    GreaterThan = 3,
    GreaterThanOrEqual = 4,
    LessThan = 5,
    LessThanOrEqual = 6,
    Contains = 7,
    NotContains = 8,
    StartsWith = 9,
    EndsWith = 10,
    DefaultStatus = 11,
};

/**
 * @brief MatchCondition structure.
 */
struct MatchCondition
{
    std::string version;          ///< Version.
    MatchRuleCondition condition; ///< Condition.
};

/**
 * @brief ScanContext structure.
 *
 */
struct ScanContext final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class constructor.
     *
     */
    ScanContext() = delete;
    // LCOV_EXCL_STOP

    /**
     * @brief Class constructor.
     *
     * @param data Scan context.
     */
    explicit ScanContext(const ScannerType type,
                         const nlohmann::json& agent,
                         const nlohmann::json& os,
                         const nlohmann::json& package,
                         const nlohmann::json& hotfixes,
                         nlohmann::json& response)
        : m_type {type}
        , packageData {package}
        , agentData {agent}
        , osData {os}
        , hotfixesData {hotfixes}
        , responseData {response}
    {
    }

    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~ScanContext() = default;
    // LCOV_EXCL_STOP

    /**
     * @brief Gets package name.
     * @return Package name.
     */
    std::string_view packageName() const
    {
        return packageData.contains("/name"_json_pointer)
                   ? packageData.at("/name"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets package version.
     * @return Package version.
     */
    std::string_view packageVersion() const
    {
        return packageData.contains("/version"_json_pointer)
                   ? packageData.at("/version"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets vendor name.
     * @return Vendor name.
     */
    std::string_view packageVendor() const
    {
        return packageData.contains("/vendor"_json_pointer)
                   ? packageData.at("/vendor"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets package install time.
     * @return Package install time.
     */
    std::string_view packageInstallTime() const
    {
        return packageData.contains("/install_time"_json_pointer)
                   ? packageData.at("/install_time"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets package location.
     * @return Package location.
     */
    std::string_view packageLocation() const
    {
        return packageData.contains("/location"_json_pointer)
                   ? packageData.at("/location"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets package architecture.
     * @return Package architecture.
     */
    std::string_view packageArchitecture() const
    {
        return packageData.contains("/architecture"_json_pointer)
                   ? packageData.at("/architecture"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets package groups.
     * @return Package groups.
     */
    std::string_view packageGroups() const
    {
        return packageData.contains("/groups"_json_pointer)
                   ? packageData.at("/groups"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets package description
     * @return Package description.
     */
    std::string_view packageDescription() const
    {
        return packageData.contains("/description"_json_pointer)
                   ? packageData.at("/description"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets package size.
     * @return Package size.
     */
    uint64_t packageSize() const
    {
        return packageData.contains("/size"_json_pointer) ? packageData.at("/size"_json_pointer).get<uint64_t>() : 0;
    }

    /**
     * @brief Gets package priority.
     * @return Package priority.
     */
    std::string_view packagePriority() const
    {
        return packageData.contains("/priority"_json_pointer)
                   ? packageData.at("/priority"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets package multi arch.
     * @return Package multi arch.
     */
    std::string_view packageMultiarch() const
    {
        return packageData.contains("/multiarch"_json_pointer)
                   ? packageData.at("/multiarch"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets package source
     * @return Package source.
     */
    std::string_view packageSource() const
    {
        return packageData.contains("/source"_json_pointer)
                   ? packageData.at("/source"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets package format.
     * @return Package format.
     */
    std::string_view packageFormat() const
    {
        return packageData.contains("/format"_json_pointer)
                   ? packageData.at("/format"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets package id.
     * @return Package id.
     */
    std::string_view packageItemId() const
    {
        return packageData.contains("/item_id"_json_pointer)
                   ? packageData.at("/item_id"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets agent id.
     * @return Agent id.
     */
    std::string_view agentId() const
    {
        return agentData.contains("/id"_json_pointer)
                   ? agentData.at("/id"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets agent IP.
     *
     * @return Agent IP.
     */
    std::string_view agentIp() const
    {
        return agentData.contains("/ip"_json_pointer)
                   ? agentData.at("/ip"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets agent name.
     *
     * @return Agent name.
     */
    std::string_view agentName() const
    {
        return agentData.contains("/name"_json_pointer)
                   ? agentData.at("/name"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets agent version.
     *
     * @return Agent version.
     */
    std::string_view agentVersion() const
    {
        return agentData.contains("/version"_json_pointer)
                   ? agentData.at("/version"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets os hostName.
     * @return Os hostName.
     */
    std::string_view osHostName() const
    {
        return osData.contains("/hostname"_json_pointer)
                   ? osData.at("/hostname"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets os architecture.
     * @return Os architecture.
     */
    std::string_view osArchitecture() const
    {
        return osData.contains("/architecture"_json_pointer)
                   ? osData.at("/architecture"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets os name.
     * @return Os name.
     */
    std::string_view osName() const
    {
        return osData.contains("/name"_json_pointer)
                   ? osData.at("/name"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets os version.
     * @return Os version.
     */
    std::string_view osVersion() const
    {
        return osData.contains("/version"_json_pointer)
                   ? osData.at("/version"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets os codeName.
     * @return Os codeName.
     */
    std::string_view osCodeName() const
    {
        return osData.contains("/codename"_json_pointer)
                   ? osData.at("/codename"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets os major version.
     * @return Os major version.
     */
    std::string_view osMajorVersion() const
    {
        return osData.contains("/major_version"_json_pointer)
                   ? osData.at("/major_version"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets os minor version.
     * @return Os minor version.
     */
    std::string_view osMinorVersion() const
    {
        return osData.contains("/minor_version"_json_pointer)
                   ? osData.at("/minor_version"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets os patch version.
     * @return Os patch version.
     */
    std::string_view osPatch() const
    {
        return osData.contains("/patch"_json_pointer)
                   ? osData.at("/patch"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets os build number.
     * @return Os build number.
     */
    std::string_view osBuild() const
    {
        return osData.contains("/build"_json_pointer)
                   ? osData.at("/build"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets os platform.
     * @return Os platform.
     */
    std::string_view osPlatform() const
    {
        return osData.contains("/platform"_json_pointer)
                   ? osData.at("/platform"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets os kernel sysName.
     * @return Os kernel sysName.
     */
    std::string_view osKernelSysName() const
    {
        return osData.contains("/kernel_name"_json_pointer)
                   ? osData.at("/kernel_name"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets os kernel release.
     * @return Os kernel release.
     */
    std::string_view osKernelRelease() const
    {
        return osData.contains("/kernel_release"_json_pointer)
                   ? osData.at("/kernel_release"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets os kernel version.
     * @return Os kernel version.
     */
    std::string_view osKernelVersion() const
    {
        return osData.contains("/kernel_version"_json_pointer)
                   ? osData.at("/kernel_version"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets os release
     * @return Os release.
     */
    std::string_view osRelease() const
    {
        return osData.contains("/release"_json_pointer)
                   ? osData.at("/release"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets os display name.
     * @return Os display name.
     */
    std::string_view osDisplayVersion() const
    {
        return osData.contains("/display_version"_json_pointer)
                   ? osData.at("/display_version"_json_pointer).get_ref<const std::string&>().c_str()
                   : "";
    }

    /**
     * @brief Gets OS CPE.
     * @return OS CPE.
     */
    std::string_view osCPEName(const nlohmann::json& osCpeMaps)
    {
        if (m_osCPE.empty())
        {
            m_osCPE = "cpe:/o:";

            std::string cpe;
            for (auto it = osCpeMaps.rbegin(); it != osCpeMaps.rend(); ++it)
            {
                if (osName().compare(it.key()) == 0 || base::utils::string::startsWith(osName(), it.key())
                    || osPlatform().compare(it.key()) == 0)
                {
                    cpe = it.value();
                    break;
                }
            }

            if (!cpe.empty())
            {
                // Replace variables in the CPE name
                base::utils::string::replaceAll(cpe, "$(MAJOR_VERSION)", osMajorVersion());
                base::utils::string::replaceAll(cpe, "$(MINOR_VERSION)", osMinorVersion());
                base::utils::string::replaceAll(cpe, "$(DISPLAY_VERSION)", osDisplayVersion());
                base::utils::string::replaceAll(cpe, "$(VERSION)", osVersion());
                base::utils::string::replaceAll(cpe, "$(RELEASE)", osRelease());

                // For SUSE, replace the hyphen in the version with a colon, because inner the version we have the
                // version update.
                std::string versionWithHyphen {osVersion()};
                base::utils::string::replaceAll(versionWithHyphen, "-", ":");
                base::utils::string::replaceAll(cpe, "$(VERSION_UPDATE_HYPHEN)", versionWithHyphen);

                m_osCPE += base::utils::string::toLowerCase(cpe);
            }
            else
            {
                // Clear the cpeName if the OS is not supported
                m_osCPE = "";
            }
        }
        return m_osCPE;
    }

    /**
     * @brief get the hotfix identifier being installed in the current scan.
     *
     * @details If no hotfix is being installed, an empty string is returned.
     *
     * @return std::string_view hotfix identifier.
     */
    const nlohmann::json& hotfixes() const { return hotfixesData; }

    /**
     * @brief Elements to process.
     */
    std::unordered_map<std::string, nlohmann::json> m_elements;

    /**
     * @brief Elements matching the query.
     *
     */
    std::unordered_map<std::string, MatchCondition> m_matchConditions;

    /**
     * @brief Feed source information.
     *
     * @note Use @see VulnerabilitySource enum to access each field
     *
     * @return Pair with CNA/ADP base name and CNA/ADP expanded name.
     */
    std::pair<std::string, std::string> m_vulnerabilitySource = std::make_pair(DEFAULT_CNA, DEFAULT_CNA);

    ScannerType scannerType() const { return m_type; }

    /**
     * @brief Move response data.
     * @param data Data to append.
     */
    void moveResponseData(nlohmann::json& data) { responseData.push_back(std::move(data)); }

private:
    const ScannerType m_type;
    const nlohmann::json& packageData;
    const nlohmann::json& agentData;
    const nlohmann::json& osData;
    const nlohmann::json& hotfixesData;
    nlohmann::json& responseData;
    std::string m_osCPE;
};

#endif // _SCAN_CONTEXT_HPP
