/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "repoLayout.hpp"

#include "version.hpp"

#include <cctype>

namespace
{
    using namespace std::string_view_literals;
    using namespace task_manager::upgrade;

    constexpr auto HTTP_TAG {"http://"sv};
    constexpr auto HTTPS_TAG {"https://"sv};

    /**
     * @brief The leading major-version number, or nullopt.
     *
     * Anchored, unlike parseVersion()'s search-anywhere rule: this mirrors the retired
     * sscanf("v%d...") / sscanf("%d...") pair, which required the 'v' -- when present -- to be the
     * very first character and a digit to follow immediately.
     */
    std::optional<int> leadingMajor(std::string_view version)
    {
        if (!version.empty() && version.front() == 'v')
        {
            version.remove_prefix(1);
        }

        if (version.empty() || std::isdigit(static_cast<unsigned char>(version.front())) == 0)
        {
            return std::nullopt;
        }

        int major {0};
        for (const char character : version)
        {
            if (std::isdigit(static_cast<unsigned char>(character)) == 0)
            {
                break;
            }
            if (major < 1000000)
            {
                major = major * 10 + (character - '0');
            }
        }

        return major;
    }
} // namespace

namespace task_manager::upgrade
{
    std::optional<std::string> resolveRepositoryUrl(const RepoRequest& request)
    {
        std::string repository;

        if (!request.requestedRepository.empty())
        {
            repository = request.requestedRepository;
        }
        else if (!request.configuredRepository.empty())
        {
            repository = request.configuredRepository;
        }
        else if (compareVersions(request.wpkVersion, "v4.0.0", true) < 0)
        {
            repository = WPK_REPO_URL_3_X;
        }
        else
        {
            const auto major {leadingMajor(request.wpkVersion)};
            if (!major.has_value())
            {
                return std::nullopt;
            }
            repository = std::string {WPK_REPO_URL_PREFIX} + std::to_string(*major) + WPK_REPO_URL_SUFFIX;
        }

        std::string url;
        // A value that already names a scheme keeps it, even when use_http asks for the other one.
        if (repository.find(HTTP_TAG) == std::string::npos && repository.find(HTTPS_TAG) == std::string::npos)
        {
            url = request.useHttp ? std::string {HTTP_TAG} : std::string {HTTPS_TAG};
        }

        url += repository;
        if (url.back() != '/')
        {
            url += '/';
        }

        return url;
    }

    RepoLayoutResult resolveRepoLayout(const AgentInfo& agent, const RepoRequest& request)
    {
        RepoLayoutResult result;

        if (request.wpkVersion.empty())
        {
            result.error = UpgradeError::WpkVersionDoesNotExist;
            return result;
        }

        const auto repositoryUrl {resolveRepositoryUrl(request)};
        if (!repositoryUrl.has_value())
        {
            result.error = UpgradeError::WpkVersionDoesNotExist;
            return result;
        }

        const auto& version {request.wpkVersion};
        const bool newStructure {compareVersions(version, NEW_VERSION_STRUCTURE_REPOSITORY, true) >= 0};
        std::string packageType {agent.packageType};

        if (agent.platform == "windows")
        {
            result.layout.pathUrl = *repositoryUrl + "windows/";
            result.layout.fileName = "wazuh_agent_" + version + "_windows.wpk";
        }
        else if (agent.platform == "darwin")
        {
            if (newStructure)
            {
                const auto architecture {translateArch(agent.platform, packageType, agent.architecture)};
                result.layout.pathUrl = *repositoryUrl + "macos/" + packageType + "/" + architecture + "/";
                result.layout.fileName =
                    "wazuh_agent_" + version + "_macos_" + architecture + "." + packageType + ".wpk";
            }
            else
            {
                // Note the inverted order relative to the new structure: <arch>/<pkg>, not <pkg>/<arch>.
                result.layout.pathUrl = *repositoryUrl + "macos/" + agent.architecture + "/" + packageType + "/";
                result.layout.fileName = "wazuh_agent_" + version + "_macos_" + agent.architecture + ".wpk";
            }
        }
        else if (compareVersions(version, NEW_LINUX_VERSION_REPOSITORY, true) >= 0)
        {
            if (newStructure)
            {
                if (!request.requestedPackageType.empty())
                {
                    if (packageType.empty())
                    {
                        packageType = request.requestedPackageType;
                        result.notice = PackageTypeNotice::DefaultedFromRequest;
                    }
                    else if (packageType != request.requestedPackageType)
                    {
                        if (request.forceUpgrade)
                        {
                            packageType = request.requestedPackageType;
                            result.notice = PackageTypeNotice::ForcedOverride;
                        }
                        else
                        {
                            result.notice = PackageTypeNotice::MismatchIgnored;
                        }
                    }
                }
                else if (packageType.empty())
                {
                    // No family from the distribution and none named by the caller: this shape puts
                    // the package type in the path, so there is simply no URL to build.
                    result.error = UpgradeError::SystemNotSupported;
                    return result;
                }

                const auto architecture {translateArch(agent.platform, packageType, agent.architecture)};
                result.layout.pathUrl = *repositoryUrl + "linux/" + packageType + "/" + architecture + "/";
                result.layout.fileName =
                    "wazuh_agent_" + version + "_linux_" + architecture + "." + packageType + ".wpk";
            }
            else
            {
                result.layout.pathUrl = *repositoryUrl + "linux/" + agent.architecture + "/";
                result.layout.fileName = "wazuh_agent_" + version + "_linux_" + agent.architecture + ".wpk";
            }
        }
        else if (agent.platform == "ubuntu")
        {
            result.layout.pathUrl = *repositoryUrl + agent.platform + "/" + agent.majorVersion + "." +
                                    agent.minorVersion + "/" + agent.architecture + "/";
            result.layout.fileName = "wazuh_agent_" + version + "_" + agent.platform + "_" + agent.majorVersion + "." +
                                     agent.minorVersion + "_" + agent.architecture + ".wpk";
        }
        else
        {
            result.layout.pathUrl =
                *repositoryUrl + agent.platform + "/" + agent.majorVersion + "/" + agent.architecture + "/";
            result.layout.fileName = "wazuh_agent_" + version + "_" + agent.platform + "_" + agent.majorVersion + "_" +
                                     agent.architecture + ".wpk";
        }

        result.layout.versionsUrl = result.layout.pathUrl + "versions";
        result.layout.packageType = std::move(packageType);
        return result;
    }
} // namespace task_manager::upgrade
