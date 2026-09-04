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

#ifndef _TASK_MANAGER_UPGRADE_REPO_LAYOUT_HPP
#define _TASK_MANAGER_UPGRADE_REPO_LAYOUT_HPP

#include "errorCodes.hpp"
#include "platform.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace task_manager::upgrade
{
    /// @brief Fallback repositories, byte-identical to the retired wm_agent_upgrade.h.
    constexpr const char* WPK_REPO_URL_3_X {"packages.wazuh.com/wpk/"};
    /// @brief Printf-free form of "packages.wazuh.com/%d.x/wpk/"; the major version goes in the gap.
    constexpr const char* WPK_REPO_URL_PREFIX {"packages.wazuh.com/"};
    constexpr const char* WPK_REPO_URL_SUFFIX {".x/wpk/"};

    /**
     * @brief What the caller asked for, independent of which agent it is being resolved against.
     *
     * One of these is built per request and reused for every agent in the batch, which is what makes
     * batch-level deduplication of `versions` fetches and WPK downloads possible.
     */
    struct RepoRequest
    {
        /// @brief Target version, already decided by checkRepositoryUpgrade().
        std::string wpkVersion;
        /// @brief The request's `wpk_repo` parameter. Wins over everything.
        std::string requestedRepository;
        /// @brief `<task-manager><wpk_repository>`. Used when the request names none.
        std::string configuredRepository;
        /// @brief The request's `package_type` parameter: "rpm", "deb", or empty.
        std::string requestedPackageType;
        bool useHttp {false};
        bool forceUpgrade {false};
    };

    /**
     * @brief Why the effective package type differs from what the agent reported.
     *
     * Returned instead of logged so the resolver stays pure; the orchestrator emits the message.
     */
    enum class PackageTypeNotice
    {
        /// @brief Nothing worth saying.
        None,
        /// @brief The request's package_type disagreed with the agent's and `force` let it win.
        ForcedOverride,
        /**
         * @brief The request's package_type disagreed with the agent's and was IGNORED.
         *
         * Deliberately asymmetric with ForcedOverride, and preserved from the retired C: without
         * force, a disagreement is a warning and the agent's own reported type is what gets used.
         * The agent knows what it installed; the caller is guessing.
         */
        MismatchIgnored,
        /// @brief The agent reported no package type and the request's supplied one.
        DefaultedFromRequest
    };

    /**
     * @brief Everything needed to fetch and name one WPK.
     */
    struct RepoLayout
    {
        /// @brief Directory URL, protocol included, always ending in '/'.
        std::string pathUrl;
        /// @brief Bare WPK file name, no directory part.
        std::string fileName;
        /// @brief pathUrl + "versions".
        std::string versionsUrl;
        /// @brief The package type actually used, after reconciliation.
        std::string packageType;
    };

    struct RepoLayoutResult
    {
        UpgradeError error {UpgradeError::Success};
        RepoLayout layout;
        PackageTypeNotice notice {PackageTypeNotice::None};
    };

    /**
     * @brief Resolve the repository base URL, protocol included and slash-terminated.
     *
     * Precedence: the request's `wpk_repo`, then the module's `<wpk_repository>`, then a built-in
     * default chosen by target version -- "packages.wazuh.com/wpk/" below v4.0.0 and
     * "packages.wazuh.com/<major>.x/wpk/" at or above it.
     *
     * A scheme is prepended only when the resolved value contains neither "http://" nor "https://",
     * so an operator who wrote a full URL keeps it -- including keeping https when `use_http` is set.
     * That is the retired behaviour and callers rely on it.
     *
     * Returns nullopt when the built-in default is needed but the target version has no readable
     * major number; the caller maps that to WpkVersionDoesNotExist.
     */
    std::optional<std::string> resolveRepositoryUrl(const RepoRequest& request);

    /**
     * @brief Build the directory, file name and `versions` URL for one agent.
     *
     * Six shapes, selected by platform and by two version epochs -- v3.4.0, when Linux moved to a
     * flat "linux/<arch>/" tree, and v4.9.0, when both Linux and macOS moved to
     * "<os>/<package_type>/<arch>/" with the package type in the file name:
     *
     *   windows                     windows/                              wazuh_agent_V_windows.wpk
     *   darwin      >= v4.9.0       macos/<pkg>/<arch*>/                  wazuh_agent_V_macos_<arch*>.<pkg>.wpk
     *   darwin       < v4.9.0       macos/<arch>/<pkg>/                   wazuh_agent_V_macos_<arch>.wpk
     *   linux       >= v4.9.0       linux/<pkg>/<arch*>/                  wazuh_agent_V_linux_<arch*>.<pkg>.wpk
     *   linux       >= v3.4.0       linux/<arch>/                         wazuh_agent_V_linux_<arch>.wpk
     *   ubuntu       < v3.4.0       ubuntu/<major>.<minor>/<arch>/ wazuh_agent_V_ubuntu_<major>.<minor>_<arch>.wpk
     *   other        < v3.4.0       <platform>/<major>/<arch>/            wazuh_agent_V_<platform>_<major>_<arch>.wpk
     *
     * arch* is translateArch()'d; the pre-4.9 shapes use the agent's raw architecture. Note the
     * macOS directory order INVERTS across v4.9.0 -- <pkg>/<arch> after, <arch>/<pkg> before -- which
     * is a property of the published repository, not a typo.
     *
     * Only the >= v4.9.0 Linux shape can fail: it is the only one that puts the package type in the
     * path, so an agent whose distribution resolved to no package family, with no `package_type` in
     * the request to stand in for it, has no URL at all -> SystemNotSupported.
     */
    RepoLayoutResult resolveRepoLayout(const AgentInfo& agent, const RepoRequest& request);
} // namespace task_manager::upgrade

#endif // _TASK_MANAGER_UPGRADE_REPO_LAYOUT_HPP
