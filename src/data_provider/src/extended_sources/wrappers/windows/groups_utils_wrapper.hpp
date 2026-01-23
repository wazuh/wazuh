/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "igroups_utils_wrapper.hpp"
#include "iusers_utils_wrapper.hpp"
#include "iwindows_api_wrapper.hpp"
#include <chrono>
#include <mutex>

/// @brief Helper class for managing and retrieving Windows group information.
///
/// Provides methods to process local Windows groups and collect group data.
class GroupsHelper : public IGroupsHelper
{
    private:
        /// @brief Windows API wrapper instance used for system calls.
        std::shared_ptr<IWindowsApiWrapper> m_winapiWrapper;

        /// @brief Users helper instance for user-related operations.
        std::shared_ptr<IUsersHelper> m_usersHelper;

        /// @brief Rate limiting constants (only applied during cache refresh)
        static constexpr std::uint32_t BATCH_SIZE = 100;
        static constexpr std::chrono::milliseconds BATCH_DELAY{250};

        static constexpr std::chrono::seconds s_cacheTimeout{60}; // Cache válido por 60 segundos

        /// @brief Validates cache and clears it if expired (> 60 seconds old).
        static void validateCache();

        /// @brief Updates cache timestamp after successful operation.
        static void updateCacheTimestamp();

    public:
        /// @brief Constructs a GroupsHelper.
        /// @param winapiWrapper Shared pointer to an `IWindowsApiWrapper`.
        /// @param usersHelper Shared pointer to an `IUsersHelper`.
        explicit GroupsHelper(
            std::shared_ptr<IWindowsApiWrapper> winapiWrapper, std::shared_ptr<IUsersHelper> usersHelper);

        /// @brief Default constructor.
        GroupsHelper();

        /// @brief Processes local Windows groups and collects group data.
        /// @return Vector of Group objects representing local groups.
        std::vector<Group> processLocalGroups() override;

        /// @brief Resets the cache.
        static void resetCache();
};
