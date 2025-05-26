/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "users_windows_utils_wrapper.hpp"

#include "json.hpp"

/// @brief Provides user data collection functionality.
///
/// Uses an `IUsersHelper` implementation to retrieve user information and
/// generate JSON output, optionally applying UID-based constraints.
class UsersProvider
{
    public:
        /// @brief Constructs the provider with a custom users helper.
        /// @param m_usersHelper Shared pointer to an `IUsersHelper` implementation.
        explicit UsersProvider(
            std::shared_ptr<IUsersHelper> m_usersHelper);

        /// @brief Default constructor. Uses default-initialized helper.
        UsersProvider();

        /// @brief Collects information about all users.
        /// @return A JSON array with information for each user.
        nlohmann::json collect();

        /// @brief Collects information only for users with specified UIDs.
        /// @param uids Set of UIDs to include in the collection.
        /// @return A JSON array with information for matching users.
        nlohmann::json collectWithConstraints(const std::set<std::uint32_t>& uids);

    private:
        /// @brief Generates a JSON object for a single user.
        /// @param user A `User` structure with user details.
        /// @return A JSON object representing the user.
        nlohmann::json genUserJson(const User& user);

        /// @brief Helper used to retrieve user information.
        std::shared_ptr<IUsersHelper> m_usersHelper;
};
