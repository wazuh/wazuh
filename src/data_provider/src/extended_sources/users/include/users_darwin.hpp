/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <map>
#include <memory>
#include <set>
#include <string>

#include "json.hpp"

#include "iuuid_wrapper.hpp"
#include "iopen_directory_utils_wrapper.hpp"
#include "ipasswd_wrapper_darwin.hpp"

/// @brief Provides user information on Darwin (macOS) systems.
///
/// Collects user data by combining information from the passwd database,
/// UUID conversion utilities, and OpenDirectory queries.
/// Supports filtering users by their UID.
///
/// Dependencies are injected via wrappers for testability and abstraction.
class UsersProvider
{
    public:
        /// @brief Constructs a UsersProvider with the given wrapper dependencies.
        /// @param passwdWrapper Wrapper for Darwin passwd operations.
        /// @param uuidWrapper Wrapper for UUID handling.
        /// @param odWrapper Wrapper for OpenDirectory utilities.
        explicit UsersProvider(
            std::shared_ptr<IPasswdWrapperDarwin> passwdWrapper,
            std::shared_ptr<IUUIDWrapper> uuidWrapper,
            std::shared_ptr<IODUtilsWrapper> odWrapper);

        /// @brief Default constructor.
        UsersProvider();

        /// @brief Collects all user information.
        /// @return JSON array with all user data.
        nlohmann::json collect();

        /// @brief Collects user information filtered by UIDs.
        /// @param uids Set of user IDs to filter.
        /// @return JSON array with filtered user data.
        nlohmann::json collectWithConstraints(const std::set<uid_t>& uids);

    private:
        /// @brief Generates JSON representation of a single user.
        /// @param pwd Pointer to passwd struct representing the user.
        /// @return JSON object representing the user.
        nlohmann::json genUserJson(const struct passwd* pwd);

        /// @brief Collects users filtered by UIDs.
        /// @param uids Set of user IDs to filter.
        /// @return JSON array of users matching the UIDs.
        nlohmann::json collectUsers(const std::set<uid_t>& uids);

        /// @brief Passwd utility wrapper.
        std::shared_ptr<IPasswdWrapperDarwin> m_passwdWrapper;

        /// @brief UUID utility wrapper.
        std::shared_ptr<IUUIDWrapper> m_uuidWrapper;

        /// @brief OpenDirectory utility wrapper.
        std::shared_ptr<IODUtilsWrapper> m_odWrapper;
};
