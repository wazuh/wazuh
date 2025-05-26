/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <map>
#include <mutex>
#include <string>
#include <vector>
#include <memory>
#include <set>

#include "json.hpp"
#include "ipasswd_wrapper.hpp"
#include "isystem_wrapper.hpp"

/// @brief Provides user information by querying local and remote user data.
///
/// This class collects user details from the system using wrapped system and passwd APIs.
/// It supports filtering by usernames and UIDs and can include or exclude remote users.
class UsersProvider
{
    public:
        /// @brief Constructs a UsersProvider with the given wrappers.
        /// @param passwdWrapper Wrapper for password database operations.
        /// @param sysWrapper Wrapper for system-level operations.
        explicit UsersProvider(
            std::shared_ptr<IPasswdWrapper> passwdWrapper,
            std::shared_ptr<ISystemWrapper> sysWrapper);

        /// @brief Default constructor.
        UsersProvider();

        /// @brief Collects all user information, optionally including remote users.
        /// @param include_remote Whether to include remote users in the collection (default: true).
        /// @return JSON array of user information objects.
        nlohmann::json collect(bool include_remote = true);

        /// @brief Collects user information filtered by usernames and UIDs, optionally including remote users.
        /// @param usernames Set of usernames to filter.
        /// @param uids Set of UIDs to filter.
        /// @param include_remote Whether to include remote users in the collection.
        /// @return JSON array of user information objects matching the constraints.
        nlohmann::json collectWithConstraints(const std::set<std::string>& usernames,
                                              const std::set<uid_t>& uids,
                                              bool include_remote);

    private:
        /// @brief Generates a JSON representation of a user from passwd struct.
        /// @param pwd Pointer to passwd struct representing the user.
        /// @param include_remote String indicating whether remote users are included.
        /// @return JSON object representing the user.
        nlohmann::json genUserJson(const struct passwd* pwd, const std::string& include_remote);

        /// @brief Collects local users filtered by usernames and UIDs.
        /// @param usernames Set of usernames to filter.
        /// @param uids Set of UIDs to filter.
        /// @return JSON array of local user information.
        nlohmann::json collectLocalUsers(const std::set<std::string>& usernames,
                                         const std::set<uid_t>& uids);

        /// @brief Collects remote users filtered by usernames and UIDs.
        /// @param usernames Set of usernames to filter.
        /// @param uids Set of UIDs to filter.
        /// @return JSON array of remote user information.
        nlohmann::json collectRemoteUsers(const std::set<std::string>& usernames,
                                          const std::set<uid_t>& uids);

        /// @brief System wrapper dependency.
        std::shared_ptr<ISystemWrapper> m_sysWrapper;

        /// @brief Passwd wrapper dependency.
        std::shared_ptr<IPasswdWrapper> m_passwdWrapper;
};
