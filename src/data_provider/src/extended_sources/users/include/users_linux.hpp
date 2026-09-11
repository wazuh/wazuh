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
            std::shared_ptr<IPasswdWrapperLinux> passwdWrapper,
            std::shared_ptr<ISystemWrapper> sysWrapper);

        /// @brief Default constructor.
        UsersProvider();

        /// @brief Collects all user information, optionally including remote users.
        ///
        /// @note Selects the enumeration source; it is not a per-user attribute. Each account
        ///       carries its own "is_remote" flag. False enumerates /etc/passwd only, which drops
        ///       every directory account.
        /// @param include_remote Whether to include remote users in the collection (default: true).
        /// @return JSON array of user information objects.
        nlohmann::json collect(bool include_remote = true);

        /// @brief Collects user information filtered by usernames and UIDs, optionally including remote users.
        /// @param usernames Set of usernames to filter.
        /// @param uids Set of UIDs to filter.
        /// @param include_remote Selects the enumeration source; see collect().
        /// @return JSON array of user information objects matching the constraints.
        nlohmann::json collectWithConstraints(const std::set<std::string>& usernames,
                                              const std::set<uid_t>& uids,
                                              bool include_remote);

    private:
        /// @brief Generates a JSON representation of a user from passwd struct.
        /// @param pwd Pointer to passwd struct representing the user.
        /// @param isRemote Whether this particular account is defined only in a directory service.
        /// @return JSON object representing the user.
        nlohmann::json genUserJson(const struct passwd* pwd, bool isRemote);

        /// @brief Size for the getpw_r/fgetpwent_r scratch buffer, clamped to a sane maximum.
        /// @return Buffer size in bytes.
        size_t passwdBufferSize() const;

        /// @brief Reads the usernames defined in /etc/passwd, to tell locally defined accounts from
        ///        directory ones. Never filtered: classification needs the complete local picture.
        /// @return Set of usernames present in /etc/passwd; empty if it cannot be read.
        std::set<std::string> collectLocalUsernames();

        /// @brief Collects local users filtered by usernames and UIDs.
        /// @param usernames Set of usernames to filter.
        /// @param uids Set of UIDs to filter.
        /// @return JSON array of local user information.
        nlohmann::json collectLocalUsers(const std::set<std::string>& usernames,
                                         const std::set<uid_t>& uids);

        /// @brief Collects users from NSS, classifying each one as local or directory-provided.
        ///        Resolved against /etc/passwd after the enumeration closes; if the file cannot be
        ///        read every row is reported local.
        /// @param usernames Set of usernames to filter.
        /// @param uids Set of UIDs to filter.
        /// @return JSON array of user information.
        nlohmann::json collectRemoteUsers(const std::set<std::string>& usernames,
                                          const std::set<uid_t>& uids);

        /// @brief Passwd wrapper dependency.
        std::shared_ptr<IPasswdWrapperLinux> m_passwdWrapper;

        /// @brief System wrapper dependency.
        std::shared_ptr<ISystemWrapper> m_sysWrapper;
};
