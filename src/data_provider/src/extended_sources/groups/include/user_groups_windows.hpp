/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "users_utils_wrapper.hpp"
#include "groups_utils_wrapper.hpp"

#include "json.hpp"

/// @brief Class for collecting user groups information on Windows.
///
/// This class provides methods to collect user groups information from the
/// Windows operating system. It uses the Windows API to enumerate local users
/// and their associated groups. The collected data is returned in JSON format
class UserGroupsProvider
{
    public:
        /// @brief Constructs a UserGroupsProvider with specific wrappers.
        /// @param winapiWrapper A shared pointer to an IWindowsApiWrapper instance for Windows API operations.
        /// @param usersHelper A shared pointer to an IUsersHelper instance for user operations.
        /// @param groupsHelper A shared pointer to an IGroupsHelper instance for group operations.
        explicit UserGroupsProvider(std::shared_ptr<IWindowsApiWrapper> winapiWrapper,
                                    std::shared_ptr<IUsersHelper> usersHelper,
                                    std::shared_ptr<IGroupsHelper> groupsHelper);

        /// @brief Default constructor that initializes the UserGroupsProvider with default wrappers.
        /// @note This constructor uses default implementations of IWindowsApiWrapper, IUsersHelper, and IGroupsHelper.
        UserGroupsProvider();

        /// @brief Collects user groups information.
        /// @param uids A set of user IDs (UIDs) to filter the results. If empty, all users are collected.
        /// @return A JSON array containing user groups information, where each entry includes UID and GID.
        /// @note The GID is the group ID of the group that the user belongs to.
        /// @note If `uids` is empty, it collects information for all local users.
        nlohmann::json collect(const std::set<std::uint32_t>& uids = {});

        /// @brief Retrieves group names associated with the specified UIDs.
        /// @param uids A set of user IDs (UIDs) for which to retrieve group names.
        /// @return A JSON object where keys are UIDs and values are arrays of group names associated with those UIDs.
        /// If a UID has no associated groups, the value will be an empty array.
        /// @note If `uids` is empty, it retrieves group names for all users.
        /// @note If `uids` contains a single UID, the result is an array of group names.
        /// If `uids` contains multiple UIDs, the result is an object where each key is a UID and the value is an array of group names.
        nlohmann::json getGroupNamesByUid(const std::set<std::uint32_t>& uids = {});

        /// @brief Retrieves usernames associated with the specified GIDs.
        /// @param gids A set of group IDs (GIDs) for which to retrieve usernames.
        /// @return A JSON object where keys are GIDs and values are arrays of usernames associated with those GIDs.
        /// If a GID has no associated usernames, the value will be an empty array.
        /// @note If `gids` is empty, it retrieves usernames for all groups.
        /// @note If `gids` contains a single GID, the result is an array of usernames.
        /// If `gids` contains multiple GIDs, the result is an object where each key is a GID and the value is an array of usernames.
        nlohmann::json getUserNamesByGid(const std::set<std::uint32_t>& gids = {});

    private:
        std::shared_ptr<IWindowsApiWrapper> m_winapiWrapper;
        std::shared_ptr<IUsersHelper> m_usersHelper;
        std::shared_ptr<IGroupsHelper> m_groupsHelper;

        /// @brief Processes local user groups and appends the results to the provided JSON object.
        /// @param user The user for whom to process groups.
        /// @param groups A vector of groups to check against.
        /// @param results The JSON object to which the results will be appended.
        void processLocalUserGroups(const User& user, const std::vector<Group>& groups, nlohmann::json& results);

        /// @brief Retrieves local users, optionally filtered by UIDs.
        /// @param uids A set of user IDs (UIDs) to filter the results. If empty, all local users are retrieved.
        /// @return A vector of User objects representing the local users.
        std::vector<User> getLocalUsers(const std::set<std::uint32_t>& uids = {});

        /// @brief Retrieves local groups.
        /// @return A vector of Group objects representing the local groups.
        /// @note This method retrieves all local groups available on the system.
        std::vector<Group> getLocalGroups();

        /// @brief Retrieves the names of local groups for a specific user.
        /// @param username The username for which to retrieve group names.
        /// @return A vector of strings containing the names of local groups that the user belongs to.
        /// @note This method uses the Windows API to enumerate the groups associated with the specified user.
        std::vector<std::string> getLocalGroupNamesForUser(const std::string& username);
};
