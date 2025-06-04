/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "groups_utils_wrapper.hpp"

#include "json.hpp"

/// @brief Class for collecting groups information on Windows.
///
/// This class provides methods to collect groups information from the
/// Windows operating system. It uses the Windows API to enumerate local groups
/// and their associated details. The collected data is returned in JSON format.
class GroupsProvider
{
    public:
        /// @brief Constructs a GroupsProvider with a specific IGroupsHelper.
        /// @param groupsHelper A shared pointer to an IGroupsHelper instance.
        explicit GroupsProvider(std::shared_ptr<IGroupsHelper> groupsHelper);

        /// @brief Default constructor that initializes the GroupsProvider with a default IGroupsHelper.
        GroupsProvider();

        /// @brief Collects groups information.
        /// @param gids A set of group IDs (GIDs) to filter the results. If empty, all groups are collected.
        /// @return A JSON object containing the collected groups information.
        nlohmann::json collect(const std::set<std::uint32_t>& gids = {});

    private:
        /// @brief A shared pointer to an IGroupsHelper instance used for group operations.
        std::shared_ptr<IGroupsHelper> m_groupsHelper;

        /// @brief Adds a group to the results JSON object.
        /// @param results The JSON object to which the group information will be added.
        /// @param group The Group object containing the group information to be added.
        void addGroupToResults(nlohmann::json& results, const Group& group);
};