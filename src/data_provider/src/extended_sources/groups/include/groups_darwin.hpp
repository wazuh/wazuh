/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <set>

#include "json.hpp"
#include "igroup_wrapper.hpp"
#include "iopen_directory_utils_wrapper.hpp"

/// @brief Class for collecting group information on Darwin systems.
///
/// This class provides methods to collect group information from the
/// Darwin operating system. It uses the system's group database to retrieve
/// group details such as group name and GID. The collected data is returned
/// in JSON format.
class GroupsProvider
{
    public:
        /// @brief Constructor that initializes the GroupsProvider with specific wrappers.
        /// @param groupWrapper A shared pointer to an IGroupWrapperDarwin instance for group operations.
        /// @param odWrapper A shared pointer to an IODUtilsWrapper instance for Open Directory operations.
        /// @note If the wrappers are not provided, default implementations will be used.
        explicit GroupsProvider(std::shared_ptr<IGroupWrapperDarwin> groupWrapper,
                                std::shared_ptr<IODUtilsWrapper> odWrapper);

        /// @brief Default constructor that initializes the GroupsProvider with default wrappers.
        /// @note This constructor uses default implementations of IGroupWrapperDarwin and IODUtilsWrapper.
        GroupsProvider();

        /// @brief Collects group information based on the provided set of GIDs.
        /// @param gids A set of GIDs to filter the groups. If empty, all groups will be collected.
        /// @return A JSON array containing group information, where each group is represented as a JSON object.
        nlohmann::json collect(const std::set<gid_t>& gids = {});

    private:
        std::shared_ptr<IGroupWrapperDarwin> m_groupWrapper;
        std::shared_ptr<IODUtilsWrapper> m_odWrapper;

        /// @brief Generates a row of group information.
        /// @param group A pointer to the group structure containing the group information.
        /// @return A JSON object representing the group information.
        nlohmann::json genGroupJson(const struct group* group);
};
