/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "igroup_wrapper.hpp"

#include <grp.h>
#include <unistd.h>

// This symbol is exported from libSystem.B and has been since 10.6.
extern "C" int getgroupcount(const char* name, gid_t basegid);

/// @brief Wrapper class for group-related operations on Darwin/macOS systems.
///
/// Provides methods to retrieve group lists and counts for users, allowing for dependency injection
/// and easier testing. This class implements the IGroupWrapperDarwin interface and uses the system calls
/// to interact with the group database.
class GroupWrapperDarwin : public IGroupWrapperDarwin
{
    public:
        /// @brief Retrieves a group by its GID.
        /// @param gid The group ID for which to retrieve the group structure.
        /// @return A pointer to the group structure if found, or nullptr if not found.
        struct group* getgrgid(gid_t gid) const override
        {
            return ::getgrgid(gid);
        }

        /// @brief Retrieves a group by its name.
        /// @param name The name of the group to retrieve.
        /// @return A pointer to the group structure if found, or nullptr if not found.
        struct group* getgrnam(const char* name) const override
        {
            return ::getgrnam(name);
        }

        /// @brief Retrieves the list of groups for a user.
        /// @param user The username for which to retrieve the group list.
        /// @param group The primary group ID of the user.
        /// @param groups Pointer to an array where the group IDs will be stored.
        /// @param ngroups Pointer to an integer that indicates the size of the groups array.
        /// @return The number of groups the user belongs to, or -1 on error.
        int getgrouplist(const char* user, gid_t group, gid_t* groups, int* ngroups) const override
        {
            return ::getgrouplist(user, group, (int*)groups, ngroups);
        }

        /// @brief Retrieves the count of groups for a user.
        /// @details This method is used to determine how many groups a user belongs to, which can be useful
        ///          for allocating the appropriate size for the groups array.
        /// @param user The username for which to count the groups.
        /// @param group The primary group ID of the user.
        /// @return The number of groups the user belongs to, or -1 on error.
        int getgroupcount(const char* user, gid_t group) const override
        {
            return ::getgroupcount(user, group);
        }
};
