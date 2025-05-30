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

/// @brief Wrapper class for group-related operations on Linux systems.
///
/// Provides methods to retrieve group lists for users, allowing for dependency injection
/// and easier testing. This class implements the IGroupWrapperLinux interface and uses the system calls
/// to interact with the group database.
class GroupWrapperLinux : public IGroupWrapperLinux
{
    public:
        /// @brief Retrieves the list of groups for a user.
        /// @param user The username for which to retrieve the group list.
        /// @param group The primary group ID of the user.
        /// @param groups Pointer to an array where the group IDs will be stored.
        /// @param ngroups Pointer to an integer that indicates the size of the groups array.
        /// @return The number of groups the user belongs to, or -1 on error.
        int getgrouplist(const char* user, gid_t group, gid_t* groups, int* ngroups) const override
        {
            return ::getgrouplist(user, group, groups, ngroups);
        }
};
