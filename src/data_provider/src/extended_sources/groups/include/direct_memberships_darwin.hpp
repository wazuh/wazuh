/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <map>
#include <memory>
#include <set>
#include <string>
#include <sys/types.h>
#include <vector>

#include "igroup_wrapper.hpp"
#include "iopen_directory_utils_wrapper.hpp"

/// @brief The groups each macOS account is a direct member of.
///
/// getgrouplist() answers with the effective groups, which include every group reached through
/// nesting: a File Sharing group that nests `everyone` shows up on every account. This class
/// answers with the groups that list the account themselves, by name or by GUID, plus the
/// account's primary group. The groups are read from OpenDirectory once, the first time a user
/// is asked about.
class DirectMemberships
{
    public:
        DirectMemberships(std::shared_ptr<IGroupWrapperDarwin> groupWrapper,
                          std::shared_ptr<IODUtilsWrapper> odWrapper);

        /// @brief Groups of one account: the primary gid first, then the others by ascending gid
        /// without repeats, so the list does not change from one scan to the next.
        /// @return Empty when the directory could not be read, which is not the same as no groups.
        std::vector<gid_t> groupsOf(const std::string& userName, gid_t primaryGid);

    private:
        struct Group
        {
            gid_t gid;
            ODGroupMembers members;
        };

        void load();
        void resolveGroups(const std::map<std::string, ODGroupMembers>& membersByGroup);
        std::string guidOf(const std::string& lowerName) const;
        std::set<gid_t> otherGroupsOf(const std::string& lowerName, const std::string& uuid, gid_t primaryGid) const;

        std::shared_ptr<IGroupWrapperDarwin> m_groupWrapper;
        std::shared_ptr<IODUtilsWrapper> m_odWrapper;
        std::vector<Group> m_groups;
        std::map<std::string, std::string> m_guidByName;
        bool m_loaded {false};
        bool m_readable {false};
};
