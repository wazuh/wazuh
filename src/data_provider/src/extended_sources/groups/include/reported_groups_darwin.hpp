/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <memory>
#include <string>
#include <sys/types.h>
#include <vector>

#include "direct_memberships_darwin.hpp"
#include "effective_groups_darwin.hpp"
#include "igroup_wrapper.hpp"
#include "iopen_directory_utils_wrapper.hpp"

/// @brief The groups reported for a macOS account in `user.groups` and `group.users`.
///
/// For the groups of the local node, the account's direct memberships (DirectMemberships), so a
/// local group that nests `everyone` does not show up on every account. The groups a directory
/// service such as Active Directory gives the account are kept as getgrouplist() lists them.
class ReportedGroups
{
    public:
        ReportedGroups(std::shared_ptr<IGroupWrapperDarwin> groupWrapper, std::shared_ptr<IODUtilsWrapper> odWrapper);

        /// @brief The primary gid first, then the others by ascending gid without repeats.
        /// @return Empty when the local directory could not be read, which is not the same as no
        /// groups. When getgrouplist() fails, only the direct memberships are returned.
        std::vector<gid_t> groupsOf(const std::string& userName, gid_t primaryGid);

        /// @brief Whether the local directory was read and the read failed.
        bool readFailed() const;

    private:
        DirectMemberships m_directMemberships;
        EffectiveGroups m_effectiveGroups;
};
