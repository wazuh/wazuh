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
#include <set>
#include <string>
#include <sys/types.h>

#include "igroup_wrapper.hpp"

/// @brief The names of every group a macOS account belongs to, nested groups included.
///
/// This is the answer getgrouplist() gives and the one sudo uses to match a `%group` rule, so a
/// user who is admin only through a group nested into `admin` is still a sudoer. It is kept apart
/// from DirectMemberships on purpose: the groups reported for the account must not follow nesting,
/// the sudo role must.
class EffectiveGroups
{
    public:
        explicit EffectiveGroups(std::shared_ptr<IGroupWrapperDarwin> groupWrapper);

        /// @return The group names, or an empty set when the system cannot list the groups.
        std::set<std::string> namesOf(const char* userName, gid_t primaryGid) const;

    private:
        std::shared_ptr<IGroupWrapperDarwin> m_groupWrapper;
};
