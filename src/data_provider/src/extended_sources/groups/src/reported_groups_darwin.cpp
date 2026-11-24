/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <set>

#include "reported_groups_darwin.hpp"

ReportedGroups::ReportedGroups(std::shared_ptr<IGroupWrapperDarwin> groupWrapper,
                               std::shared_ptr<IODUtilsWrapper> odWrapper)
    : m_directMemberships(groupWrapper, std::move(odWrapper))
    , m_effectiveGroups(std::move(groupWrapper))
{
}

std::vector<gid_t> ReportedGroups::groupsOf(const std::string& userName, gid_t primaryGid)
{
    const auto direct = m_directMemberships.groupsOf(userName, primaryGid);

    if (direct.empty())
    {
        return direct;
    }

    const auto fromDirectory =
        m_directMemberships.groupsFromDirectoryServices(m_effectiveGroups.gidsOf(userName.c_str(), primaryGid));
    std::set<gid_t> others(direct.begin() + 1, direct.end());
    others.insert(fromDirectory.begin(), fromDirectory.end());
    others.erase(primaryGid);

    std::vector<gid_t> groups {primaryGid};
    groups.insert(groups.end(), others.begin(), others.end());
    return groups;
}

bool ReportedGroups::readFailed() const
{
    return m_directMemberships.readFailed();
}
