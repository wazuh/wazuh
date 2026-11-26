/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <algorithm>
#include <vector>

#include "effective_groups_darwin.hpp"

EffectiveGroups::EffectiveGroups(std::shared_ptr<IGroupWrapperDarwin> groupWrapper)
    : m_groupWrapper(std::move(groupWrapper))
{
}

std::vector<gid_t> EffectiveGroups::gidsOf(const char* userName, gid_t primaryGid) const
{
    int ngroups = m_groupWrapper->getgroupcount(userName, primaryGid);
    std::vector<gid_t> gids(ngroups > 0 ? static_cast<size_t>(ngroups) : 0);

    if (gids.empty() || m_groupWrapper->getgrouplist(userName, primaryGid, gids.data(), &ngroups) < 0)
    {
        return {};
    }

    gids.resize(std::min(gids.size(), static_cast<size_t>(std::max(ngroups, 0))));
    return gids;
}

std::set<std::string> EffectiveGroups::namesOf(const char* userName, gid_t primaryGid) const
{
    std::set<std::string> names;

    for (const auto gid : gidsOf(userName, primaryGid))
    {
        if (const struct group* grp = m_groupWrapper->getgrgid(gid); grp != nullptr && grp->gr_name != nullptr)
        {
            names.insert(grp->gr_name);
        }
    }

    return names;
}
