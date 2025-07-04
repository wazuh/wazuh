/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "groups_windows.hpp"

GroupsProvider::GroupsProvider(std::shared_ptr<IGroupsHelper> groupsHelper)
    : m_groupsHelper(std::move(groupsHelper))
{
}

GroupsProvider::GroupsProvider()
    : m_groupsHelper(std::make_shared<GroupsHelper>())
{
}

nlohmann::json GroupsProvider::collect(const std::set<std::uint32_t>& gids)
{
    nlohmann::json results = nlohmann::json::array();

    auto localGroups = m_groupsHelper->processLocalGroups();

    auto filteringGroups = [&](const std::vector<Group>& groups)
    {
        for (const auto& group : groups)
        {
            if (gids.empty() || gids.find(group.gid) != gids.end())
            {
                addGroupToResults(results, group);
            }
        }
    };

    filteringGroups(localGroups);

    return results;
}

void GroupsProvider::addGroupToResults(nlohmann::json& results, const Group& group)
{
    nlohmann::json groupJson;

    groupJson["gid"] = group.gid;
    groupJson["gid_signed"] = static_cast<int32_t>(group.gid);
    groupJson["group_sid"] = group.sid;
    groupJson["comment"] = group.comment;
    groupJson["groupname"] = group.groupname;

    results.push_back(std::move(groupJson));
}
