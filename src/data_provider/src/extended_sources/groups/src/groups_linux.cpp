/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "groups_linux.hpp"
#include "group_wrapper.hpp"

// Reasonable upper bound for getpw_r buffer
constexpr size_t MAX_GETPW_R_BUF_SIZE = 16 * 1024;

GroupsProvider::GroupsProvider(std::shared_ptr<IGroupWrapperLinux> groupWrapper)
    : m_groupWrapper(std::move(groupWrapper)) {}

GroupsProvider::GroupsProvider()
    : m_groupWrapper(std::make_shared<GroupWrapperLinux>()) {}

nlohmann::json GroupsProvider::collect(const std::set<gid_t>& gids)
{
    nlohmann::json results = nlohmann::json::array();
    struct group* groupResult {nullptr};
    struct group group;

    size_t bufSize = MAX_GETPW_R_BUF_SIZE;
    auto buf = std::make_unique<char[]>(bufSize);
    if (!gids.empty())
    {
        for (const auto& gid : gids)
        {
            while (getgrgid_r(gid, &group, buf.get(), bufSize, &groupResult) == ERANGE)
            {
                bufSize *= 2;
                buf = std::make_unique<char[]>(bufSize);
            }
            if (groupResult == nullptr)
            {
                continue;
            }
            addGroupToResults(results, groupResult);
        }
    }
    else
    {
        std::set<long> groupsIn;
        setgrent();
        while (1)
        {
            while (getgrent_r(&group, buf.get(), bufSize, &groupResult) == ERANGE)
            {
                bufSize *= 2;
                buf = std::make_unique<char[]>(bufSize);
            }
            if (groupResult == nullptr)
            {
                break;
            }
            if (std::find(groupsIn.begin(), groupsIn.end(), groupResult->gr_gid) == groupsIn.end())
            {
                addGroupToResults(results, groupResult);
                groupsIn.insert(groupResult->gr_gid);
            }
        }
        endgrent();
        groupsIn.clear();
    }

    return results;
}

void GroupsProvider::addGroupToResults(nlohmann::json& results, const group* group)
{
    nlohmann::json row;
    row["groupname"] = group->gr_name;
    row["gid"] = group->gr_gid;
    row["gid_signed"] = static_cast<int32_t>(group->gr_gid);
    row["pid_with_namespace"] = "0";
    results.push_back(row);
}
