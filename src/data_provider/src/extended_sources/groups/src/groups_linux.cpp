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
    struct group* groupResult
    {
        nullptr
    };
    struct group group;

    size_t bufSize = MAX_GETPW_R_BUF_SIZE;
    auto buf = std::make_unique<char[]>(bufSize);

    if (!gids.empty())
    {
        for (const auto& gid : gids)
        {
            while (m_groupWrapper->getgrgid_r(gid, &group, buf.get(), bufSize, &groupResult) == ERANGE)
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
        m_groupWrapper->setgrent();

        while (1)
        {
            while (m_groupWrapper->getgrent_r(&group, buf.get(), bufSize, &groupResult) == ERANGE)
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

        m_groupWrapper->endgrent();
        groupsIn.clear();
    }

    return results;
}

void GroupsProvider::addGroupToResults(nlohmann::json& results, const group* group)
{
    nlohmann::json groupJson;

    groupJson["groupname"] = group->gr_name;
    groupJson["gid"] = group->gr_gid;
    groupJson["gid_signed"] = static_cast<int32_t>(group->gr_gid);

    results.push_back(groupJson);
}
