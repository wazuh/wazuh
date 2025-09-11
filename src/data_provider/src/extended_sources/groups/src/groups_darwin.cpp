/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "groups_darwin.hpp"
#include "group_wrapper.hpp"
#include "open_directory_utils_wrapper.hpp"

GroupsProvider::GroupsProvider(std::shared_ptr<IGroupWrapperDarwin> groupWrapper,
                               std::shared_ptr<IODUtilsWrapper> odWrapper)
    : m_groupWrapper(std::move(groupWrapper))
    , m_odWrapper(std::move(odWrapper))
{
}

GroupsProvider::GroupsProvider()
    : m_groupWrapper(std::make_shared<GroupWrapperDarwin>())
    , m_odWrapper(std::make_shared<ODUtilsWrapper>())
{
}

nlohmann::json GroupsProvider::genGroupJson(const group* group)
{
    nlohmann::json groupJson;

    groupJson["groupname"] = group->gr_name;
    groupJson["gid"] = group->gr_gid;
    groupJson["gid_signed"] = static_cast<int32_t>(group->gr_gid);

    return groupJson;
}

nlohmann::json GroupsProvider::collect(const std::set<gid_t>& gids)
{
    nlohmann::json results = nlohmann::json::array();

    if (!gids.empty())
    {
        for (const auto& gid : gids)
        {
            struct group* group = m_groupWrapper->getgrgid(gid);

            if (group == nullptr)
            {
                continue;
            }

            std::map<std::string, bool> groupNames;
            std::string groupName {group->gr_name};
            m_odWrapper->genEntries("dsRecTypeStandard:Groups", &groupName, groupNames);

            nlohmann::json groupJson = genGroupJson(group);
            groupJson["is_hidden"] = int(groupNames[groupJson["groupname"]]);
            results.push_back(groupJson);
        }
    }
    else
    {
        std::map<std::string, bool> groupNames;
        m_odWrapper->genEntries("dsRecTypeStandard:Groups", nullptr, groupNames);

        for (const auto& groupName : groupNames)
        {
            // opendirectory and getgrnam are documented as having
            // different code paths. Thus we may see cases where
            // genODEntries produces responses that are not in
            // getgrnam. So with a surfeit of caution we populate some of
            // the row here
            nlohmann::json groupJson;

            struct group* group = m_groupWrapper->getgrnam(groupName.first.c_str());

            if (group != nullptr)
            {
                groupJson = genGroupJson(group);
            }
            else
            {
                groupJson["groupname"] = groupName.first;
            }

            groupJson["is_hidden"] = static_cast<int>(groupName.second);
            results.push_back(groupJson);
        }
    }

    return results;
}
