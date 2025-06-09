/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <iostream>

#include "user_groups_windows.hpp"
#include "iusers_utils_wrapper.hpp"
#include "users_utils_wrapper.hpp"
#include "windows_api_wrapper.hpp"
#include "encodingWindowsHelper.h"

UserGroupsProvider::UserGroupsProvider(std::shared_ptr<IWindowsApiWrapper> winapiWrapper,
                                       std::shared_ptr<IUsersHelper> usersHelper,
                                       std::shared_ptr<IGroupsHelper> groupsHelper)
    : m_winapiWrapper(std::move(winapiWrapper))
    , m_usersHelper(std::move(usersHelper))
    , m_groupsHelper(std::move(groupsHelper))
{
}

UserGroupsProvider::UserGroupsProvider()
    : m_winapiWrapper(std::make_shared<WindowsApiWrapper>())
    , m_usersHelper(std::make_shared<UsersHelper>())
    , m_groupsHelper(std::make_shared<GroupsHelper>())
{
}

nlohmann::json UserGroupsProvider::collect(const std::set<std::uint32_t>& uids)
{

    nlohmann::json results;

    auto localUsers = getLocalUsers(uids);
    auto groups = getLocalGroups();

    for (const auto& user : localUsers)
    {
        processLocalUserGroups(user, groups, results);
    }

    return results;
}

nlohmann::json UserGroupsProvider::getGroupNamesByUid(const std::set<std::uint32_t>& uids)
{
    auto localUsers = getLocalUsers(uids);
    auto groups = getLocalGroups();

    const bool singleUid = uids.size() == 1;
    nlohmann::json result = singleUid ? nlohmann::json::array() : nlohmann::json::object();

    for (const auto& user : localUsers)
    {
        const auto groupNames = getLocalGroupNamesForUser(user.username);

        if (singleUid)
        {
            for (const auto& group : groupNames)
            {
                result.push_back(group);
            }
        }
        else
        {
            result[std::to_string(user.uid)] = groupNames;
        }
    }

    return result;
}

nlohmann::json UserGroupsProvider::getUserNamesByGid(const std::set<std::uint32_t>& gids)
{
    const bool singleGid = gids.size() == 1;
    auto localUsers = getLocalUsers({});
    auto groups = getLocalGroups();

    std::unordered_map<uint32_t, std::vector<std::string>> gidToUsers;

    for (const auto& user : localUsers)
    {
        const auto userGroupNames = getLocalGroupNamesForUser(user.username);

        for (const auto& groupname : userGroupNames)
        {
            auto it = std::find_if(groups.begin(),
                                   groups.end(),
                                   [&groupname](const Group & group)
            {
                return group.groupname == groupname;
            });

            if (it != groups.end())
            {
                if (gids.empty() || gids.find(it->gid) != gids.end())
                {
                    gidToUsers[it->gid].emplace_back(user.username);
                }
            }
        }
    }

    if (singleGid)
    {
        uint32_t onlyGid = *gids.begin();

        if (gidToUsers.find(onlyGid) != gidToUsers.end())
        {
            return gidToUsers[onlyGid];
        }
    }
    else
    {
        nlohmann::json result = nlohmann::json::object();

        for (const auto& [gid, usernames] : gidToUsers)
        {
            result[std::to_string(gid)] = usernames;
        }

        return result;
    }
}

void UserGroupsProvider::processLocalUserGroups(const User& user,
                                                const std::vector<Group>& groups,
                                                nlohmann::json& results)
{
    const auto groupNames = getLocalGroupNamesForUser(user.username);

    for (const auto& groupname : groupNames)
    {
        auto optGroup = std::find_if(
                            groups.begin(), groups.end(), [&groupname](const Group & group)
        {
            return group.groupname == groupname;
        });

        if (optGroup == groups.end())
        {
            continue;
        }

        results.push_back({{"uid", user.uid}, {"gid", optGroup->gid}});
    }
}

std::vector<User> UserGroupsProvider::getLocalUsers(const std::set<std::uint32_t>& uids)
{
    std::set<std::string> processedSids;
    auto localUsers = m_usersHelper->processLocalAccounts(processedSids);

    std::vector<User> filteredUsers;

    for (const auto& user : localUsers)
    {
        if (uids.empty() || uids.find(user.uid) != uids.end())
        {
            if (user.username == "LOCAL SERVICE" || user.username == "SYSTEM" || user.username == "NETWORK SERVICE")
            {
                continue;
            }

            filteredUsers.push_back(user);
        }
    }

    return filteredUsers;
}

std::vector<Group> UserGroupsProvider::getLocalGroups()
{
    return m_groupsHelper->processLocalGroups();
}

std::vector<std::string> UserGroupsProvider::getLocalGroupNamesForUser(const std::string& username)
{
    std::wstring wUsername = m_usersHelper->stringToWstring(username);
    DWORD groupInfoLevel = 0;
    DWORD numGroups = 0;
    DWORD totalGroups = 0;
    localgroup_users_info_0_ptr groupInfo;

    DWORD ret = m_winapiWrapper->NetUserGetLocalGroupsWrapper(nullptr,
                                                              wUsername.c_str(),
                                                              groupInfoLevel,
                                                              1,
                                                              reinterpret_cast<LPBYTE*>(groupInfo.get_new_ptr()),
                                                              MAX_PREFERRED_LENGTH,
                                                              &numGroups,
                                                              &totalGroups);

    std::vector<std::string> groupNames;

    if (ret == NERR_Success && groupInfo != nullptr)
    {
        for (std::size_t i = 0; i < numGroups; ++i)
        {
            groupNames.emplace_back(Utils::EncodingWindowsHelper::wstringToStringUTF8(groupInfo.get()[i].lgrui0_name));
        }
    }

    return groupNames;
}
