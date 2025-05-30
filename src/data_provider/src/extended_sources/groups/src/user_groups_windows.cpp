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

void UserGroupsProvider::processLocalUserGroups(const User& user, const std::vector<Group>& groups, nlohmann::json& results)
{
    DWORD groupInfoLevel = 0;
    DWORD numGroups = 0;
    DWORD totalGroups = 0;
    localgroup_users_info_0_ptr groupInfo;

    DWORD ret = 0;

    std::wstring username = m_usersHelper->stringToWstring(user.username);

    ret = m_winapiWrapper->NetUserGetLocalGroupsWrapper(nullptr,
                                                        username.c_str(),
                                                        groupInfoLevel,
                                                        1,
                                                        reinterpret_cast<LPBYTE*>(groupInfo.get_new_ptr()),
                                                        MAX_PREFERRED_LENGTH,
                                                        &numGroups,
                                                        &totalGroups);

    if (ret == ERROR_MORE_DATA)
    {
        // std::cerr << "User " << user.username << " group membership exceeds buffer limits, processing " << numGroups
        //           << " our of " << totalGroups << " groups" << std::endl;
    }
    else if (ret != NERR_Success || groupInfo == nullptr)
    {
        // std::cerr << " NetUserGetLocalGroups failed for user " << user.username << " with " << ret << std::endl;
        return;
    }

    for (std::size_t i = 0; i < numGroups; i++)
    {
        std::string groupname = Utils::EncodingWindowsHelper::wstringToStringUTF8(groupInfo.get()[i].lgrui0_name);

        auto optGroup = std::find_if(groups.begin(), groups.end(),
                                     [&groupname](const Group & group)
        {
            return group.groupname == groupname;
        });

        if (optGroup == groups.end())
        {
            // std::cerr << "Group " << groupname << " not found in local groups" << std::endl;
            continue;
        }

        nlohmann::json row;

        row["uid"] = user.uid;
        row["gid"] = optGroup->gid;

        results.push_back(std::move(row));
    }
}

nlohmann::json UserGroupsProvider::collect(const std::set<std::uint32_t>& uids)
{

    nlohmann::json results;

    std::set<std::string> processedSids;
    auto localUsers = m_usersHelper->processLocalAccounts(processedSids);
    auto groups = m_groupsHelper->processLocalGroups();

    auto filteringUsers = [&](const std::vector<User>& users)
    {
        for (const auto& user : users)
        {
            if (uids.empty() || uids.find(user.uid) != uids.end())
            {
                if (user.username == "LOCAL SERVICE" || user.username == "SYSTEM" || user.username == "NETWORK SERVICE")
                {
                    continue;
                }

                processLocalUserGroups(user, groups, results);
            }
        }
    };

    filteringUsers(localUsers);

    return results;
}
