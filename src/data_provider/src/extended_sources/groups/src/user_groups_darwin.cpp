/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <iostream>
#include "user_groups_darwin.hpp"
#include "group_wrapper.hpp"
#include "passwd_wrapper.hpp"
#include "open_directory_utils_wrapper.hpp"

UserGroupsProvider::UserGroupsProvider(std::shared_ptr<IGroupWrapperDarwin> groupWrapper,
                                       std::shared_ptr<IPasswdWrapperDarwin> passwdWrapper,
                                       std::shared_ptr<IODUtilsWrapper> odWrapper)
    : m_groupWrapper(std::move(groupWrapper))
    , m_passwdWrapper(std::move(passwdWrapper))
    , m_odWrapper(std::move(odWrapper))
{
}

UserGroupsProvider::UserGroupsProvider()
    : m_groupWrapper(std::make_shared<GroupWrapperDarwin>())
    , m_passwdWrapper(std::make_shared<PasswdWrapperDarwin>())
    , m_odWrapper(std::make_shared<ODUtilsWrapper>())
{
}

nlohmann::json UserGroupsProvider::collect(const std::set<uid_t>& uids)
{
    nlohmann::json results = nlohmann::json::array();

    if (!uids.empty())
    {
        for (const auto& uid : uids)
        {
            struct passwd* pwd = m_passwdWrapper->getpwuid(uid);

            if (pwd != nullptr)
            {
                UserInfo user {pwd->pw_name, pwd->pw_uid, pwd->pw_gid};
                getGroupsForUser(results, user);
            }
        }
    }
    else
    {
        std::map<std::string, bool> usernames;
        m_odWrapper->genEntries("dsRecTypeStandard:Users", nullptr, usernames);

        for (const auto& username : usernames)
        {
            struct passwd* pwd = m_passwdWrapper->getpwnam(username.first.c_str());

            if (pwd != nullptr)
            {
                UserInfo user {pwd->pw_name, pwd->pw_uid, pwd->pw_gid};
                getGroupsForUser(results, user);
            }
        }
    }

    return results;
}

void UserGroupsProvider::getGroupsForUser(nlohmann::json& results, const UserInfo& user)
{
    int ngroups = m_groupWrapper->getgroupcount(user.name, user.gid);
    gid_t* groups = new gid_t[ngroups];

    if (m_groupWrapper->getgrouplist(user.name, user.gid, groups, &ngroups) < 0)
    {
        std::cerr << "Could not get users group list" << std::endl;
    }
    else
    {
        addGroupsToResults(results, user.uid, groups, ngroups);
    }

    delete[] groups;
}

void UserGroupsProvider::addGroupsToResults(nlohmann::json& results, uid_t uid, const gid_t* groups, int ngroups)
{
    for (int i = 0; i < ngroups; i++)
    {
        nlohmann::json row;
        row["uid"] = uid;
        row["gid"] = groups[i];
        results.push_back(row);
    }
}
