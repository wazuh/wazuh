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
    std::vector<gid_t> groups(ngroups);

    if (m_groupWrapper->getgrouplist(user.name, user.gid, groups.data(), &ngroups) < 0)
    {
        // std::cerr << "Could not get users group list" << std::endl;
    }
    else
    {
        addGroupsToResults(results, user.uid, groups.data(), ngroups);
    }
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

std::vector<gid_t> UserGroupsProvider::getGroupIdsForUser(const UserInfo& user)
{
    int ngroups = m_groupWrapper->getgroupcount(user.name, user.gid);
    std::vector<gid_t> groups(ngroups);

    if (m_groupWrapper->getgrouplist(user.name, user.gid, groups.data(), &ngroups) < 0)
    {
        return {};
    }

    groups.resize(ngroups);
    return groups;
}

nlohmann::json UserGroupsProvider::getUserNamesByGid(const std::set<gid_t>& gids)
{
    bool singleGid = (gids.size() == 1);
    nlohmann::json results = singleGid ? nlohmann::json::array() : nlohmann::json::object();
    std::map<std::string, bool> usernames;

    m_odWrapper->genEntries("dsRecTypeStandard:Users", nullptr, usernames);

    for (const auto& username : usernames)
    {
        struct passwd* pwd = m_passwdWrapper->getpwnam(username.first.c_str());

        if (pwd != nullptr)
        {
            UserInfo user {pwd->pw_name, pwd->pw_uid, pwd->pw_gid};
            auto userGids = getGroupIdsForUser(user);

            for (const auto& gid : userGids)
            {
                if (gids.count(gid))
                {
                    if (singleGid)
                    {
                        results.push_back(user.name);
                    }
                    else
                    {
                        results[std::to_string(gid)].push_back(user.name);
                    }
                }
            }
        }
    }

    return results;
}

nlohmann::json UserGroupsProvider::getGroupNamesByUid(const std::set<uid_t>& uids)
{
    const bool allUsers = uids.empty();
    const bool singleUid = (!allUsers && uids.size() == 1);
    nlohmann::json results = singleUid ? nlohmann::json::array() : nlohmann::json::object();

    for (const auto& uid : uids)
    {
        struct passwd* pwd = m_passwdWrapper->getpwuid(uid);

        if (pwd == nullptr)
        {
            continue;
        }

        UserInfo user {pwd->pw_name, pwd->pw_uid, pwd->pw_gid};

        int ngroups = m_groupWrapper->getgroupcount(user.name, user.gid);
        std::vector<gid_t> groups(ngroups);

        if (m_groupWrapper->getgrouplist(user.name, user.gid, groups.data(), &ngroups) >= 0)
        {
            nlohmann::json groupNames = nlohmann::json::array();

            for (int i = 0; i < ngroups; ++i)
            {
                struct group* grp = m_groupWrapper->getgrgid(groups[i]);

                if (grp != nullptr)
                {
                    groupNames.push_back(grp->gr_name);
                }
            }

            if (singleUid)
            {
                results = groupNames;
            }
            else
            {
                results[std::to_string(uid)] = groupNames;
            }
        }
    }

    return results;
}
