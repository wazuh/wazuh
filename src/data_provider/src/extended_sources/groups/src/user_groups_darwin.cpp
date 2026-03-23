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

// Thread-local cache for user group mappings (uid -> list of gids)
static thread_local std::unordered_map<uid_t, std::vector<gid_t>> s_userGroupsCache;
static thread_local std::chrono::steady_clock::time_point s_cacheTimestamp;
static constexpr std::chrono::seconds CACHE_TIMEOUT{60};

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

void UserGroupsProvider::resetCache()
{
    s_userGroupsCache.clear();
    s_cacheTimestamp = std::chrono::steady_clock::time_point{};
}

bool UserGroupsProvider::validateCache()
{
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - s_cacheTimestamp);

    if (elapsed > CACHE_TIMEOUT)
    {
        s_userGroupsCache.clear();
        s_cacheTimestamp = now;
        return false;
    }

    return !s_userGroupsCache.empty();
}

std::vector<gid_t> UserGroupsProvider::getUserGroups(uid_t uid, const char* username, gid_t gid)
{
    // Check cache first
    if (validateCache())
    {
        auto it = s_userGroupsCache.find(uid);

        if (it != s_userGroupsCache.end())
        {
            return it->second;
        }
    }

    // Cache miss - get groups from system
    int ngroups = m_groupWrapper->getgroupcount(username, gid);
    std::vector<gid_t> groups(ngroups);

    if (m_groupWrapper->getgrouplist(username, gid, groups.data(), &ngroups) < 0)
    {
        groups.clear();
    }
    else
    {
        groups.resize(ngroups);
    }

    // Store in cache
    s_userGroupsCache[uid] = groups;
    s_cacheTimestamp = std::chrono::steady_clock::now();

    return groups;
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
    // Use cache-aware method
    auto groups = getUserGroups(user.uid, user.name, user.gid);

    if (!groups.empty())
    {
        addGroupsToResults(results, user.uid, groups.data(), groups.size());
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
    // Use cache-aware method
    return getUserGroups(user.uid, user.name, user.gid);
}

nlohmann::json UserGroupsProvider::getUserNamesByGid(const std::set<gid_t>& gids)
{
    validateCache();

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

        // Use cache-aware method
        auto groups = getUserGroups(user.uid, user.name, user.gid);

        if (!groups.empty())
        {
            nlohmann::json groupNames = nlohmann::json::array();

            for (size_t i = 0; i < groups.size(); ++i)
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
