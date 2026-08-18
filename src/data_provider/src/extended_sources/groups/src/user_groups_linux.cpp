/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "user_groups_linux.hpp"
#include "group_wrapper.hpp"
#include "passwd_wrapper.hpp"
#include "system_wrapper.hpp"
#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>

// Reasonable upper bound for getpw_r buffer
constexpr size_t MAX_GETPW_R_BUF_SIZE = 16 * 1024;

// Initialize static thread-local cache variables
thread_local std::unordered_map<uid_t, std::vector<gid_t>> UserGroupsProvider::s_userGroupsCache;
thread_local std::chrono::steady_clock::time_point UserGroupsProvider::s_cacheTimestamp;
thread_local bool UserGroupsProvider::s_cacheValid = false;

UserGroupsProvider::UserGroupsProvider(std::shared_ptr<IGroupWrapperLinux> groupWrapper,
                                       std::shared_ptr<IPasswdWrapperLinux> passwdWrapper,
                                       std::shared_ptr<ISystemWrapper> sysWrapper)
    : m_groupWrapper(std::move(groupWrapper))
    , m_passwdWrapper(std::move(passwdWrapper))
    , m_sysWrapper(std::move(sysWrapper))
{
}

UserGroupsProvider::UserGroupsProvider()
    : m_groupWrapper(std::make_shared<GroupWrapperLinux>())
    , m_passwdWrapper(std::make_shared<PasswdWrapperLinux>())
    , m_sysWrapper(std::make_shared<SystemWrapper>())
{
}

void UserGroupsProvider::resetCache()
{
    s_userGroupsCache.clear();
    s_cacheValid = false;
}

void UserGroupsProvider::validateCache()
{
    if (s_cacheValid)
    {
        const auto now = std::chrono::steady_clock::now();
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - s_cacheTimestamp);

        if (elapsed >= s_cacheTimeout)
        {
            s_userGroupsCache.clear();
            s_cacheValid = false;
        }
    }
}

nlohmann::json UserGroupsProvider::collect(const std::set<uid_t>& uids)
{
    nlohmann::json results = nlohmann::json::array();
    auto usersGroups = getUserGroups(uids);

    for (const auto& [uid, groups] : usersGroups)
    {
        addGroupsToResults(results, uid, groups.data(), static_cast<int>(groups.size()));
    }

    return results;
}

nlohmann::json UserGroupsProvider::getGroupNamesByUid(const std::set<uid_t>& uids)
{
    const bool singleUid = (uids.size() == 1);
    nlohmann::json result = singleUid ? nlohmann::json::array() : nlohmann::json::object();
    auto usersGroups = getUserGroups(uids);

    size_t bufSize = m_sysWrapper->sysconf(_SC_GETGR_R_SIZE_MAX);

    if (bufSize > MAX_GETPW_R_BUF_SIZE)
    {
        bufSize = MAX_GETPW_R_BUF_SIZE;
    }

    // Resolve each distinct gid once for the whole call instead of once per user that
    // belongs to it. Group membership overlaps heavily, so the previous behaviour cost
    // one lookup per (user, group) pair. On a host where the group database is served by
    // a network directory, every one of those lookups is a round trip.
    // Unresolvable gids are memoised too, otherwise they keep costing a lookup per user.
    std::unordered_map<gid_t, std::string> gidToName;
    std::unordered_set<gid_t> unresolvableGids;

    const auto resolveGidName = [&](gid_t gid, std::string & name) -> bool
    {
        if (const auto cached = gidToName.find(gid); cached != gidToName.end())
        {
            name = cached->second;
            return true;
        }

        if (unresolvableGids.count(gid) > 0)
        {
            return false;
        }

        struct group grp {};

        struct group* grpResult = nullptr;

        auto groupBuf = std::make_unique<char[]>(bufSize);

        const auto result = m_groupWrapper->getgrgid_r(gid, &grp, groupBuf.get(), bufSize, &grpResult);

        if (result == 0 && grpResult != nullptr)
        {
            name = grpResult->gr_name;
            gidToName.emplace(gid, name);
            return true;
        }

        // Only an authoritative answer is remembered. A return of 0 with no entry means the
        // group database does not know this gid, which will not change within one scan. A
        // non-zero return is a failed lookup, which may be transient on a host whose group
        // database is served over the network, so it is left unmemoized and the next user
        // that belongs to this gid attempts it again, as it did before this change.
        if (result == 0)
        {
            unresolvableGids.insert(gid);
        }

        return false;
    };

    for (const auto& [uid, groups] : usersGroups)
    {
        nlohmann::json groupNames = nlohmann::json::array();

        for (const auto& gid : groups)
        {
            std::string groupName;

            if (resolveGidName(gid, groupName))
            {
                groupNames.push_back(groupName);
            }
        }

        if (singleUid)
        {
            result = groupNames;
        }
        else
        {
            result[std::to_string(uid)] = groupNames;
        }
    }

    return result;
}

nlohmann::json UserGroupsProvider::getUserNamesByGid(const std::set<gid_t>& gids)
{
    const bool allGroups = gids.empty();
    const bool singleGid = (!allGroups && gids.size() == 1);
    nlohmann::json result = singleGid ? nlohmann::json::array() : nlohmann::json::object();

    size_t bufSize = m_sysWrapper->sysconf(_SC_GETPW_R_SIZE_MAX);

    if (bufSize > MAX_GETPW_R_BUF_SIZE)
    {
        bufSize = MAX_GETPW_R_BUF_SIZE;
    }

    std::map<gid_t, std::set<std::string>> gidToUsernames;

    if (allGroups)
    {
        struct group* grp = nullptr;
        m_groupWrapper->setgrent();

        while ((grp = m_groupWrapper->getgrent()) != nullptr)
        {
            gid_t gid = grp->gr_gid;
            char** members = grp->gr_mem;

            while (members && *members)
            {
                gidToUsernames[gid].insert(*members);
                ++members;
            }
        }

        m_groupWrapper->endgrent();
    }
    else
    {
        for (const auto& gid : gids)
        {
            struct group grp {};
            struct group* grpResult = nullptr;
            auto groupBuf = std::make_unique<char[]>(bufSize);

            if (m_groupWrapper->getgrgid_r(gid, &grp, groupBuf.get(), bufSize, &grpResult) == 0 && grpResult != nullptr)
            {
                char** members = grpResult->gr_mem;

                while (members && *members)
                {
                    gidToUsernames[gid].insert(*members);
                    ++members;
                }
            }
        }
    }

    struct passwd* pwd = nullptr;

    m_passwdWrapper->setpwent();

    while ((pwd = m_passwdWrapper->getpwent()) != nullptr)
    {
        if (allGroups || gids.count(pwd->pw_gid))
        {
            gidToUsernames[pwd->pw_gid].insert(pwd->pw_name);
        }
    }

    m_passwdWrapper->endpwent();

    for (const auto& [gid, usernames] : gidToUsernames)
    {
        nlohmann::json jsonUsernames = nlohmann::json::array();

        for (const auto& name : usernames)
        {
            jsonUsernames.push_back(name);
        }

        if (singleGid)
        {
            result = jsonUsernames;
        }
        else
        {
            result[std::to_string(gid)] = jsonUsernames;
        }
    }

    return result;
}

std::vector<std::pair<uid_t, std::vector<gid_t>>> UserGroupsProvider::getUserGroups(const std::set<uid_t>& uids)
{
    // Validate cache (auto-invalidates after 60 seconds)
    validateCache();

    std::vector<std::pair<uid_t, std::vector<gid_t>>> userGroups;
    struct passwd pwd {};
    struct passwd* pwdResults = nullptr;

    size_t bufSize = m_sysWrapper->sysconf(_SC_GETPW_R_SIZE_MAX);

    if (bufSize > MAX_GETPW_R_BUF_SIZE)
    {
        bufSize = MAX_GETPW_R_BUF_SIZE;
    }

    auto buf = std::make_unique<char[]>(bufSize);

    auto processUser = [&](const struct passwd * pwdInfo)
    {
        UserInfo user {pwdInfo->pw_name, pwdInfo->pw_uid, pwdInfo->pw_gid};

        // Check cache first
        auto it = s_userGroupsCache.find(user.uid);

        if (it != s_userGroupsCache.end())
        {
            userGroups.emplace_back(user.uid, it->second);
            return;
        }

        std::vector<gid_t> groups(EXPECTED_GROUPS_MAX);
        int nGroups = EXPECTED_GROUPS_MAX;

        if (m_groupWrapper->getgrouplist(user.name, user.gid, groups.data(), &nGroups) < 0)
        {
            groups.resize(nGroups);

            if (m_groupWrapper->getgrouplist(user.name, user.gid, groups.data(), &nGroups) < 0)
            {
                // std::cerr << "Could not get user's group list" << std::endl;
                return;
            }

            groups.resize(nGroups);
        }
        else
        {
            groups.resize(nGroups);
        }

        // Store in cache
        s_userGroupsCache[user.uid] = groups;
        userGroups.emplace_back(user.uid, std::move(groups));
    };

    if (!uids.empty())
    {
        for (const auto& uid : uids)
        {
            if (m_passwdWrapper->getpwuid_r(uid, &pwd, buf.get(), bufSize, &pwdResults) == 0 && pwdResults != nullptr)
            {
                processUser(pwdResults);
            }
        }
    }
    else
    {
        std::set<uid_t> processed_uids;
        m_passwdWrapper->setpwent();

        while (m_passwdWrapper->getpwent_r(&pwd, buf.get(), bufSize, &pwdResults) == 0 && pwdResults != nullptr)
        {
            if (processed_uids.insert(pwdResults->pw_uid).second)
            {
                processUser(pwdResults);
            }
        }

        m_passwdWrapper->endpwent();
    }

    // Mark cache as valid and update timestamp
    if (!s_userGroupsCache.empty())
    {
        s_cacheValid = true;
        s_cacheTimestamp = std::chrono::steady_clock::now();
    }

    return userGroups;
}

void UserGroupsProvider::addGroupsToResults(nlohmann::json& results, uid_t uid, const gid_t* groups, int nGroups)
{
    for (int i = 0; i < nGroups; i++)
    {
        nlohmann::json groupJson;

        groupJson["uid"] = uid;
        groupJson["gid"] = groups[i];

        results.push_back(groupJson);
    }
}
