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

// Reasonable upper bound for getpw_r buffer
constexpr size_t MAX_GETPW_R_BUF_SIZE = 16 * 1024;

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

    for (const auto& [uid, groups] : usersGroups)
    {
        nlohmann::json groupNames = nlohmann::json::array();

        for (const auto& gid : groups)
        {
            struct group grp;
            struct group* grpResult = nullptr;
            auto groupBuf = std::make_unique<char[]>(bufSize);

            if (m_groupWrapper->getgrgid_r(gid, &grp, groupBuf.get(), bufSize, &grpResult) == 0 && grpResult != nullptr)
            {
                groupNames.push_back(grpResult->gr_name);
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
            struct group grp;
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
    std::vector<std::pair<uid_t, std::vector<gid_t>>> userGroups;
    struct passwd pwd;
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
