/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "users_windows.hpp"
#include "iusers_utils_wrapper.hpp"
#include "users_utils_wrapper.hpp"

#include "json.hpp"

UsersProvider::UsersProvider(
    std::shared_ptr<IUsersHelper> usersHelper)
    : m_usersHelper(std::move(usersHelper)) {}

UsersProvider::UsersProvider()
    : m_usersHelper(std::make_shared<UsersHelper>()) {}

nlohmann::json UsersProvider::collect()
{
    return collectWithConstraints({});
}

nlohmann::json UsersProvider::collectWithConstraints(const std::set<std::uint32_t>& uids)
{
    std::set<std::string> processed_sids;
    auto  local = m_usersHelper->processLocalAccounts(processed_sids);
    auto  roaming = m_usersHelper->processRoamingProfiles(processed_sids);
    local.insert(local.end(), roaming.begin(), roaming.end());

    nlohmann::json result;

    auto filteringUsers = [&](const std::vector<User>& users)
    {
        for (const auto& user : users)
        {
            if (uids.empty() || uids.find(user.uid) != uids.end())
            {
                result.push_back(genUserJson(user));
            }
        }
    };

    filteringUsers(local);

    return result;
}

nlohmann::json UsersProvider::genUserJson(const User& user)
{
    nlohmann::json r;
    r["username"] = user.username;
    r["uid"] = user.uid;
    r["gid"] = user.gid;
    r["uid_signed"] = static_cast<std::int32_t>(user.uid);
    r["gid_signed"] = static_cast<std::int32_t>(user.gid);
    r["description"] = user.description;
    r["directory"] = user.directory;
    r["shell"] = m_usersHelper->getUserShell(user.sid);
    r["type"] = user.type;
    r["uuid"] = user.sid;
    return r;
}
