/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <unordered_map>

#include <sys/types.h>

#include "json.hpp"

/// The last login of every collected account, and whether the host records last logins at all.
struct LastLoginResolution
{
    /// Epoch seconds per account name, 0 where the account has no last login.
    std::unordered_map<std::string, uint32_t> byName;

    /// Whether the host recorded a last login for any account, which is what makes "failures since
    /// the last login" answerable. False means the count has nothing to be measured from.
    bool known;
};

/// Builds the last login of every collected account.
///
/// Three rules decide the result, and the order of the last two is the point of this function:
///
/// 1. Only rows of type "user" date a login. utmp also keeps the logout as a DEAD_PROCESS row, and
///    boot and init rows carry times of their own, so folding every row in would move an account's
///    anchor to its logout and hide the failures of the session that just ended.
/// 2. Whether the host records last logins is decided from `lastlog` and `lastlog2` alone, before any
///    open session is merged in. A session says the account is logged in now; it is not a record of
///    last logins, so it must not make the count answerable for every other account on a host that
///    keeps none. Deciding after the merge anchors the others at the epoch and counts every failure
///    the log still holds against them, and makes the field alternate as sessions come and go.
/// 3. An open session still refines that account's own last login, which is why the merge happens
///    at all.
///
/// @param collectedUsers Accounts, each with "username" and "uid".
/// @param collectedLoggedInUser utmp rows, each with "user", "time" and "type".
/// @param provider Anything exposing lastLogin(uid_t, const std::string&).
template<typename TLastLoginProvider>
LastLoginResolution resolveLastLogins(const nlohmann::json& collectedUsers,
                                      const nlohmann::json& collectedLoggedInUser,
                                      TLastLoginProvider& provider)
{
    LastLoginResolution resolution;

    for (const auto& user : collectedUsers)
    {
        if (user.contains("username") && !user["username"].get<std::string>().empty())
        {
            auto& lastLogin = resolution.byName[user["username"].get<std::string>()];
            lastLogin = std::max(lastLogin, provider.lastLogin(user["uid"].get<uid_t>(), user["username"]));
        }
    }

    // Rule 2: decided from the recorded logins only, before the sessions below are merged in.
    resolution.known = std::any_of(resolution.byName.cbegin(), resolution.byName.cend(),
                                   [](const auto & entry)
    {
        return entry.second > 0;
    });

    for (const auto& item : collectedLoggedInUser)
    {
        // Rule 1.
        if (item.value("type", std::string {}) != "user")
        {
            continue;
        }

        const auto entry = resolution.byName.find(item["user"].get<std::string>());

        // Rule 3.
        if (entry != resolution.byName.end())
        {
            entry->second = std::max(entry->second,
                                     static_cast<uint32_t>(std::max<int32_t>(item["time"].get<int32_t>(), 0)));
        }
    }

    return resolution;
}
