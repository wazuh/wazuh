/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <set>
#include <string>
#include <map>
#include <memory>
#include <limits>
#include <algorithm>

#include "users_darwin.hpp"
#include "uuid_wrapper.hpp"
#include "passwd_wrapper.hpp"
#include "open_directory_utils_wrapper.hpp"

UsersProvider::UsersProvider(
    std::shared_ptr<IPasswdWrapperDarwin> passwdWrapper,
    std::shared_ptr<IUUIDWrapper> uuidWrapper,
    std::shared_ptr<IODUtilsWrapper> odWrapper)
    : m_passwdWrapper(std::move(passwdWrapper)),
      m_uuidWrapper(std::move(uuidWrapper)),
      m_odWrapper(std::move(odWrapper)) {}

UsersProvider::UsersProvider()
    : m_passwdWrapper(std::make_shared<PasswdWrapperDarwin>()),
      m_uuidWrapper(std::make_shared<UUIDWrapper>()),
      m_odWrapper(std::make_shared<ODUtilsWrapper>()) {}

nlohmann::json UsersProvider::collect()
{
    return collectWithConstraints({});
}

nlohmann::json UsersProvider::collectWithConstraints(const std::set<uid_t>& uids)
{
    return collectUsers(uids);
}

nlohmann::json UsersProvider::genUserJson(const struct passwd* pwd)
{
    nlohmann::json user;

    if (!pwd) return user;

    user["username"] = pwd->pw_name ? pwd->pw_name : "";
    user["uid"] = pwd->pw_uid;
    user["gid"] = pwd->pw_gid;
    user["uid_signed"] = static_cast<int32_t>(pwd->pw_uid);
    user["gid_signed"] = static_cast<int32_t>(pwd->pw_gid);
    user["description"] = pwd->pw_gecos ? pwd->pw_gecos : "";
    user["directory"] = pwd->pw_dir ? pwd->pw_dir : "";
    user["shell"] = pwd->pw_shell ? pwd->pw_shell : "";

    uuid_t uuid = {0};
    uuid_string_t uuid_string = {0};

    // From the docs: mbr_uid_to_uuid will always succeed and may return a
    // synthesized UUID with the prefix FFFFEEEE-DDDD-CCCC-BBBB-AAAAxxxxxxxx,
    // where 'xxxxxxxx' is a hex conversion of the UID.
    m_uuidWrapper->uidToUUID(pwd->pw_uid, uuid);
    m_uuidWrapper->uuidToString(uuid, uuid_string);
    user["uuid"] = uuid_string;

    return user;
}

nlohmann::json UsersProvider::collectUsers(const std::set<uid_t>& uids)
{
    nlohmann::json users = nlohmann::json::array();

    // Both are resolved once per collection rather than once per user: the directory is read
    // in a single query and the membership list is the same for everyone.
    std::set<std::string> disabledUsers;
    const auto disabledUsersResolved { m_odWrapper->genDisabledUsers(disabledUsers) };

    std::map<std::string, nlohmann::json> passwordData;
    m_odWrapper->genPasswordData(passwordData);

    if (!uids.empty())
    {
        for (const auto& uid : uids)
        {
            struct passwd* pwd = m_passwdWrapper->getpwuid(uid);

            if (!pwd) continue;

            std::map<std::string, bool> userNames;
            std::string pwUsernameStr{pwd->pw_name};
            m_odWrapper->genEntries("dsRecTypeStandard:Users", &pwUsernameStr, userNames);

            nlohmann::json user = genUserJson(pwd);
            user["is_hidden"] = int(userNames[user["username"]]);

            user.update(collectAccountPolicyData(user["uid"]));
            user.update(collectPasswordData(pwUsernameStr, disabledUsers, disabledUsersResolved, passwordData));

            users.push_back(user);
        }

        return users;
    }

    std::map<std::string, bool> userNames;
    m_odWrapper->genEntries("dsRecTypeStandard:Users", nullptr, userNames);

    for (const auto& [username, isHidden] : userNames)
    {
        // opendirectory and getpwnam are documented as having
        // different code paths. Thus we may see cases where
        // genODEntries produces responses that are not in
        // getpwnam. So with a surfeit of caution we populate some of
        // the row here
        nlohmann::json user;

        struct passwd* pwd = m_passwdWrapper->getpwnam(username.c_str());

        if (pwd != nullptr)
        {
            user = genUserJson(pwd);
        }
        else
        {
            // User exists in OpenDirectory but not in local passwd database
            // Initialize all fields with default values to ensure consistent JSON structure
            user["username"] = username;
            user["uid"] = static_cast<uid_t>(-1);  // Special value indicating user not found locally
            user["gid"] = static_cast<gid_t>(-1);
            user["uid_signed"] = -1;
            user["gid_signed"] = -1;
            user["description"] = "";
            user["directory"] = "";
            user["shell"] = "";
            user["uuid"] = "";
        }

        user["is_hidden"] = static_cast<int>(isHidden);

        user.update(collectAccountPolicyData(user["uid"]));
        user.update(collectPasswordData(username, disabledUsers, disabledUsersResolved, passwordData));

        users.push_back(user);
    }

    return users;
}

nlohmann::json UsersProvider::collectAccountPolicyData(const uid_t uid)
{
    nlohmann::json accountData;
    m_odWrapper->genAccountPolicyData(std::to_string(uid), accountData);

    // expires_every_n_days is only present when pwpolicy or an MDM has imposed a change
    // interval. It doubles as the source for the expiration date, which macOS does not store
    // directly: it is derived the same way the policy itself evaluates it, from the last change.
    // password_last_set_time defaults to 0.0 in od_wrapper.mm when OpenDirectory never reported
    // it, so the key is always present; a real last-set time (> 0) is required, not merely
    // present, before either aging field is derived -- otherwise both fields would misrepresent
    // an unknown last-set time as an epoch-1970 one.
    if (accountData.contains("expires_every_n_days"))
    {
        const auto expiresEveryNDays = accountData["expires_every_n_days"].get<int64_t>();
        const auto lastSetTimeSeconds = static_cast<int64_t>(accountData.value("password_last_set_time", 0.0));

        if (lastSetTimeSeconds > 0)
        {
            constexpr auto secondsPerDay = 86400;
            constexpr int64_t noExpiration = -1;
            constexpr int64_t maxWireValue = std::numeric_limits<int32_t>::max();
            // Largest day count that still keeps lastSetTime + days*secondsPerDay within the int
            // wire field for this account's actual last-set time (not a fixed day count: the same
            // policy overflows sooner the more recently the password was last changed). Mirrors
            // shadow_linux.cpp's MAX_EXPIRE_DAYS: the manager's parser rejects an out-of-range int
            // and would drop the whole message.
            const int64_t maxExpireDaysForAccount = (maxWireValue - lastSetTimeSeconds) / secondsPerDay;

            // password_max_days_between_changes is the raw day count and shares the same int
            // wire field, so it needs its own cap independent of the expiration-date arithmetic.
            accountData["password_max_days_between_changes"] = std::min(expiresEveryNDays, maxWireValue);
            accountData["password_expiration_date"] = (expiresEveryNDays > maxExpireDaysForAccount)
                                                      ? noExpiration
                                                      : lastSetTimeSeconds + expiresEveryNDays * secondsPerDay;
        }
    }

    return accountData;
}

nlohmann::json UsersProvider::collectPasswordData(const std::string& username,
                                                  const std::set<std::string>& disabledUsers,
                                                  const bool disabledUsersResolved,
                                                  const std::map<std::string, nlohmann::json>& passwordData)
{
    // Empty rather than absent, so a user whose record could not be read is reported as not
    // collected instead of inheriting whatever the caller had in the object.
    nlohmann::json userPasswordData
    {
        {"password_status", ""},
        {"password_hash_algorithm", ""}
    };

    const auto it { passwordData.find(username) };

    if (it != passwordData.end())
    {
        userPasswordData = it->second;
    }

    // A disabled account keeps its hash, so the group membership has to win over the
    // status derived from the authentication authority. Without that membership the status
    // cannot be trusted at all: a disabled account would otherwise be reported as active, so
    // it is reported as not collected instead.
    if (!disabledUsersResolved)
    {
        userPasswordData["password_status"] = "";
    }
    else if (disabledUsers.count(username))
    {
        userPasswordData["password_status"] = "locked";
    }

    return userPasswordData;
}
