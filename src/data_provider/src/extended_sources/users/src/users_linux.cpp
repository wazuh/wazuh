/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "users_linux.hpp"
#include "passwd_wrapper.hpp"
#include "system_wrapper.hpp"

#include <sys/types.h>
#include <cerrno>
#include <pwd.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <fstream>

// Reasonable upper bound for getpw_r buffer
constexpr size_t MAX_GETPW_R_BUF_SIZE = 16 * 1024;

constexpr auto PASSWD_FILE_PATH {"/etc/passwd"};

// Reserved by systemd for DynamicUser= units (man systemd.exec). nss-systemd enumerates those
// accounts although /etc/passwd does not define them, so they would otherwise look like directory
// accounts. They are local and transient, so the range is excluded from that inference.
constexpr uid_t SYSTEMD_DYNAMIC_UID_MIN = 61184;
constexpr uid_t SYSTEMD_DYNAMIC_UID_MAX = 65519;

UsersProvider::UsersProvider(
    std::shared_ptr<IPasswdWrapperLinux> passwdWrapper,
    std::shared_ptr<ISystemWrapper> sysWrapper)
    : m_passwdWrapper(std::move(passwdWrapper)),
      m_sysWrapper(std::move(sysWrapper)) {}

UsersProvider::UsersProvider()
    : m_passwdWrapper(std::make_shared<PasswdWrapperLinux>()),
      m_sysWrapper(std::make_shared<SystemWrapper>()) {}

nlohmann::json UsersProvider::collect(bool include_remote)
{
    return collectWithConstraints({}, {}, include_remote);
}

nlohmann::json UsersProvider::collectWithConstraints(const std::set<std::string>& usernames,
                                                     const std::set<uid_t>& uids,
                                                     bool include_remote)
{

    if (include_remote)
    {
        return collectRemoteUsers(usernames, uids);
    }

    return collectLocalUsers(usernames, uids);
}

size_t UsersProvider::passwdBufferSize() const
{
    // size_t is deliberate: sysconf() returns -1 for "no limit", which wraps and gets clamped below,
    // whereas a signed type would let -1 reach make_unique.
    size_t bufsize = m_sysWrapper->sysconf(_SC_GETPW_R_SIZE_MAX);

    if (bufsize > MAX_GETPW_R_BUF_SIZE)
    {
        bufsize = MAX_GETPW_R_BUF_SIZE;
    }

    return bufsize;
}

std::set<std::string> UsersProvider::collectLocalUsernames()
{
    std::set<std::string> localUsernames;

    FILE* passwd_file = m_sysWrapper->fopen(PASSWD_FILE_PATH, "r");

    if (passwd_file == nullptr)
    {
        // Nothing to compare against, so locality cannot be determined. The caller reports every
        // account as local, which is the value the whole downstream stack already defaults to.
        return localUsernames;
    }

    // The upper bound rather than passwdBufferSize(): glibc's _SC_GETPW_R_SIZE_MAX is 1024, and one
    // longer line returns ERANGE, which discards the whole set (see below). A long GECOS triggers it.
    constexpr size_t bufsize = MAX_GETPW_R_BUF_SIZE;
    auto buf = std::make_unique<char[]>(bufsize);

    struct passwd pwd;
    struct passwd* result
    {
        nullptr
    };

    // Unfiltered on purpose: classification needs every name the file defines.
    int ret;

    while ((ret = m_passwdWrapper->fgetpwent_r(passwd_file, &pwd, buf.get(), bufsize, &result)) == 0
            && result != nullptr)
    {
        if (result->pw_name != nullptr)
        {
            localUsernames.emplace(result->pw_name);
        }
    }

    m_sysWrapper->fclose(passwd_file);

    // ENOENT means end of file; anything else means it was not read to the end, and a partial set
    // would flag every name past that point as remote. Discard it and fall back to reporting local.
    if (ret != 0 && ret != ENOENT)
    {
        localUsernames.clear();
    }

    return localUsernames;
}

nlohmann::json UsersProvider::genUserJson(const struct passwd* pwd, bool isRemote)
{
    nlohmann::json r;
    r["uid"] = pwd->pw_uid;
    r["gid"] = pwd->pw_gid;
    r["uid_signed"] = static_cast<int32_t>(pwd->pw_uid);
    r["gid_signed"] = static_cast<int32_t>(pwd->pw_gid);

    r["username"] = (pwd->pw_name != nullptr) ? pwd->pw_name : "";
    r["description"] = (pwd->pw_gecos != nullptr) ? pwd->pw_gecos : "";
    r["directory"] = (pwd->pw_dir != nullptr) ? pwd->pw_dir : "";
    r["shell"] = (pwd->pw_shell != nullptr) ? pwd->pw_shell : "";

    r["pid_with_namespace"] = "0";
    r["is_remote"] = static_cast<int>(isRemote);

    return r;
}

nlohmann::json UsersProvider::collectLocalUsers(const std::set<std::string>& usernames,
                                                const std::set<uid_t>& uids)
{
    nlohmann::json results = nlohmann::json::array();

    FILE* passwd_file = m_sysWrapper->fopen(PASSWD_FILE_PATH, "r");

    if (passwd_file == nullptr)
    {
        return results;
    }

    const auto bufsize = passwdBufferSize();
    auto buf = std::make_unique<char[]>(bufsize);

    struct passwd pwd;
    struct passwd* result
    {
        nullptr
    };

    while (m_passwdWrapper->fgetpwent_r(passwd_file, &pwd, buf.get(), bufsize, &result) == 0 && result != nullptr)
    {
        if (!usernames.empty()
                && (result->pw_name == nullptr || usernames.find(result->pw_name) == usernames.end()))
        {
            continue;
        }

        if (!uids.empty() && uids.find(result->pw_uid) == uids.end())
        {
            continue;
        }

        results.push_back(genUserJson(result, false));
    }

    m_sysWrapper->fclose(passwd_file);
    return results;
}

nlohmann::json UsersProvider::collectRemoteUsers(const std::set<std::string>& usernames,
                                                 const std::set<uid_t>& uids)
{
    nlohmann::json results = nlohmann::json::array();

    const auto bufsize = passwdBufferSize();
    auto buf = std::make_unique<char[]>(bufsize);

    struct passwd pwd;
    struct passwd* pwd_results
    {
        nullptr
    };

    m_passwdWrapper->setpwent();

    while (m_passwdWrapper->getpwent_r(&pwd, buf.get(), bufsize, &pwd_results) == 0 && pwd_results != nullptr)
    {
        if (!usernames.empty()
                && (pwd_results->pw_name == nullptr || usernames.find(pwd_results->pw_name) == usernames.end()))
        {
            continue;
        }
        else if (!uids.empty() && uids.find(pwd_results->pw_uid) == uids.end())
        {
            continue;
        }

        // Classified below, once the enumeration is closed; local until then.
        results.push_back(genUserJson(pwd_results, false));
    }

    m_passwdWrapper->endpwent();

    // After the enumeration, not before: reading first would report an account created in between as
    // remote for one scan. This way it falls outside the enumeration and appears on the next one.
    const auto localUsernames = collectLocalUsernames();

    // The files module is in every passwd nsswitch line, so the enumeration returns local accounts
    // too; an account is remote only when /etc/passwd does not define its name. Keyed by name, not
    // uid, so a directory account colliding with a local uid does not inherit that uid's answer.
    // An empty set means locality is unknown, and a nameless row cannot be looked up: both stay
    // local, which is what the rest of the stack defaults to.
    if (!localUsernames.empty())
    {
        for (auto& user : results)
        {
            const auto& username = user["username"].get_ref<const std::string&>();
            const auto uid = user["uid"].get<uid_t>();
            const auto isSystemdDynamic = uid >= SYSTEMD_DYNAMIC_UID_MIN && uid <= SYSTEMD_DYNAMIC_UID_MAX;

            user["is_remote"] = static_cast<int>(!username.empty()
                                                 && !isSystemdDynamic
                                                 && localUsernames.count(username) == 0);
        }
    }

    return results;
}
