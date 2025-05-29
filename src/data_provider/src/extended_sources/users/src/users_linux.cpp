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
#include <pwd.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <fstream>

// Reasonable upper bound for getpw_r buffer
constexpr size_t MAX_GETPW_R_BUF_SIZE = 16 * 1024;

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

nlohmann::json UsersProvider::genUserJson(const struct passwd* pwd, bool include_remote)
{
    nlohmann::json r;
    r["uid"] = pwd->pw_uid;
    r["gid"] = pwd->pw_gid;
    r["uid_signed"] = static_cast<int32_t>(pwd->pw_uid);
    r["gid_signed"] = static_cast<int32_t>(pwd->pw_gid);

    if (pwd->pw_name != nullptr)
    {
        r["username"] = pwd->pw_name;
    }

    if (pwd->pw_gecos != nullptr)
    {
        r["description"] = pwd->pw_gecos;
    }

    if (pwd->pw_dir != nullptr)
    {
        r["directory"] = pwd->pw_dir;
    }

    if (pwd->pw_shell != nullptr)
    {
        r["shell"] = pwd->pw_shell;
    }

    r["pid_with_namespace"] = "0";
    r["include_remote"] = static_cast<int>(include_remote);

    return r;
}

nlohmann::json UsersProvider::collectLocalUsers(const std::set<std::string>& usernames,
                                                const std::set<uid_t>& uids)
{
    nlohmann::json results = nlohmann::json::array();

    FILE* passwd_file = m_sysWrapper->fopen("/etc/passwd", "r");

    if (passwd_file == nullptr)
    {
        return results;
    }

    size_t bufsize = m_sysWrapper->sysconf(_SC_GETPW_R_SIZE_MAX);

    if (bufsize > MAX_GETPW_R_BUF_SIZE)
    {
        bufsize = MAX_GETPW_R_BUF_SIZE;
    }

    auto buf = std::make_unique<char[]>(bufsize);

    struct passwd pwd;
    struct passwd* result
    {
        nullptr
    };

    while (m_passwdWrapper->fgetpwent_r(passwd_file, &pwd, buf.get(), bufsize, &result) == 0 && result != nullptr)
    {
        if (!usernames.empty() && usernames.find(result->pw_name) == usernames.end())
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

    size_t bufsize = m_sysWrapper->sysconf(_SC_GETPW_R_SIZE_MAX);

    if (bufsize > MAX_GETPW_R_BUF_SIZE)
    {
        bufsize = MAX_GETPW_R_BUF_SIZE;
    }

    auto buf = std::make_unique<char[]>(bufsize);

    struct passwd pwd;
    struct passwd* pwd_results
    {
        nullptr
    };

    m_passwdWrapper->setpwent();

    while (m_passwdWrapper->getpwent_r(&pwd, buf.get(), bufsize, &pwd_results) == 0 && pwd_results != nullptr)
    {
        if (!usernames.empty() && usernames.find(pwd_results->pw_name) == usernames.end())
        {
            continue;
        }
        else if (!uids.empty() && uids.find(pwd_results->pw_uid) == uids.end())
        {
            continue;
        }

        results.push_back(genUserJson(pwd_results, true));
    }

    m_passwdWrapper->endpwent();

    return results;
}
