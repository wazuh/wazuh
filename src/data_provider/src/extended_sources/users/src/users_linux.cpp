#include "users_linux.hpp"
#include "passwd_wrapper.hpp"
#include "system_wrapper.hpp"

#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <fstream>

UsersProvider::UsersProvider(
    std::shared_ptr<IPasswdWrapper> passwdWrapper,
    std::shared_ptr<ISystemWrapper> sysWrapper)
    : m_passwdWrapper(std::move(passwdWrapper)),
      m_sysWrapper(std::move(sysWrapper)) {}

UsersProvider::UsersProvider()
    : m_passwdWrapper(std::make_shared<PasswdWrapper>()),
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

nlohmann::json UsersProvider::genUserJson(const struct passwd* pwd, const std::string& include_remote)
{
    nlohmann::json r;
    r["uid"] = std::to_string(pwd->pw_uid);
    r["gid"] = std::to_string(pwd->pw_gid);
    r["uid_signed"] = std::to_string(static_cast<int32_t>(pwd->pw_uid));
    r["gid_signed"] = std::to_string(static_cast<int32_t>(pwd->pw_gid));

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
    r["include_remote"] = include_remote;

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

    if (bufsize > 16384)
    {
        bufsize = 16384;
    }

    auto buf = std::make_unique<char[]>(bufsize);

    struct passwd pwd;
    struct passwd* result
    {
        nullptr
    };
    int ret;

    while (1)
    {
        ret = m_passwdWrapper->fgetpwent_r(passwd_file, &pwd, buf.get(), bufsize, &result);

        if (ret != 0 || result == nullptr)
        {
            break;
        }

        if (!usernames.empty() && usernames.find(result->pw_name) == usernames.end())
        {
            continue;
        }

        if (!uids.empty() && uids.find(result->pw_uid) == uids.end())
        {
            continue;
        }

        results.push_back(genUserJson(result, "0"));
    }

    m_sysWrapper->fclose(passwd_file);
    return results;
}

nlohmann::json UsersProvider::collectRemoteUsers(const std::set<std::string>& usernames,
                                                 const std::set<uid_t>& uids)
{
    nlohmann::json results = nlohmann::json::array();

    size_t bufsize = m_sysWrapper->sysconf(_SC_GETPW_R_SIZE_MAX);

    if (bufsize > 16384)
    {
        bufsize = 16384;
    }

    auto buf = std::make_unique<char[]>(bufsize);

    struct passwd pwd;
    struct passwd* pwd_results
    {
        nullptr
    };

    m_passwdWrapper->setpwent();

    while (1)
    {
        m_passwdWrapper->getpwent_r(&pwd, buf.get(), bufsize, &pwd_results);

        if (pwd_results == nullptr)
        {
            break;
        }

        if (!usernames.empty())
        {
            if (usernames.find(pwd_results->pw_name) == usernames.end())
            {
                continue;
            }
        }
        else if (!uids.empty())
        {
            if (uids.find(pwd_results->pw_uid) == uids.end())
            {
                continue;
            }
        }

        results.push_back(genUserJson(pwd_results, "1"));
    }

    m_passwdWrapper->endpwent();

    return results;
}
