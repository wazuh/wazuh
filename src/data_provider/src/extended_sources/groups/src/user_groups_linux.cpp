#include <iostream>
#include "user_groups_linux.hpp"
#include "group_wrapper_linux.hpp"
#include "passwd_wrapper_linux.hpp"
#include "system_wrapper.hpp"

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
    struct passwd pwd;
    struct passwd* pwd_results
    {
        nullptr
    };

    size_t bufsize = m_sysWrapper->sysconf(_SC_GETPW_R_SIZE_MAX);

    if (bufsize > 16384)
    {
        /* Value was indeterminate */
        bufsize = 16384; /* Should be more than enough */
    }

    auto buf = std::make_unique<char[]>(bufsize);

    if (!uids.empty())
    {
        for (const auto& uid : uids)
        {
            if (m_passwdWrapper->getpwuid_r(uid, &pwd, buf.get(), bufsize, &pwd_results) == 0 &&
                    pwd_results != nullptr)
            {
                UserInfo user{pwd_results->pw_name, pwd_results->pw_uid, pwd_results->pw_gid};
                getGroupsForUser(results, user);
            }
        }
    }
    else
    {
        std::set<uid_t> processed_uids;
        m_passwdWrapper->setpwent();

        while (m_passwdWrapper->getpwent_r(&pwd, buf.get(), bufsize, &pwd_results) == 0 && pwd_results != nullptr)
        {
            if (processed_uids.insert(pwd_results->pw_uid).second)
            {
                UserInfo user{pwd_results->pw_name, pwd_results->pw_uid, pwd_results->pw_gid};
                getGroupsForUser(results, user);
            }
        }

        m_passwdWrapper->endpwent();
    }

    return results;
}

void UserGroupsProvider::getGroupsForUser(nlohmann::json& results, const UserInfo& user)
{
    gid_t groups_buf[EXPECTED_GROUPS_MAX];
    gid_t* groups = groups_buf;
    int ngroups = EXPECTED_GROUPS_MAX;

    if (!m_groupWrapper)
    {
        std::cerr << "UserGroupsProvider: user groups wrapper is not initialized" << std::endl;
        return;
    }

    // GLIBC version before 2.3.3 may have a buffer overrun:
    // http://man7.org/linux/man-pages/man3/getgrouplist.3.html
    if (m_groupWrapper->getgrouplist(user.name, user.gid, groups, &ngroups) < 0)
    {
        groups = new gid_t[ngroups];

        if (groups == nullptr)
        {
            std::cerr << "Could not allocate memory to get user groups" << std::endl;
            return;
        }

        if (m_groupWrapper->getgrouplist(user.name, user.gid, groups, &ngroups) < 0)
        {
            std::cerr << "Could not get user's group list" << std::endl;
        }
        else
        {
            addGroupsToResults(results, user.uid, groups, ngroups);
        }

        delete[] groups;
    }
    else
    {
        addGroupsToResults(results, user.uid, groups, ngroups);
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
