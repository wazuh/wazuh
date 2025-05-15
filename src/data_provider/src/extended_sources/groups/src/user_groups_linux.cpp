#include "user_groups_unix.hpp"
#include "user_groups_wrapper.hpp"

UserGroupsProvider::UserGroupsProvider(std::shared_ptr<IUserGroupsWrapper> wrapper)
    : m_userGroupsWrapper(std::move(wrapper))
{
}

UserGroupsProvider::UserGroupsProvider()
    : m_userGroupsWrapper(std::make_shared<UserGroupsWrapper>())
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

    size_t bufsize = m_userGroupsWrapper->sysconf(_SC_GETPW_R_SIZE_MAX);

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
            if (m_userGroupsWrapper->getpwuid_r(uid, &pwd, buf.get(), bufsize, &pwd_results) == 0 &&
                    pwd_results != nullptr)
            {
                user_t<uid_t, gid_t> user;
                user.name = pwd_results->pw_name;
                user.uid = pwd_results->pw_uid;
                user.gid = pwd_results->pw_gid;
                getGroupsForUser<uid_t, gid_t>(results, user, m_userGroupsWrapper);
            }
        }
    }
    else
    {
        std::set<uid_t> processed_uids;
        m_userGroupsWrapper->setpwent();

        while (m_userGroupsWrapper->getpwent_r(&pwd, buf.get(), bufsize, &pwd_results) == 0 && pwd_results != nullptr)
        {
            if (processed_uids.insert(pwd_results->pw_uid).second)
            {
                user_t<uid_t, gid_t> user;
                user.name = pwd_results->pw_name;
                user.uid = pwd_results->pw_uid;
                user.gid = pwd_results->pw_gid;
                getGroupsForUser<uid_t, gid_t>(results, user, m_userGroupsWrapper);
            }
        }

        m_userGroupsWrapper->endpwent();
    }

    return results;
}
