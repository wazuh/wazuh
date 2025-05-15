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

    if (!uids.empty())
    {
        for (const auto& uid : uids)
        {
            struct passwd* pwd = m_userGroupsWrapper->getpwuid(uid);
            if (pwd != nullptr)
            {
                UserInfo user {pwd->pw_name, pwd->pw_uid, pwd->pw_gid};
                getGroupsForUser(results, user);
            }
        }
    }
    else
    {
        m_userGroupsWrapper->setpwent();
        std::set<uid_t> processed_uids;
        struct passwd* pwd = nullptr;
        while ((pwd = m_userGroupsWrapper->getpwent()) != nullptr)
        {
            if (processed_uids.insert(pwd->pw_uid).second)
            {
                UserInfo user {pwd->pw_name, pwd->pw_uid, pwd->pw_gid};
                getGroupsForUser(results, user);
            }
        }
        m_userGroupsWrapper->endpwent();
    }
    return results;
}
