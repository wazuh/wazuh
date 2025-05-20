#include <iostream>
#include "user_groups_darwin.hpp"
#include "user_groups_wrapper.hpp"
#include "open_directory_utils_wrapper.hpp"

UserGroupsProvider::UserGroupsProvider(std::shared_ptr<IUserGroupsWrapper> wrapper,
                                       std::shared_ptr<IODUtilsWrapper> odWrapper)
    : m_userGroupsWrapper(std::move(wrapper))
    , m_odWrapper(std::move(odWrapper))
{
}

UserGroupsProvider::UserGroupsProvider()
    : m_userGroupsWrapper(std::make_shared<UserGroupsWrapper>())
    , m_odWrapper(std::make_shared<ODUtilsWrapper>())
{
}

nlohmann::json UserGroupsProvider::collect(const std::set<uid_type>& uids)
{
    nlohmann::json results = nlohmann::json::array();

    if (!uids.empty())
    {
        for (const auto& uid : uids)
        {
            struct passwd* pwd = m_userGroupsWrapper->getpwuid(uid);
            if (pwd != nullptr)
            {
                UserInfo user {pwd->pw_name, static_cast<uid_type>(pwd->pw_uid), static_cast<gid_type>(pwd->pw_gid)};
                getGroupsForUser(results, user);
            }
        }
    }
    else {
        std::map<std::string, bool> usernames;
        m_odWrapper->genEntries("dsRecTypeStandard:Users", nullptr, usernames);
        for (const auto& username : usernames) {
            struct passwd* pwd = m_userGroupsWrapper->getpwnam(username.first.c_str());
            if (pwd != nullptr) {
                UserInfo user {pwd->pw_name, static_cast<uid_type>(pwd->pw_uid), static_cast<gid_type>(pwd->pw_gid)};
                getGroupsForUser(results, user);
            }
        }
    }
    return results;
}

void UserGroupsProvider::getGroupsForUser(nlohmann::json& results, const UserInfo& user)
{
    int ngroups = m_userGroupsWrapper->getgroupcount(user.name, user.gid);
    gid_type* groups = new int[ngroups];
    if (m_userGroupsWrapper->getgrouplist(user.name, user.gid, groups, &ngroups) < 0) 
    {
        std::cerr << "Could not get users group list" << std::endl;
    } 
    else 
    {
        addGroupsToResults(results, user.uid, groups, ngroups);
    }
    delete[] groups;
}

void UserGroupsProvider::addGroupsToResults(nlohmann::json& results, uid_type uid, const gid_type* groups, int ngroups)
{
    for (int i = 0; i < ngroups; i++)
    {
        nlohmann::json row;
        row["uid"] = uid;
        row["gid"] = groups[i];
        results.push_back(row);
    }
}
