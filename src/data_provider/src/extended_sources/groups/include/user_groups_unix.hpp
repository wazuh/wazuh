#pragma once

#include <set>
#include <grp.h>
#include <pwd.h>

#include "json.hpp"
#include "iuser_groups_wrapper.hpp"

#define EXPECTED_GROUPS_MAX 64

class UserGroupsProvider
{
    public:
        explicit UserGroupsProvider(std::shared_ptr<IUserGroupsWrapper> userGroupsWrapper);
        UserGroupsProvider();
        nlohmann::json collect(const std::set<uid_t>& uids = {});

    private:
        std::shared_ptr<IUserGroupsWrapper> m_userGroupsWrapper;

        struct UserInfo
        {
            const char* name;
            uid_t uid;
            gid_t gid;
        };

        void getGroupsForUser(nlohmann::json& results, const UserInfo& user);
        void addGroupsToResults(nlohmann::json& results, uid_t uid, const gid_t* groups, int ngroups);

};
