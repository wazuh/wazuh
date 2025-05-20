#pragma once

#include <set>

#include "json.hpp"
#include "igroup_wrapper_linux.hpp"
#include "ipasswd_wrapper_linux.hpp"
#include "isystem_wrapper.hpp"

#define EXPECTED_GROUPS_MAX 64

class UserGroupsProvider
{
    public:
        explicit UserGroupsProvider(std::shared_ptr<IGroupWrapperLinux> groupWrapper,
                                    std::shared_ptr<IPasswdWrapperLinux> passwdWrapper,
                                    std::shared_ptr<ISystemWrapper> sysWrapper);
        UserGroupsProvider();
        nlohmann::json collect(const std::set<uid_t>& uids = {});

    private:
        std::shared_ptr<IGroupWrapperLinux> m_groupWrapper;
        std::shared_ptr<IPasswdWrapperLinux> m_passwdWrapper;
        std::shared_ptr<ISystemWrapper> m_sysWrapper;

        struct UserInfo
        {
            const char* name;
            uid_t uid;
            gid_t gid;
        };

        void getGroupsForUser(nlohmann::json& results, const UserInfo& user);
        void addGroupsToResults(nlohmann::json& results, uid_t uid, const gid_t* groups, int ngroups);
};
